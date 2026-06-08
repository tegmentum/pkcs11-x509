//! # x509-path
//!
//! X.509 certificate **path validation** — build a chain from a leaf
//! certificate up to a trusted anchor (a CA in a trust store), verifying each
//! link's signature, validity window, and revocation. Pure-Rust and
//! wasm-friendly; the per-link signature check is **pluggable** via
//! [`CertVerifier`] so it can run natively (default, [`NativeVerifier`]) or be
//! routed through a PKCS#11 `verify()` primitive for HSM-backed verification.
//!
//! This is the layer *above* PKCS#11: PKCS#11 (and the `tegmentum:key-backend`
//! contract) provides key operations; this crate provides the X.509 *policy*
//! (parse + chain-to-anchor) that PKCS#11 deliberately does not.
//!
//! ## Example
//! ```no_run
//! use x509_path::{Cert, TrustStore, Revocations, NativeVerifier, validate_chain};
//! # fn demo(leaf_der: &[u8], ca_der: &[u8]) -> Result<(), x509_path::PathError> {
//! let leaf = Cert::from_der(leaf_der)?;
//! let store = TrustStore::from_ders([ca_der])?;
//! let validated = validate_chain(&leaf, &[], &store, &Revocations::empty(), 0, &NativeVerifier)?;
//! println!("authorized by {}", validated.anchor_subject);
//! # Ok(()) }
//! ```
//!
//! ## What is and isn't checked
//! Checked: issuer/subject chaining, per-link signature, validity window
//! (against a caller-supplied time), CA basic-constraints on issuers, and
//! revocation by certificate-DER hash (the `dbx` model). **Not** yet checked:
//! name constraints, EKU, policy constraints, path-length. Documented so
//! callers know the assurance boundary.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use x509_cert::der::Decode;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

/// Why path validation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    /// A certificate could not be parsed.
    Parse(String),
    /// A certificate in the chain is revoked (`dbx`).
    Revoked,
    /// A certificate is outside its validity window at the supplied time.
    Expired,
    /// No issuer for some certificate could be found among intermediates/anchors.
    NoIssuer,
    /// An issuer's signature over a child did not verify.
    BadSignature,
    /// The chain exceeded the maximum length without reaching an anchor.
    ChainTooLong,
    /// A non-leaf certificate is not a CA (basic constraints).
    NotACa,
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PathError {}

/// A parsed certificate plus its raw DER (kept for hashing / revocation).
#[derive(Clone, Debug)]
pub struct Cert {
    inner: Certificate,
    der: Vec<u8>,
}

impl Cert {
    /// Parse a certificate from DER.
    pub fn from_der(der: &[u8]) -> Result<Self, PathError> {
        let inner = Certificate::from_der(der).map_err(|e| PathError::Parse(e.to_string()))?;
        Ok(Cert {
            inner,
            der: der.to_vec(),
        })
    }

    /// The underlying parsed certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.inner
    }

    /// SHA-256 over the certificate DER — the identity used for `dbx` matching.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.der);
        h.finalize().into()
    }

    /// The subject distinguished name, rendered (best-effort) as a string.
    pub fn subject(&self) -> String {
        self.inner.tbs_certificate.subject.to_string()
    }

    fn issuer_dn(&self) -> &x509_cert::name::Name {
        &self.inner.tbs_certificate.issuer
    }
    fn subject_dn(&self) -> &x509_cert::name::Name {
        &self.inner.tbs_certificate.subject
    }

    fn is_self_issued(&self) -> bool {
        self.subject_dn() == self.issuer_dn()
    }

    /// Whether the cert asserts the CA basic-constraint (or has no BC at all,
    /// which we treat permissively for anchors). Used to reject non-CA issuers.
    fn is_ca(&self) -> bool {
        let Some(exts) = &self.inner.tbs_certificate.extensions else {
            return true; // no extensions → don't block (permissive)
        };
        for ext in exts.iter() {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                return match BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                    Ok(bc) => bc.ca,
                    Err(_) => false,
                };
            }
        }
        true // no basic-constraints extension → permissive
    }

    /// `not_before <= now <= not_after`, with `now` as unix seconds.
    fn valid_at(&self, now_unix: u64) -> bool {
        let v = &self.inner.tbs_certificate.validity;
        let nb = v.not_before.to_unix_duration().as_secs();
        let na = v.not_after.to_unix_duration().as_secs();
        now_unix >= nb && now_unix <= na
    }
}

/// The per-link signature-verification seam. Implement this to route the check
/// through a PKCS#11 `verify()` backend; the default is [`NativeVerifier`].
pub trait CertVerifier {
    /// Does `issuer`'s public key verify `cert`'s signature?
    fn verify_signed_by(&self, cert: &Cert, issuer: &Cert) -> bool;
}

/// Native (pure-Rust) signature verification via `x509-verify` (RSA / ECDSA /
/// Ed25519, per the certificate's signature algorithm).
pub struct NativeVerifier;

impl CertVerifier for NativeVerifier {
    fn verify_signed_by(&self, cert: &Cert, issuer: &Cert) -> bool {
        // The issuer's public key (from its SPKI) verifies the child cert's
        // signature over its TBS — x509-verify's `VerifyInfo` extracts both
        // from `&Certificate`.
        let Ok(key) = x509_verify::VerifyingKey::try_from(&issuer.inner) else {
            return false;
        };
        key.verify(&cert.inner).is_ok()
    }
}

/// Trusted anchors — the `db` equivalent (CA certs that may terminate a chain).
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    anchors: Vec<Cert>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, anchor: Cert) {
        self.anchors.push(anchor);
    }
    /// Build a store from anchor DER blobs.
    pub fn from_ders<'a>(ders: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, PathError> {
        let mut s = Self::new();
        for d in ders {
            s.add(Cert::from_der(d)?);
        }
        Ok(s)
    }
    fn anchor_for<'b>(&'b self, cert: &Cert, verifier: &dyn CertVerifier) -> Option<&'b Cert> {
        self.anchors
            .iter()
            .find(|a| a.subject_dn() == cert.issuer_dn() && verifier.verify_signed_by(cert, a))
    }
    fn is_anchor(&self, cert: &Cert) -> bool {
        self.anchors
            .iter()
            .any(|a| a.fingerprint() == cert.fingerprint())
    }
}

/// Revoked certificates — the `dbx` equivalent, by certificate-DER fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Revocations {
    fingerprints: BTreeSet<[u8; 32]>,
}

impl Revocations {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn revoke(&mut self, fingerprint: [u8; 32]) {
        self.fingerprints.insert(fingerprint);
    }
    /// Revoke a certificate by its DER.
    pub fn revoke_der(&mut self, der: &[u8]) {
        let mut h = Sha256::new();
        h.update(der);
        self.fingerprints.insert(h.finalize().into());
    }
    fn contains(&self, cert: &Cert) -> bool {
        self.fingerprints.contains(&cert.fingerprint())
    }
}

/// The result of a successful path validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validated {
    /// The leaf's subject DN.
    pub subject: String,
    /// The anchoring CA's subject DN.
    pub anchor_subject: String,
    /// Number of links from leaf to anchor.
    pub chain_len: usize,
}

const MAX_CHAIN: usize = 16;

/// Validate `leaf`'s path to a trusted anchor in `store`, drawing intermediate
/// CAs from `intermediates`. Verifies each link's signature (via `verifier`),
/// each certificate's validity at `now_unix`, CA constraints on issuers, and
/// that no certificate in the path is revoked.
pub fn validate_chain(
    leaf: &Cert,
    intermediates: &[Cert],
    store: &TrustStore,
    revoked: &Revocations,
    now_unix: u64,
    verifier: &dyn CertVerifier,
) -> Result<Validated, PathError> {
    let mut current = leaf.clone();
    let mut depth = 0usize;

    loop {
        if revoked.contains(&current) {
            return Err(PathError::Revoked);
        }
        if !current.valid_at(now_unix) {
            return Err(PathError::Expired);
        }

        // Already an anchor (or self-signed root that is itself anchored)?
        if store.is_anchor(&current) {
            return Ok(Validated {
                subject: leaf.subject(),
                anchor_subject: current.subject(),
                chain_len: depth,
            });
        }

        // Terminate at an anchor that issued `current`.
        if let Some(anchor) = store.anchor_for(&current, verifier) {
            if revoked.contains(anchor) {
                return Err(PathError::Revoked);
            }
            if !anchor.valid_at(now_unix) {
                return Err(PathError::Expired);
            }
            return Ok(Validated {
                subject: leaf.subject(),
                anchor_subject: anchor.subject(),
                chain_len: depth + 1,
            });
        }

        if depth >= MAX_CHAIN {
            return Err(PathError::ChainTooLong);
        }

        // Climb to an intermediate CA that issued `current`.
        let next = intermediates.iter().find(|c| {
            c.subject_dn() == current.issuer_dn()
                && c.fingerprint() != current.fingerprint() // avoid self-loop
                && c.is_ca()
                && verifier.verify_signed_by(&current, c)
        });
        match next {
            Some(issuer) => {
                current = issuer.clone();
                depth += 1;
            }
            None => {
                // A self-signed cert that never matched an anchor is untrusted.
                if current.is_self_issued() {
                    return Err(PathError::NoIssuer);
                }
                return Err(PathError::NoIssuer);
            }
        }
    }
}

#[cfg(test)]
mod tests;
