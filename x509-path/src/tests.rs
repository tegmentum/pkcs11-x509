use super::*;
use rcgen::{
    date_time_ymd, BasicConstraints as RcBasicConstraints, CertificateParams, DnType, IsCa, KeyPair,
};

struct Issued {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn der_of(c: &rcgen::Certificate) -> Vec<u8> {
    c.der().as_ref().to_vec()
}

fn ca(cn: &str) -> Issued {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(RcBasicConstraints::Unconstrained);
    p.not_before = date_time_ymd(2000, 1, 1);
    p.not_after = date_time_ymd(2100, 1, 1);
    p.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    Issued { cert, key }
}

fn leaf(cn: &str, issuer: &Issued, nb: (i32, u8, u8), na: (i32, u8, u8)) -> Issued {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.not_before = date_time_ymd(nb.0, nb.1, nb.2);
    p.not_after = date_time_ymd(na.0, na.1, na.2);
    p.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Issued { cert, key }
}

fn intermediate(cn: &str, issuer: &Issued) -> Issued {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(RcBasicConstraints::Unconstrained);
    p.not_before = date_time_ymd(2000, 1, 1);
    p.not_after = date_time_ymd(2100, 1, 1);
    p.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Issued { cert, key }
}

// A fixed "now" inside the 2000..2100 validity window.
const NOW: u64 = 1_700_000_000; // ~2023

#[test]
fn valid_leaf_chains_to_anchor() {
    let root = ca("Root CA");
    let leaf = leaf("kernel-signer", &root, (2000, 1, 1), (2100, 1, 1));
    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let leaf_c = Cert::from_der(&der_of(&leaf.cert)).unwrap();

    let v = validate_chain(
        &leaf_c,
        &[],
        &store,
        &Revocations::empty(),
        NOW,
        &NativeVerifier,
    )
    .unwrap();
    assert!(v.anchor_subject.contains("Root CA"));
    assert_eq!(v.chain_len, 1);
}

#[test]
fn leaf_signed_by_untrusted_ca_is_rejected() {
    let real = ca("Real CA");
    let rogue = ca("Rogue CA");
    let leaf = leaf("img", &rogue, (2000, 1, 1), (2100, 1, 1));
    let store = TrustStore::from_ders([der_of(&real.cert).as_slice()]).unwrap();
    let leaf_c = Cert::from_der(&der_of(&leaf.cert)).unwrap();

    let err = validate_chain(
        &leaf_c,
        &[],
        &store,
        &Revocations::empty(),
        NOW,
        &NativeVerifier,
    )
    .unwrap_err();
    assert_eq!(err, PathError::NoIssuer);
}

#[test]
fn expired_leaf_is_rejected() {
    let root = ca("Root CA");
    // Validity ends in 2010, but we validate at NOW (~2023).
    let leaf = leaf("old", &root, (2000, 1, 1), (2010, 1, 1));
    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let leaf_c = Cert::from_der(&der_of(&leaf.cert)).unwrap();

    let err = validate_chain(
        &leaf_c,
        &[],
        &store,
        &Revocations::empty(),
        NOW,
        &NativeVerifier,
    )
    .unwrap_err();
    assert_eq!(err, PathError::Expired);
}

#[test]
fn revoked_leaf_is_rejected() {
    let root = ca("Root CA");
    let leaf = leaf("img", &root, (2000, 1, 1), (2100, 1, 1));
    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let leaf_der = der_of(&leaf.cert);
    let leaf_c = Cert::from_der(&leaf_der).unwrap();

    let mut dbx = Revocations::empty();
    dbx.revoke_der(&leaf_der); // moved to dbx
    let err = validate_chain(&leaf_c, &[], &store, &dbx, NOW, &NativeVerifier).unwrap_err();
    assert_eq!(err, PathError::Revoked);
}

#[test]
fn three_link_chain_through_an_intermediate() {
    let root = ca("Root CA");
    let inter = intermediate("Intermediate CA", &root);
    let leaf = leaf("img", &inter, (2000, 1, 1), (2100, 1, 1));

    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let inter_c = Cert::from_der(&der_of(&inter.cert)).unwrap();
    let leaf_c = Cert::from_der(&der_of(&leaf.cert)).unwrap();

    let v = validate_chain(
        &leaf_c,
        &[inter_c],
        &store,
        &Revocations::empty(),
        NOW,
        &NativeVerifier,
    )
    .unwrap();
    assert!(v.anchor_subject.contains("Root CA"));
    assert_eq!(v.chain_len, 2);
}

#[test]
fn revoked_intermediate_breaks_the_chain() {
    let root = ca("Root CA");
    let inter = intermediate("Intermediate CA", &root);
    let leaf = leaf("img", &inter, (2000, 1, 1), (2100, 1, 1));
    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let inter_der = der_of(&inter.cert);
    let inter_c = Cert::from_der(&inter_der).unwrap();
    let leaf_c = Cert::from_der(&der_of(&leaf.cert)).unwrap();

    let mut dbx = Revocations::empty();
    dbx.revoke_der(&inter_der);
    let err = validate_chain(&leaf_c, &[inter_c], &store, &dbx, NOW, &NativeVerifier).unwrap_err();
    assert_eq!(err, PathError::Revoked);
}

#[test]
fn a_directly_anchored_cert_validates() {
    // The leaf's own cert IS an anchor (pinned-cert db entry).
    let root = ca("Pinned CA");
    let store = TrustStore::from_ders([der_of(&root.cert).as_slice()]).unwrap();
    let self_c = Cert::from_der(&der_of(&root.cert)).unwrap();
    let v = validate_chain(
        &self_c,
        &[],
        &store,
        &Revocations::empty(),
        NOW,
        &NativeVerifier,
    )
    .unwrap();
    assert_eq!(v.chain_len, 0);
}

#[test]
fn untrusted_self_signed_is_rejected() {
    let rogue = ca("Rogue Root");
    let store = TrustStore::new(); // trust nothing
    let c = Cert::from_der(&der_of(&rogue.cert)).unwrap();
    let err =
        validate_chain(&c, &[], &store, &Revocations::empty(), NOW, &NativeVerifier).unwrap_err();
    assert_eq!(err, PathError::NoIssuer);
}
