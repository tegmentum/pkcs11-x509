//! WASM Component wrapper exporting `tegmentum:x509-path/validation`, backed by
//! the native `x509-path` core. Thin glue: it parses the DER inputs, runs
//! [`x509_path::validate_chain`] with the native verifier, and maps the result
//! onto the WIT `outcome`.

wit_bindgen::generate!({
    path: "wit",
    world: "x509-path",
    generate_all,
});

use exports::tegmentum::x509_path::validation::{
    Guest, Outcome, Reason, Validated as WitValidated,
};
use x509_path::{validate_chain, Cert, NativeVerifier, PathError, Revocations, TrustStore};

struct Component;

fn parse_all(ders: &[Vec<u8>]) -> Result<Vec<Cert>, PathError> {
    ders.iter().map(|d| Cert::from_der(d)).collect()
}

fn map_err(e: PathError) -> Reason {
    match e {
        PathError::Parse(_) => Reason::Parse,
        PathError::Revoked => Reason::Revoked,
        PathError::Expired => Reason::Expired,
        PathError::NoIssuer => Reason::NoIssuer,
        PathError::BadSignature => Reason::BadSignature,
        PathError::ChainTooLong => Reason::ChainTooLong,
        PathError::NotACa => Reason::NotACa,
    }
}

impl Guest for Component {
    fn validate(
        leaf: Vec<u8>,
        intermediates: Vec<Vec<u8>>,
        anchors: Vec<Vec<u8>>,
        revoked: Vec<Vec<u8>>,
        now_unix: u64,
    ) -> Outcome {
        let leaf = match Cert::from_der(&leaf) {
            Ok(c) => c,
            Err(e) => return Outcome::Rejected(map_err(e)),
        };
        let inters = match parse_all(&intermediates) {
            Ok(v) => v,
            Err(e) => return Outcome::Rejected(map_err(e)),
        };
        let mut store = TrustStore::new();
        for a in &anchors {
            match Cert::from_der(a) {
                Ok(c) => store.add(c),
                Err(e) => return Outcome::Rejected(map_err(e)),
            }
        }
        let mut dbx = Revocations::empty();
        for r in &revoked {
            dbx.revoke_der(r);
        }
        match validate_chain(&leaf, &inters, &store, &dbx, now_unix, &NativeVerifier) {
            Ok(v) => Outcome::Valid(WitValidated {
                subject: v.subject,
                anchor_subject: v.anchor_subject,
                chain_len: v.chain_len as u32,
            }),
            Err(e) => Outcome::Rejected(map_err(e)),
        }
    }
}

export!(Component);
