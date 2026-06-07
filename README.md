# pkcs11-x509

X.509 certificate **path validation** for the `pkcs11*` / `openssl-provider-wit`
stack — the policy layer *above* PKCS#11.

PKCS#11 (and the `tegmentum:key-backend` contract) gives you key operations:
sign, **verify**, decrypt, derive. It deliberately does *not* parse X.509 or
build/validate certificate chains. This crate fills that gap: given a leaf
certificate, a set of trusted anchors (a `db`), and a revocation set (a `dbx`),
it decides whether the leaf **chains to a trusted anchor** — verifying each
link's signature, validity window, CA constraints, and revocation.

It was extracted as a shared component because the need recurs: Secure Boot
`db`/`dbx` authority validation (Citadel's measured-boot appraisal), verifying a
peer/client cert chains to an org CA, validating a signed-artifact publisher,
etc. — all want "does this cert chain to something I trust," not raw
key-by-key matching.

## Layout

* **`x509-path/`** — the native Rust core (this is the dependency other projects
  use directly; pure-Rust, wasm-friendly, no wasmtime on the hot path).
* **`x509-path-component/`** — a thin WASM **Component** wrapper exporting
  `tegmentum:x509-path/validation`, for the component-model stack. Backed by the
  same core. (Not a default workspace member — build with the wasm toolchain.)
* **`wit/`** — the `tegmentum:x509-path` WIT contract.

## Native usage

```rust
use x509_path::{Cert, TrustStore, Revocations, NativeVerifier, validate_chain};

let leaf = Cert::from_der(leaf_der)?;
let store = TrustStore::from_ders([root_ca_der])?;          // the db
let mut dbx = Revocations::empty();                         // the dbx
dbx.revoke_der(compromised_cert_der);

match validate_chain(&leaf, &intermediates, &store, &dbx, now_unix, &NativeVerifier) {
    Ok(v)  => println!("authorized by {}", v.anchor_subject),
    Err(e) => println!("rejected: {e}"),
}
```

## Pluggable signature verification

The per-link signature check goes through the [`CertVerifier`] trait. The
default [`NativeVerifier`] uses pure-Rust crypto (`x509-verify`: RSA / ECDSA /
Ed25519). To verify on an HSM, implement `CertVerifier` over the PKCS#11
`verify()` primitive (`pkcs11-bridge` / `tegmentum:key-backend`) — parse + chain
logic stays here, the crypto runs on the token.

## Assurance boundary

Checked: issuer/subject chaining, per-link signature, validity window (against a
caller-supplied time), CA basic-constraints on issuers, and revocation by
certificate-DER hash. **Not yet** checked: name constraints, EKU, policy
constraints, path-length constraints. State this when relying on it for
high-assurance trust decisions.

## Building the component

```sh
cargo build --release --target wasm32-wasip2 \
  --manifest-path x509-path-component/Cargo.toml
```

## License

MIT OR Apache-2.0.
