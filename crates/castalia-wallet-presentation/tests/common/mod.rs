use base64::{Engine as _, engine::general_purpose::STANDARD};
use castalia_wallet_presentation::{Caller, TrustPin, canonical_json};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

pub fn fixture() -> (Vec<u8>, Vec<TrustPin>, Caller, SigningKey) {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let holder = SigningKey::from_bytes(&[22; 32]);
    let caller = Caller {
        kind: "terminal".into(),
        id: "fixture-terminal".into(),
    };
    let disclosure =
        json!({"title":"Fixture request", "statements":["Approve the exact request bytes."]});
    let claims = json!({"schema":"castalia.request-credential.v1", "issuer":"fixture-issuer", "key_id":"fixture-key", "holder_public_key":hex::encode(holder.verifying_key().as_bytes()), "audience":"fixture-service", "caller":caller, "request_digest_sha256":castalia_wallet_presentation::digest(b"opaque request"), "disclosure_digest_sha256":castalia_wallet_presentation::digest(&canonical_json(&disclosure).unwrap()), "policy_digest_sha256":"ab".repeat(32), "nonce":"01".repeat(16), "issued_at":1800000000u64, "expires_at":1800000120u64});
    let mut bytes = b"castalia.request-credential.v1/signature\0".to_vec();
    bytes.extend(canonical_json(&claims).unwrap());
    let request = json!({"schema":"castalia.credential-presentation-request.v2", "request_bytes_base64":STANDARD.encode(b"opaque request"), "disclosure":disclosure, "credential":{"claims":claims,"signature":hex::encode(issuer.sign(&bytes).to_bytes())}});
    let pins = vec![TrustPin {
        issuer: "fixture-issuer".into(),
        key_id: "fixture-key".into(),
        public_key: hex::encode(issuer.verifying_key().as_bytes()),
        audience: "fixture-service".into(),
        callers: vec![caller.clone()],
    }];
    (canonical_json(&request).unwrap(), pins, caller, holder)
}
