//! Generates public synthetic interoperability material, never production keys.
#[path = "../tests/common/mod.rs"]
mod common;
use castalia_wallet_presentation::{CREDENTIAL_DOMAIN, canonical_json, complete, prepare_request};
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};
fn main() {
    let (raw, pins, caller, holder) = common::fixture();
    let request: Value = serde_json::from_slice(&raw).unwrap();
    let prepared = prepare_request(
        &raw,
        &pins,
        &caller,
        &hex::encode(holder.verifying_key().as_bytes()),
        1800000000,
    )
    .unwrap()
    .prepare_presentation(1800000001, &[33; 16])
    .unwrap();
    let presentation_transcript = hex::encode(prepared.signature_transcript());
    let signature = holder.sign(prepared.signature_transcript()).to_bytes();
    let presentation = complete(prepared, &signature).unwrap().canonical().unwrap();
    let mut credential_transcript = CREDENTIAL_DOMAIN.to_vec();
    credential_transcript.extend(canonical_json(&request["credential"]["claims"]).unwrap());
    let result = json!({"schema":"castalia.credential-presentation-test-vector.v2", "request":request,
        "trust_config":{"schema":"castalia.wallet-presentation-trust.v1","caller":caller,"pins":pins},
        "holder_seed_hex":hex::encode([22;32]),"issuer_seed_hex":hex::encode([11;32]),
        "now":1800000000u64,"approved_at":1800000001u64,"presentation_nonce_hex":hex::encode([33;16]),
        "expected_presentation":serde_json::from_slice::<Value>(&presentation).unwrap(),
        "credential_signing_bytes_hex":hex::encode(credential_transcript),"presentation_signing_bytes_hex":presentation_transcript,
        "canonical_request":String::from_utf8(raw).unwrap(),"canonical_presentation":String::from_utf8(presentation).unwrap()});
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
