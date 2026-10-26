//! Route authentication is separate from browser consent and member authority.
use castalia_wallet_presentation::{Caller, TrustPin};
use secs_grant_contract::{AccessPointBinding, IssuerPin, verify_access_point};
use serde_json::json;
use wasm_bindgen::prelude::*;

/// Translate a verified, already-approved browser issuer context to its stable
/// authority receiver. Never persist the translated pin or approve another site.
pub fn presentation_context(
    pins: &[TrustPin],
    caller: &Caller,
    binding: &AccessPointBinding,
    now: u64,
) -> Result<(Vec<TrustPin>, Caller), &'static str> {
    caller.validate()?;
    if caller.kind != "browser" {
        return Err("invalid_service_binding");
    }
    let c = &binding.claims;
    let pin = pins
        .iter()
        .find(|p| p.issuer == c.issuer && p.key_id == c.key_id && p.callers.contains(caller))
        .ok_or("issuer_setup_required")?;
    verify_access_point(
        &IssuerPin {
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            public_key: pin.public_key.clone(),
            service: c.service.clone(),
        },
        binding,
        &caller.id,
        now,
    )?;
    let canonical = Caller {
        kind: "browser".into(),
        id: c.authority_receiver.clone(),
    };
    let translated = pins
        .iter()
        .filter(|p| {
            p.issuer == pin.issuer
                && p.key_id == pin.key_id
                && p.public_key == pin.public_key
                && p.callers.contains(caller)
        })
        .map(|p| TrustPin {
            issuer: p.issuer.clone(),
            key_id: p.key_id.clone(),
            public_key: p.public_key.clone(),
            audience: p.audience.clone(),
            callers: vec![canonical.clone()],
        })
        .collect();
    Ok((translated, canonical))
}

#[wasm_bindgen(js_name=servicePresentationContext)]
pub fn service_presentation_context(
    pins: &str,
    caller: &str,
    binding: &str,
    now: &str,
) -> Result<String, JsValue> {
    let error = |e: &'static str| JsValue::from_str(e);
    let pins: Vec<TrustPin> =
        castalia_wallet_presentation::parse(pins.as_bytes(), 65536).map_err(error)?;
    let caller: Caller =
        castalia_wallet_presentation::parse(caller.as_bytes(), 1024).map_err(error)?;
    let binding: AccessPointBinding =
        castalia_wallet_presentation::parse(binding.as_bytes(), 16384).map_err(error)?;
    let (pins, caller) = presentation_context(
        &pins,
        &caller,
        &binding,
        now.parse().map_err(|_| error("invalid_clock"))?,
    )
    .map_err(error)?;
    Ok(json!({"pins":pins,"caller":caller}).to_string())
}
