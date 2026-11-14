//! Standalone data projection only. No Wallet, origin approval or custody epoch.
use crate::{feed_projection::PreparedFeedProjectionV1, feeds::MAX_SECTION_BYTES};
use wasm_bindgen::prelude::*;

fn json_text(bytes: &[u8]) -> Result<&str, JsValue> {
    if bytes.is_empty() || bytes.len() > MAX_SECTION_BYTES {
        return Err(JsValue::from_str("feed_projection_input_limit"));
    }
    std::str::from_utf8(bytes).map_err(|_| JsValue::from_str("invalid_feed_projection_utf8"))
}

/// Standalone locally owned preparation, not a host approval or portable token.
#[wasm_bindgen]
pub struct WasmFeedProjectionV1 {
    inner: Option<PreparedFeedProjectionV1>,
}
#[wasm_bindgen]
impl WasmFeedProjectionV1 {
    #[wasm_bindgen(constructor)]
    pub fn new(source: &[u8], selection: &[u8], origin: &str) -> Result<Self, JsValue> {
        let prepared =
            PreparedFeedProjectionV1::prepare(json_text(source)?, json_text(selection)?, origin)
                .map_err(JsValue::from_str)?;
        Ok(Self {
            inner: Some(prepared),
        })
    }
    #[wasm_bindgen(js_name=destinationOrigin)]
    pub fn destination_origin(&self) -> Result<String, JsValue> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("disposed_feed_projection"))?
            .destination_origin()
            .to_owned())
    }
    #[wasm_bindgen(js_name=previewJson)]
    pub fn preview_json(&self) -> Result<String, JsValue> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| JsValue::from_str("disposed_feed_projection"))?
            .preview_json())
    }
    /// Consume before raw current-source validation. Failed calls cannot replay.
    pub fn confirm(&mut self, source: &[u8], origin: &str) -> Result<String, JsValue> {
        let prepared = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("disposed_feed_projection"))?;
        Ok(prepared
            .confirm(json_text(source)?, origin)
            .map_err(JsValue::from_str)?
            .to_string())
    }
    pub fn dispose(&mut self) {
        self.inner = None;
    }
}
