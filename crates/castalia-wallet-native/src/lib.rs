//! Thin C ABI over the same Rust state machine exported to WASM.
use castalia_wallet_core::holder_session_custody::HolderSessionCustody;
use castalia_wallet_core::recovery_session::RecoverySession;
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Mutex, OnceLock},
};
use zeroize::Zeroizing;
#[cfg(test)]
mod holder_custody_tests;
#[derive(Default)]
struct Handles {
    next: u64,
    sessions: HashMap<u64, RecoverySession>,
    holder_custody: HashMap<u64, HolderSessionCustody>,
    results: HashMap<u64, Zeroizing<Vec<u8>>>,
}
static HANDLES: OnceLock<Mutex<Handles>> = OnceLock::new();
fn handles() -> &'static Mutex<Handles> {
    HANDLES.get_or_init(|| Mutex::new(Handles::default()))
}
fn allocate(h: &mut Handles) -> Option<u64> {
    h.next = h.next.checked_add(1)?;
    Some(h.next)
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_abi_version() -> u32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_holder_session_abi_version() -> u32 {
    1
}
/// # Safety
/// `bytes` must point to `length` readable profile bytes. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_holder_session_new(bytes: *const u8, length: usize) -> u64 {
    if bytes.is_null() || length == 0 || length > 65536 {
        return 0;
    }
    let input = unsafe { std::slice::from_raw_parts(bytes, length) };
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.holder_custody.len() >= 16 {
        return 0;
    }
    let Ok(Ok(custody)) = catch_unwind(|| HolderSessionCustody::new(input)) else {
        return 0;
    };
    let Some(id) = allocate(&mut h) else { return 0 };
    h.holder_custody.insert(id, custody);
    id
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_holder_session_free(custody: u64) {
    if let Ok(mut h) = handles().lock() {
        // Drop zeroizes temporary keys. This does not revoke the issuer grant.
        h.holder_custody.remove(&custody);
    }
}
/// # Safety
/// `bytes` must point to `length` readable command bytes. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_holder_session_invoke(
    custody: u64,
    bytes: *const u8,
    length: usize,
) -> u64 {
    if bytes.is_null() || length == 0 || length > 131072 {
        return 0;
    }
    let input = unsafe { std::slice::from_raw_parts(bytes, length) };
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.results.len() >= 32 {
        return 0;
    }
    let Some(agent) = h.holder_custody.get_mut(&custody) else {
        return 0;
    };
    let response = match catch_unwind(AssertUnwindSafe(|| agent.invoke(input))) {
        Ok(value) => value,
        Err(_) => {
            h.holder_custody.remove(&custody);
            serde_json::json!({"schema":"castalia.holder-session-agent-result.v1",
                "request_id":null,"ok":false,"error":"core_failed"})
        }
    };
    let Ok(encoded) = serde_json::to_vec(&response) else {
        return 0;
    };
    if encoded.len() > 131072 {
        return 0;
    }
    let Some(id) = allocate(&mut h) else { return 0 };
    h.results.insert(id, Zeroizing::new(encoded));
    id
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_session_new() -> u64 {
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.sessions.len() >= 16 {
        return 0;
    }
    let Some(id) = allocate(&mut h) else { return 0 };
    h.sessions.insert(id, RecoverySession::new());
    id
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_session_free(session: u64) {
    if let Ok(mut h) = handles().lock() {
        h.sessions.remove(&session);
    }
}
/// # Safety
/// `bytes` must point to `length` readable bytes for this call. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_session_invoke(
    session: u64,
    bytes: *const u8,
    length: usize,
) -> u64 {
    if bytes.is_null() || length == 0 || length > 3 * 1_048_576 {
        return 0;
    }
    let input = Zeroizing::new(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec());
    let Ok(raw) = std::str::from_utf8(&input) else {
        return 0;
    };
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.results.len() >= 32 {
        return 0;
    }
    let Some(core) = h.sessions.get_mut(&session) else {
        return 0;
    };
    let response = match catch_unwind(AssertUnwindSafe(|| core.invoke(raw))) {
        Ok(Ok(value)) => serde_json::json!({"ok":true,"value":value}),
        Ok(Err(code)) => serde_json::json!({"ok":false,"error":code}),
        Err(_) => {
            let _ = core.invoke("{\"operation\":\"lock\"}");
            serde_json::json!({"ok":false,"error":"core_failed"})
        }
    };
    let Ok(encoded) = serde_json::to_vec(&response) else {
        return 0;
    };
    let Some(id) = allocate(&mut h) else { return 0 };
    h.results.insert(id, Zeroizing::new(encoded));
    id
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_result_length(result: u64) -> usize {
    handles()
        .lock()
        .ok()
        .and_then(|h| h.results.get(&result).map(|r| r.len()))
        .unwrap_or(0)
}
/// # Safety
/// `destination` must point to at least `capacity` writable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_result_copy(
    result: u64,
    destination: *mut u8,
    capacity: usize,
) -> usize {
    if destination.is_null() {
        return 0;
    }
    let Ok(h) = handles().lock() else { return 0 };
    let Some(data) = h.results.get(&result) else {
        return 0;
    };
    if capacity < data.len() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), destination, data.len());
    }
    data.len()
}
#[unsafe(no_mangle)]
pub extern "C" fn castalia_result_free(result: u64) {
    if let Ok(mut h) = handles().lock() {
        h.results.remove(&result);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_handles_and_disposal() {
        let h = castalia_session_new();
        assert_ne!(h, 0);
        let input = br#"{"operation":"state"}"#;
        let r = unsafe { castalia_session_invoke(h, input.as_ptr(), input.len()) };
        assert_ne!(r, 0);
        let mut out = vec![0; castalia_result_length(r)];
        assert_eq!(unsafe { castalia_result_copy(r, out.as_mut_ptr(), 1) }, 0);
        assert_eq!(
            unsafe { castalia_result_copy(r, out.as_mut_ptr(), out.len()) },
            out.len()
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out).unwrap()["value"]["unlocked"],
            false
        );
        castalia_result_free(r);
        castalia_result_free(r);
        assert_eq!(castalia_result_length(r), 0);
        castalia_session_free(h);
        castalia_session_free(h);
        assert_eq!(
            unsafe { castalia_session_invoke(h, input.as_ptr(), input.len()) },
            0
        );
        assert_eq!(
            unsafe { castalia_session_invoke(h, std::ptr::null(), 1) },
            0
        );
    }
}
