//! Standalone in-process data projection. Owned IDs are not consent or authority.
use super::{allocate, handles};
use castalia_wallet_core::{feed_projection::PreparedFeedProjectionV1, feeds::MAX_SECTION_BYTES};
use std::panic::{AssertUnwindSafe, catch_unwind};
use zeroize::Zeroizing;

#[unsafe(no_mangle)]
pub extern "C" fn castalia_feed_projection_abi_version() -> u32 {
    1
}

fn valid_input(pointer: *const u8, length: usize, maximum: usize) -> bool {
    !pointer.is_null() && length > 0 && length <= maximum
}

fn result(bytes: Vec<u8>) -> u64 {
    if bytes.is_empty() || bytes.len() > MAX_SECTION_BYTES {
        return 0;
    }
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.results.len() >= 32 {
        return 0;
    }
    let Some(id) = allocate(&mut h) else {
        return 0;
    };
    h.results.insert(id, Zeroizing::new(bytes));
    id
}

/// Return a process-local owned preparation or 0. No Wallet is opened or queried.
/// Source/selection are original UTF-8 JSON, never decoded/re-encoded by this ABI.
/// # Safety
/// Each non-null pointer with an accepted length must be readable for that length
/// during this call. Inputs are not retained. Bounds are checked before reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_feed_projection_prepare(
    source: *const u8,
    source_len: usize,
    selection: *const u8,
    selection_len: usize,
    origin: *const u8,
    origin_len: usize,
) -> u64 {
    if !valid_input(source, source_len, MAX_SECTION_BYTES)
        || !valid_input(selection, selection_len, MAX_SECTION_BYTES)
        || !valid_input(origin, origin_len, 2048)
    {
        return 0;
    }
    let prepared = catch_unwind(|| {
        let s =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(source, source_len) }).ok()?;
        let c =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(selection, selection_len) })
                .ok()?;
        let o =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(origin, origin_len) }).ok()?;
        PreparedFeedProjectionV1::prepare(s, c, o).ok()
    });
    let Ok(Some(prepared)) = prepared else {
        return 0;
    };
    let Ok(mut h) = handles().lock() else {
        return 0;
    };
    if h.feed_projections.len() >= 16 {
        return 0;
    }
    // SAME allocator as sessions, holder custody and result handles.
    let Some(id) = allocate(&mut h) else {
        return 0;
    };
    h.feed_projections.insert(id, prepared);
    id
}

/// Return an owned result of selected-section UTF-8 bytes, or 0. No origin or
/// preparation handle appears in those bytes. Free it using castalia_result_free.
#[unsafe(no_mangle)]
pub extern "C" fn castalia_feed_projection_preview(handle: u64) -> u64 {
    let bytes = {
        let Ok(h) = handles().lock() else {
            return 0;
        };
        let Some(prepared) = h.feed_projections.get(&handle) else {
            return 0;
        };
        // Borrowed preview requires the lock. Catch inside it so serialization
        // cannot poison the global table; no foreign callbacks occur.
        catch_unwind(AssertUnwindSafe(|| prepared.preview_json().into_bytes()))
    };
    match bytes {
        Ok(bytes) => result(bytes),
        Err(_) => 0,
    }
}

/// Every call with a live preparation consumes it, including invalid arguments
/// or unavailable result capacity. A returned result owns selected-section bytes.
/// # Safety
/// Each non-null pointer with an accepted length must be readable for that length
/// during this call. Bounds are checked before reads. No pointer is retained.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn castalia_feed_projection_confirm(
    handle: u64,
    source: *const u8,
    source_len: usize,
    origin: *const u8,
    origin_len: usize,
) -> u64 {
    let prepared = {
        let Ok(mut h) = handles().lock() else {
            return 0;
        };
        h.feed_projections.remove(&handle)
    };
    let Some(prepared) = prepared else {
        return 0;
    };
    if !valid_input(source, source_len, MAX_SECTION_BYTES) || !valid_input(origin, origin_len, 2048)
    {
        return 0;
    }
    let bytes = catch_unwind(AssertUnwindSafe(|| {
        let s =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(source, source_len) }).ok()?;
        let o =
            std::str::from_utf8(unsafe { std::slice::from_raw_parts(origin, origin_len) }).ok()?;
        Some(prepared.confirm(s, o).ok()?.to_string().into_bytes())
    }));
    match bytes {
        Ok(Some(bytes)) => result(bytes),
        _ => 0,
    }
}

/// Idempotently dispose a preparation. Other handle families are unaffected.
#[unsafe(no_mangle)]
pub extern "C" fn castalia_feed_projection_free(handle: u64) {
    if let Ok(mut h) = handles().lock() {
        h.feed_projections.remove(&handle);
    }
}
