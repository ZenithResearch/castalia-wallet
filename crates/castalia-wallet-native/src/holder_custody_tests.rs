use super::*;
use serde_json::{Value, json};

#[test]
fn portable_profile_and_commands_fail_closed_without_exposing_input() {
    let mut p: Value = serde_json::from_slice(&profile()).unwrap();
    for field in ["origin", "audience"] {
        let original = p["context"][field].clone();
        p["context"][field] = json!("*");
        let raw = serde_json::to_vec(&p).unwrap();
        assert_eq!(
            unsafe { castalia_holder_session_new(raw.as_ptr(), raw.len()) },
            0
        );
        p["context"][field] = original;
    }
    p["provider"]["public_key"] = json!("00".repeat(32));
    let raw = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        unsafe { castalia_holder_session_new(raw.as_ptr(), raw.len()) },
        0
    );
    let p = profile();
    let handle = unsafe { castalia_holder_session_new(p.as_ptr(), p.len()) };
    assert_ne!(handle, 0);
    let raw =
        br#"{"secret":"NEVER PROJECT INPUT","request_id":"11111111111111111111111111111111"}"#;
    let result = unsafe { castalia_holder_session_invoke(handle, raw.as_ptr(), raw.len()) };
    let mut bytes = vec![0; castalia_result_length(result)];
    unsafe { castalia_result_copy(result, bytes.as_mut_ptr(), bytes.len()) };
    assert!(!String::from_utf8_lossy(&bytes).contains("NEVER PROJECT INPUT"));
    castalia_result_free(result);
    castalia_holder_session_free(handle);
}

fn profile() -> Vec<u8> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap();
    serde_json::to_vec(&json!({"schema":"castalia.holder-session-agent-profile.v1",
        "provider":v["pin"],"context":v["context"],"maximum_session_seconds":300}))
    .unwrap()
}
fn invoke(handle: u64, id: u64, body: Value) -> Value {
    let raw = serde_json::to_vec(&json!({"schema":"castalia.holder-session-agent-command.v1",
        "request_id":format!("{id:032x}"),"body":body}))
    .unwrap();
    let result = unsafe { castalia_holder_session_invoke(handle, raw.as_ptr(), raw.len()) };
    assert_ne!(result, 0);
    let mut bytes = vec![0; castalia_result_length(result)];
    let len = bytes.len();
    assert_eq!(
        unsafe { castalia_result_copy(result, bytes.as_mut_ptr(), len) },
        len
    );
    castalia_result_free(result);
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn temporary_custody_is_separate_bounded_nonexportable_and_terminal_on_free() {
    assert_eq!(castalia_abi_version(), 1);
    assert_eq!(castalia_holder_session_abi_version(), 1);
    let p = profile();
    let a = unsafe { castalia_holder_session_new(p.as_ptr(), p.len()) };
    let b = unsafe { castalia_holder_session_new(p.as_ptr(), p.len()) };
    assert_ne!(a, 0);
    assert_ne!(b, 0);
    assert_ne!(a, b);
    let root = castalia_session_new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let create = json!({"operation":"create_session","expires_at":now+240});
    let created = invoke(a, 1, create.clone());
    assert_eq!(created["ok"], true);
    assert_eq!(created, invoke(a, 1, create));
    let session = created["value"]["session_handle"].clone();
    assert!(created["value"].get("private_key").is_none());
    // Dropping root custody cannot lock the separately held application key.
    castalia_session_free(root);
    assert_eq!(
        invoke(
            a,
            2,
            json!({"operation":"create_session","expires_at":now+200})
        )["ok"],
        true
    );
    assert_eq!(
        invoke(
            b,
            3,
            json!({"operation":"close_session","session_handle":session})
        )["ok"],
        false
    );
    for (index, operation) in [
        "import_seed",
        "export_key",
        "sign",
        "approve_enrollment",
        "install_grant",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            invoke(a, 10 + index as u64, json!({"operation":operation}))["ok"],
            false
        );
    }
    assert_eq!(
        invoke(
            a,
            20,
            json!({"operation":"close_session","session_handle":session})
        )["ok"],
        true
    );
    assert_eq!(
        invoke(
            a,
            21,
            json!({"operation":"close_session","session_handle":session})
        )["ok"],
        false
    );
    castalia_holder_session_free(a);
    castalia_holder_session_free(a);
    let raw = b"{}";
    assert_eq!(
        unsafe { castalia_holder_session_invoke(a, raw.as_ptr(), raw.len()) },
        0
    );
    castalia_holder_session_free(b);
    assert_eq!(
        unsafe { castalia_holder_session_new(std::ptr::null(), 1) },
        0
    );
    assert_eq!(
        unsafe { castalia_holder_session_new(raw.as_ptr(), raw.len()) },
        0
    );
}
