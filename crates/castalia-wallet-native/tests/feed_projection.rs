use castalia_wallet_native::*;
use serde_json::{Value, json};

fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../contracts/feeds/v1/projection-conformance.json"
    ))
    .unwrap()
}
fn prepare(source: &[u8], choices: &[u8], origin: &[u8]) -> u64 {
    unsafe {
        castalia_feed_projection_prepare(
            source.as_ptr(),
            source.len(),
            choices.as_ptr(),
            choices.len(),
            origin.as_ptr(),
            origin.len(),
        )
    }
}
fn confirm(handle: u64, source: &[u8], origin: &[u8]) -> u64 {
    unsafe {
        castalia_feed_projection_confirm(
            handle,
            source.as_ptr(),
            source.len(),
            origin.as_ptr(),
            origin.len(),
        )
    }
}
fn copy(result: u64) -> Value {
    assert_ne!(result, 0);
    let size = castalia_result_length(result);
    assert!(size > 0 && size <= 262144);
    let mut data = vec![0x55; size];
    assert_eq!(
        unsafe { castalia_result_copy(result, data.as_mut_ptr(), size - 1) },
        0
    );
    assert!(data.iter().all(|b| *b == 0x55));
    assert_eq!(
        unsafe { castalia_result_copy(result, data.as_mut_ptr(), size) },
        size
    );
    castalia_result_free(result);
    castalia_result_free(result);
    assert_eq!(castalia_result_length(result), 0);
    serde_json::from_slice(&data).unwrap()
}

// One integration-test process owns these quota checks. Existing native unit
// tests run in another process and cannot consume this process's global slots.
#[test]
fn actual_c_abi_vectors_ownership_limits_and_concurrent_consumption() {
    assert_eq!(castalia_abi_version(), 1);
    assert_eq!(castalia_feed_projection_abi_version(), 1);
    let corpus = corpus();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 46);
    for case in corpus["cases"].as_array().unwrap() {
        let source = case["sourceRaw"].as_str().unwrap().as_bytes();
        let choices = case["selectionRaw"].as_str().unwrap().as_bytes();
        let origin = case["origin"].as_str().unwrap().as_bytes();
        let h = prepare(source, choices, origin);
        assert_eq!(h != 0, case["valid"].as_bool().unwrap(), "{}", case["id"]);
        if h != 0 {
            assert_eq!(
                copy(castalia_feed_projection_preview(h)),
                case["expectedSection"]
            );
            assert_eq!(copy(confirm(h, source, origin)), case["expectedSection"]);
            assert_eq!(confirm(h, source, origin), 0);
            assert_eq!(castalia_feed_projection_preview(h), 0);
            castalia_feed_projection_free(h);
        }
    }
    for case in corpus["confirmationCases"].as_array().unwrap() {
        let source = case["sourceRaw"].as_str().unwrap().as_bytes();
        let choices = case["selectionRaw"].as_str().unwrap().as_bytes();
        let origin = case["origin"].as_str().unwrap().as_bytes();
        let h = prepare(source, choices, origin);
        let result = confirm(
            h,
            case["currentSourceRaw"].as_str().unwrap().as_bytes(),
            case["confirmOrigin"].as_str().unwrap().as_bytes(),
        );
        assert_eq!(
            result != 0,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
        if result != 0 {
            copy(result);
        }
        assert_eq!(confirm(h, source, origin), 0);
    }
    let first = &corpus["cases"][0];
    let source = first["sourceRaw"].as_str().unwrap().as_bytes();
    let choices = first["selectionRaw"].as_str().unwrap().as_bytes();
    let origin = first["origin"].as_str().unwrap().as_bytes();
    let mut s = source.to_vec();
    let mut c = choices.to_vec();
    let mut o = origin.to_vec();
    let h = prepare(&s, &c, &o);
    s.fill(0);
    c.fill(0);
    o.fill(0);
    assert_eq!(copy(confirm(h, source, origin)), first["expectedSection"]);
    assert_eq!(prepare(&[255], choices, origin), 0);
    assert_eq!(prepare(source, &[255], origin), 0);
    assert_eq!(prepare(source, choices, &[255]), 0);
    assert_eq!(prepare(&vec![b' '; 262145], choices, origin), 0);
    assert_eq!(prepare(source, &vec![b' '; 262145], origin), 0);
    assert_eq!(prepare(source, choices, &vec![b'a'; 2049]), 0);
    assert_eq!(
        unsafe {
            castalia_feed_projection_prepare(
                std::ptr::null(),
                1,
                choices.as_ptr(),
                choices.len(),
                origin.as_ptr(),
                origin.len(),
            )
        },
        0
    );
    // Every pointer slot is checked before reads, including impossible lengths.
    for (pointer, length) in [(std::ptr::null(), 1), (std::ptr::dangling(), usize::MAX)] {
        assert_eq!(
            unsafe {
                castalia_feed_projection_prepare(
                    pointer,
                    length,
                    choices.as_ptr(),
                    choices.len(),
                    origin.as_ptr(),
                    origin.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                castalia_feed_projection_prepare(
                    source.as_ptr(),
                    source.len(),
                    pointer,
                    length,
                    origin.as_ptr(),
                    origin.len(),
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                castalia_feed_projection_prepare(
                    source.as_ptr(),
                    source.len(),
                    choices.as_ptr(),
                    choices.len(),
                    pointer,
                    length,
                )
            },
            0
        );
        let h = prepare(source, choices, origin);
        assert_eq!(
            unsafe {
                castalia_feed_projection_confirm(h, source.as_ptr(), source.len(), pointer, length)
            },
            0
        );
        assert_eq!(confirm(h, source, origin), 0);
        let h = prepare(source, choices, origin);
        assert_eq!(
            unsafe {
                castalia_feed_projection_confirm(h, pointer, length, origin.as_ptr(), origin.len())
            },
            0
        );
        assert_eq!(confirm(h, source, origin), 0);
    }
    for bad in [Vec::new(), vec![255], vec![b' '; 262145]] {
        let h = prepare(source, choices, origin);
        assert_ne!(h, 0);
        assert_eq!(confirm(h, &bad, origin), 0);
        assert_eq!(confirm(h, source, origin), 0);
    }
    let h = prepare(source, choices, origin);
    assert_eq!(
        unsafe {
            castalia_feed_projection_confirm(h, std::ptr::null(), 1, origin.as_ptr(), origin.len())
        },
        0
    );
    assert_eq!(confirm(h, source, origin), 0);
    let h = prepare(source, choices, origin);
    assert_eq!(confirm(h, source, &[255]), 0);
    assert_eq!(confirm(h, source, origin), 0);
    let h = prepare(source, choices, origin);
    castalia_feed_projection_free(h);
    castalia_feed_projection_free(h);
    assert_eq!(confirm(h, source, origin), 0);

    let hs: Vec<_> = (0..16).map(|_| prepare(source, choices, origin)).collect();
    assert!(hs.iter().all(|h| *h != 0));
    assert_eq!(prepare(source, choices, origin), 0);
    for h in hs {
        castalia_feed_projection_free(h);
    }
    let h = prepare(source, choices, origin);
    assert_ne!(h, 0);
    let results: Vec<_> = (0..32)
        .map(|_| castalia_feed_projection_preview(h))
        .collect();
    assert!(results.iter().all(|r| *r != 0));
    assert_eq!(castalia_feed_projection_preview(h), 0);
    assert_eq!(confirm(h, source, origin), 0); // Full result table still consumes.
    for r in results {
        castalia_result_free(r);
    }
    assert_eq!(confirm(h, source, origin), 0);

    let session = castalia_session_new();
    assert_ne!(session, 0);
    let v: Value = serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap();
    let profile=serde_json::to_vec(&json!({"schema":"castalia.holder-session-agent-profile.v1","provider":v["pin"],"context":v["context"],"maximum_session_seconds":300})).unwrap();
    let holder = unsafe { castalia_holder_session_new(profile.as_ptr(), profile.len()) };
    assert_ne!(holder, 0);
    let h = prepare(source, choices, origin);
    let r = castalia_feed_projection_preview(h);
    let families = [session, holder, h, r];
    assert_eq!(
        families
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    for wrong in [session, holder, r] {
        assert_eq!(castalia_feed_projection_preview(wrong), 0);
        assert_eq!(confirm(wrong, source, origin), 0);
        castalia_feed_projection_free(wrong);
    }
    castalia_result_free(h);
    castalia_session_free(h);
    castalia_holder_session_free(h);
    assert_eq!(copy(r), first["expectedSection"]);
    assert_eq!(copy(confirm(h, source, origin)), first["expectedSection"]);
    let request = br#"{"operation":"state"}"#;
    let r = unsafe { castalia_session_invoke(session, request.as_ptr(), request.len()) };
    assert_eq!(copy(r)["ok"], true);
    castalia_session_free(session);
    castalia_holder_session_free(holder);

    let h = prepare(source, choices, origin);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let barrier = barrier.clone();
            let s = source.to_vec();
            let o = origin.to_vec();
            std::thread::spawn(move || {
                barrier.wait();
                confirm(h, &s, &o)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| **r != 0).count(), 1);
    for r in results {
        if r != 0 {
            assert_eq!(copy(r), first["expectedSection"]);
        }
    }
}
