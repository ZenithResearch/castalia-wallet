use super::*;

const CORPUS: &str = include_str!("corpus.json");

#[test]
fn shared_original_envelopes() {
    let corpus: Json = serde_json::from_str(CORPUS).unwrap();
    assert_eq!(
        corpus["schema"],
        "castalia.kettle-current-wire-resolved-corpus.v1"
    );
    assert_eq!(
        corpus["sourceManifestSha256"],
        "283f5d6c41925c8046a86d06da7fce4bb73cc94b2182868d4883b949936f5034"
    );
    let mut names = BTreeSet::new();
    let mut passed = 0;
    let mut rejected = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        assert!(names.insert(name));
        let raw = case["originalHex"].as_str().unwrap();
        let expected = &case["expected"];
        let got = decode_original_transaction(raw);
        if let Some(err) = expected["error"].as_str() {
            assert_eq!(got.unwrap_err().to_string(), err, "{name}: error");
            rejected += 1;
            continue;
        }
        let got = got.unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_eq!(got.transaction_id(), expected["txId"], "{name}: body ID");
        assert_eq!(
            got.envelope.sha256, expected["envelopeSha256"],
            "{name}: original envelope"
        );
        assert_eq!(
            got.scalus_output_values(),
            expected["scalus"],
            "{name}: Scalus Value"
        );
        let canonical = serde_jcs::to_vec(&got).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(canonical)),
            expected["observationSha256"],
            "{name}: observation"
        );
        // Re-decode every original body output (including collateral return) in isolation. Local
        // offsets restart at zero; compare original bytes/digests and the complete typed Value.
        for o in got
            .body
            .outputs
            .iter()
            .chain(got.body.collateral_return.iter())
        {
            let start = o.span.offset * 2;
            let standalone =
                decode_original_output(&raw[start..start + 2 * o.span.length]).unwrap();
            assert_eq!(standalone.span.offset, 0, "{name}: standalone span");
            assert_eq!(standalone.span.sha256, o.span.sha256);
            assert_eq!(standalone.value.span.sha256, o.value.span.sha256);
            assert_eq!(
                standalone.value.scalus_compatibility(),
                o.value.scalus_compatibility()
            );
        }
        passed += 1;
    }
    assert_eq!((passed, rejected), (46, 32));
}

#[test]
fn standalone_output_limits_are_checked_before_use() {
    assert_eq!(decode_original_output("").unwrap_err(), Bound);
    assert_eq!(
        decode_original_output(&"00".repeat(MAX_BYTES + 1)).unwrap_err(),
        Bound
    );
    assert_eq!(decode_original_output("8241FF01").unwrap_err(), Encoding);
    assert_eq!(decode_original_output("8241000100").unwrap_err(), Encoding);
    let output = decode_original_output("8241001bffffffffffffffff").unwrap();
    assert_eq!(output.value.coin, u64::MAX);
    assert_eq!(
        output.value.scalus_compatibility(),
        json!({"error":"scalus-value-quantity"})
    );
}
