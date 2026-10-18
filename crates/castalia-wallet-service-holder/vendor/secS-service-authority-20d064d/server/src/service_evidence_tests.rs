use super::*;
#[test]
fn exact_framing_golden_matches_independent_vector() {
    let input = EvidenceInput {
        owner: [0xbb; 32],
        descriptor: [0xaa; 32],
        subject: "holder:fixture".into(),
        audience: "runtime://receiver-local".into(),
        operation: "runtime.run.create.v1".into(),
        resource: "runs/run-1".into(),
        request: [0xcc; 32],
        start: 90,
        end: 160,
        observed: 100,
    };
    let value = encode(&input, [0xa5; 32]);
    let hex: String = value
        .bindings
        .evidence_snapshot_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        hex,
        "5c4084f97feba34f89b34d9973c6ae2bfe9937c05cc01f9671e8e46a07e793d1"
    );
    assert_eq!(value.bindings.evidence_observed_at, 100);
}
fn input() -> EvidenceInput {
    EvidenceInput {
        owner: [0xbb; 32],
        descriptor: [0xaa; 32],
        subject: "holder:fixture".into(),
        audience: "runtime://receiver-local".into(),
        operation: "runtime.run.create.v1".into(),
        resource: "runs/run-1".into(),
        request: [0xcc; 32],
        start: 90,
        end: 160,
        observed: 100,
    }
}
fn descriptor() -> OperationDescriptor {
    use crate::manifest::{OpcodeRange, OperationName, ReplayScope, TargetKind};
    OperationDescriptor {
        opcode: 66,
        name: OperationName::new("runtime.run.create.v1"),
        payload_schema: None,
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec![],
        required_capabilities: vec![],
        accepted_evidence: vec![],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: "fixture/runtime.run.create.v1".into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: crate::privacy::DisclosurePolicy::deny_by_default("fixture", 1),
    }
}
#[test]
fn actual_obligations_and_authority_mode_always_deny() {
    for i in 0..4 {
        let mut d = descriptor();
        match i {
            0 => d.required_credentials.push("caller.credential".into()),
            1 => d.required_capabilities.push("provider.scope".into()),
            2 => d.accepted_evidence.push("model.evidence".into()),
            _ => {
                d.required_authority_mode =
                    Some(crate::dregg_authority::AuthorityMode::SignedSource)
            }
        };
        assert!(matches!(
            prepare_none(&d, &input()),
            Err(EvidenceError::UnsupportedRequiredEvidence)
        ));
    }
}
#[test]
fn original_observation_deadline_and_lineage_never_refresh() {
    let d = descriptor();
    let i = input();
    let prepared = prepare_none(&d, &i).unwrap();
    revalidate_none(&d, &i, &prepared, 159).unwrap();
    assert_eq!(prepared.bindings.evidence_observed_at, 100);
    assert_eq!(
        revalidate_none(&d, &i, &prepared, 160),
        Err(EvidenceError::InvalidWindow)
    );
    let mut newer = i.clone();
    newer.observed = 120;
    assert_eq!(
        revalidate_none(&d, &newer, &prepared, 120),
        Err(EvidenceError::Changed)
    );
    let mut moved = i.clone();
    moved.owner = [1; 32];
    assert_eq!(
        revalidate_none(&d, &moved, &prepared, 120),
        Err(EvidenceError::Changed)
    );
}
#[test]
fn finite_horizon_and_safe_clock_are_required() {
    let d = descriptor();
    for (start, end, observed) in [
        (100, 100, 100),
        (0, 160, 0),
        (90, MAX_SAFE_TIME + 1, 100),
        (90, 160, 160),
    ] {
        let mut i = input();
        i.start = start;
        i.end = end;
        i.observed = observed;
        assert!(prepare_none(&d, &i).is_err());
    }
}

#[test]
fn epoch_zero_validity_start_preserves_positive_observation_and_exclusive_end() {
    let d = descriptor();
    let mut i = input();
    i.start = 0;
    let prepared = prepare_none(&d, &i).unwrap();
    assert_eq!(prepared.bindings.evidence_valid_not_before, 0);
    assert_eq!(prepared.bindings.evidence_observed_at, 100);
    revalidate_none(&d, &i, &prepared, 159).unwrap();
    assert_eq!(
        revalidate_none(&d, &i, &prepared, 160),
        Err(EvidenceError::InvalidWindow)
    );
    i.observed = 0;
    assert!(matches!(
        prepare_none(&d, &i),
        Err(EvidenceError::InvalidWindow)
    ));
}
