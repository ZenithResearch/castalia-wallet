//! Disposable issuer keys, never real credentials or an alternate holder signer.
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use castalia_wallet_core::recovery_session::RecoverySession;
use castalia_wallet_presentation::{Caller, TrustPin, canonical_json, digest, verify_presentation};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;
use serde_json::{Value, json};
const NOW: u64 = 1_800_000_000;
fn call(s: &mut RecoverySession, v: Value) -> Value {
    s.invoke(&v.to_string()).expect("session operation")
}
fn commit(s: &mut RecoverySession, p: Value) -> String {
    let c = call(
        s,
        json!({"operation":"commit_candidate","token":p["token"],"expected_revision":p["expected_revision"]}),
    );
    let snap = c["snapshot"].as_str().unwrap().to_owned();
    call(
        s,
        json!({"operation":"confirm_commit","token":p["token"],"snapshot":snap}),
    );
    snap
}
struct Fixture {
    s: RecoverySession,
    issuer: SigningKey,
    owner: String,
    snapshot: String,
    pins: Vec<TrustPin>,
    caller: Caller,
}
impl Fixture {
    fn new() -> Self {
        let mut s = RecoverySession::new();
        let p = call(
            &mut s,
            json!({"operation":"prepare_create","password":"fixture password 123","created_at":1,"expected_revision":0}),
        );
        commit(&mut s, p);
        let owner = call(&mut s, json!({"operation":"state"}))["public_key"]
            .as_str()
            .unwrap()
            .to_owned();
        let recovery = call(
            &mut s,
            json!({"operation":"export_recovery","password":"fixture password 123"}),
        );
        let p = call(
            &mut s,
            json!({"operation":"verify_backup","file":recovery["file"],"password":"fixture password 123"}),
        );
        commit(&mut s, p);
        let issuer = SigningKey::generate(&mut OsRng);
        let public = hex::encode(issuer.verifying_key().as_bytes());
        let p = call(
            &mut s,
            json!({"operation":"prepare_trust","trust":{"v3":{"schema":"castalia.zenith-membership-trust-policy.v1","version":1,"roots":[{"issuerId":"fixture-issuer","keyId":"fixture-key","signatureSuite":"Ed25519","publicKey":public}]}}}),
        );
        commit(&mut s, p);
        let owner_bytes = hex::decode(&owner).unwrap();
        let mut id = b"castalia/zenith-membership-id/v3\0".to_vec();
        id.extend(&owner_bytes);
        let membership_id = digest(&id);
        let mut transcript = b"castalia/zenith-membership-credential/v3\0".to_vec();
        transcript.extend(3u64.to_le_bytes());
        transcript.extend(hex::decode(&membership_id).unwrap());
        transcript.extend(owner_bytes);
        for text in ["active", "fixture-issuer", "fixture-key", "ed25519"] {
            transcript.extend((text.len() as u32).to_le_bytes());
            transcript.extend(text.as_bytes());
        }
        let proof = json!({"schema":"castalia.zenith-membership-credential.v3","version":3,"membershipId":membership_id,"ownerPublicKey":owner,"status":"active","issuerId":"fixture-issuer","issuerKeyId":"fixture-key","signatureSuite":"Ed25519","issuerSignature":URL_SAFE_NO_PAD.encode(issuer.sign(&transcript).to_bytes())});
        let p = call(
            &mut s,
            json!({"operation":"activate_membership","proof":proof,"scoped":false}),
        );
        let snapshot = commit(&mut s, p);
        let caller = Caller {
            kind: "browser".into(),
            id: "http://127.0.0.1:4337".into(),
        };
        let pins = vec![TrustPin {
            issuer: "fixture-issuer".into(),
            key_id: "fixture-key".into(),
            public_key: public,
            audience: "fixture-service".into(),
            callers: vec![caller.clone()],
        }];
        Self {
            s,
            issuer,
            owner,
            snapshot,
            pins,
            caller,
        }
    }
    fn trust(&mut self) {
        call(
            &mut self.s,
            json!({"operation":"approve_presentation_trust","config":{"schema":"castalia.wallet-presentation-trust.v1","caller":self.caller,"pins":self.pins}}),
        );
    }
    fn request(&self) -> String {
        let disclosure =
            json!({"title":"Fixture request","statements":["Approve these exact bytes."]});
        let claims = json!({"schema":"castalia.request-credential.v1","issuer":"fixture-issuer","key_id":"fixture-key","holder_public_key":self.owner,"audience":"fixture-service","caller":self.caller,"request_digest_sha256":digest(b"opaque request"),"disclosure_digest_sha256":digest(&canonical_json(&disclosure).unwrap()),"policy_digest_sha256":"ab".repeat(32),"nonce":"01".repeat(16),"issued_at":NOW,"expires_at":NOW+120});
        let mut bytes = castalia_wallet_presentation::CREDENTIAL_DOMAIN.to_vec();
        bytes.extend(canonical_json(&claims).unwrap());
        json!({"schema":"castalia.credential-presentation-request.v2","request_bytes_base64":STANDARD.encode(b"opaque request"),"disclosure":disclosure,"credential":{"claims":claims,"signature":hex::encode(self.issuer.sign(&bytes).to_bytes())}}).to_string()
    }
    fn prepare(&mut self) -> Value {
        let request = self.request();
        call(
            &mut self.s,
            json!({"operation":"prepare_credential_presentation","request":request,"now":NOW}),
        )
    }
    fn approve(&mut self, p: &Value, now: u64) -> Result<Value, &'static str> {
        self.s.invoke(
            &json!({"operation":"approve_credential_presentation","token":p["token"],"now":now})
                .to_string(),
        )
    }
}
#[test]
fn same_custody_signs_once_without_changing_storage_or_recovery() {
    let mut f = Fixture::new();
    assert!(
        f.s.invoke(
            &json!({"operation":"prepare_credential_presentation","request":f.request(),"now":NOW})
                .to_string()
        )
        .is_err()
    );
    f.trust();
    let identity = call(&mut f.s, json!({"operation":"presentation_identity"}));
    assert_eq!(identity["public_key"], f.owner);
    assert_eq!(identity["membership"]["ownerPublicKey"], f.owner);
    let p = f.prepare();
    assert_eq!(p["summary"]["holder_public_key"], f.owner);
    let result = f.approve(&p, NOW + 1).unwrap();
    verify_presentation(
        f.request().as_bytes(),
        result["presentation"].as_str().unwrap().as_bytes(),
        &f.pins,
        &f.caller,
        NOW + 1,
    )
    .unwrap();
    assert!(f.approve(&p, NOW + 1).is_err());
    assert_eq!(call(&mut f.s, json!({"operation":"state"}))["revision"], 4);
    call(&mut f.s, json!({"operation":"lock"}));
    call(
        &mut f.s,
        json!({"operation":"unlock","snapshot":f.snapshot,"password":"fixture password 123"}),
    );
    assert!(
        f.s.invoke(
            &json!({"operation":"prepare_credential_presentation","request":f.request(),"now":NOW})
                .to_string()
        )
        .is_err(),
        "trust is session-only"
    );
    f.trust();
    f.prepare();
}
#[test]
fn cancellation_failed_preparation_clock_and_mutation_invalidate_consent() {
    let mut f = Fixture::new();
    f.trust();
    let p = f.prepare();
    assert!(f.s.invoke("not json").is_err());
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    call(
        &mut f.s,
        json!({"operation":"cancel_credential_presentation"}),
    );
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    assert!(
        f.s.invoke(
            &json!({"operation":"prepare_credential_presentation","request":"{}","now":NOW})
                .to_string()
        )
        .is_err()
    );
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    assert!(f.approve(&p, NOW - 1).is_err());
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    assert!(f.approve(&p, NOW + 120).is_err());
    let p = f.prepare();
    assert!(
        f.s.invoke(
            &json!({"operation":"approve_credential_presentation","token":"wrong","now":NOW})
                .to_string()
        )
        .is_err()
    );
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    call(&mut f.s, json!({"operation":"cancel"}));
    assert!(f.approve(&p, NOW).is_err());
    let p = f.prepare();
    assert!(
        f.s.invoke(r#"{"operation":"prepare_trust","trust":{}}"#)
            .is_ok()
    );
    assert!(f.approve(&p, NOW).is_err());
    call(&mut f.s, json!({"operation":"cancel"}));
    let p = f.prepare();
    call(&mut f.s, json!({"operation":"lock"}));
    assert!(f.approve(&p, NOW).is_err());
}
#[test]
fn backup_membership_and_explicit_pinned_caller_are_required() {
    let mut f = Fixture::new();
    f.trust();
    let p = f.prepare();
    assert!(f.s.invoke(&json!({"operation":"approve_presentation_trust","config":{"schema":"castalia.wallet-presentation-trust.v1","caller":{"kind":"browser","id":"https://different.example"},"pins":f.pins}}).to_string()).is_err());
    assert!(f.approve(&p, NOW).is_err());
    let mut empty = RecoverySession::new();
    assert!(
        empty
            .invoke(r#"{"operation":"presentation_identity"}"#)
            .is_err()
    );
    let p = call(
        &mut empty,
        json!({"operation":"prepare_create","password":"fixture password 123","created_at":1,"expected_revision":0}),
    );
    commit(&mut empty, p);
    assert!(empty.invoke(&json!({"operation":"approve_presentation_trust","config":{"schema":"castalia.wallet-presentation-trust.v1","caller":f.caller,"pins":f.pins}}).to_string()).is_err());
    assert!(empty.invoke(&json!({"operation":"prepare_credential_presentation","request":f.request(),"now":NOW}).to_string()).is_err());
}
