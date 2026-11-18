//! Synthetic admission capability, never evidence of end-user consent.
use super::*;
use crate::marsh_creation::{self as codec, TrustCommitment, TrustPath};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::Signer;
pub const MARSH_PROFILE_DOMAIN: &str = "castalia/marsh-fixture-profile/v1\0";
pub const MARSH_CONTEXT_DOMAIN: &str = "castalia/marsh-fixture-context/v1\0";
pub const MARSH_ADMISSION_DOMAIN: &str = "castalia/marsh-fixture-admission/v1\0";
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarshFixturePreparation {
    pub handle: String,
    pub review: JsonValue,
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MarshFixtureProof {
    pub label: String,
    /// The exact frozen A3 DTO. The A4 trust path is deliberately separate.
    pub proof: JsonValue,
    pub trust_path: TrustPath,
    pub review_hash: String,
}
struct MarshPrepared {
    message: Vec<u8>,
    credential: JsonValue,
    path: TrustPath,
    review_hash: String,
    epoch: u64,
    generation: u64,
    context_digest: String,
    deadline: Instant,
}
#[derive(Default)]
pub(super) struct MarshState {
    admission: Option<JsonValue>,
    profile_digest: Option<String>,
    trust: Option<TrustCommitment>,
    context: Option<Context>,
    pending: BTreeMap<String, MarshPrepared>,
    used: BTreeSet<String>,
}
impl MarshState {
    pub(super) fn invalidate(&mut self) {
        self.context = None;
        self.pending.clear();
        self.used.clear();
    }
}
fn checked<T>(r: codec::Result<T>) -> FixtureResult<T> {
    r.map_err(FixtureError)
}
impl FundingFixtureSession {
    /// Public MemberKey only, from the same custody root as `info().account`.
    pub fn member_key(&self) -> FixtureResult<String> {
        self.active()?;
        Ok(self.wallet.as_ref().unwrap().public_key_hex())
    }
    pub fn marsh_profile_statement(&self, raw: &str) -> FixtureResult<JsonValue> {
        self.active()?;
        let admission = checked(codec::parse(raw))?;
        let obj = admission
            .as_object()
            .ok_or(FixtureError("invalid Marsh profile"))?;
        if obj.len() != 2
            || !obj.contains_key("deployment")
            || !obj.contains_key("membershipTrustPolicy")
        {
            return Err(FixtureError("invalid Marsh profile fields"));
        }
        checked(codec::deployment(&admission["deployment"]))?;
        let network = self.info.account.network();
        let supplied = &admission["deployment"]["network"];
        if supplied["id"]["magic"].as_u64() != Some(network.network_magic().into())
            || supplied["genesisDigest"] != network.genesis_hash()
            || supplied["genesisKind"] != network.genesis_kind()
        {
            return Err(FixtureError("Marsh profile network mismatch"));
        }
        let trust = checked(codec::trust_commitment(&admission["membershipTrustPolicy"]))?;
        Ok(
            json!({"schema":"castalia.marsh-fixture-profile.v1","sessionId":self.info.session_id,"epoch":self.info.epoch,"account":self.info.account,"admission":admission,"trust":trust}),
        )
    }
    /// Independent synthetic signer authenticates the whole immutable manifest.
    /// This API admits no production profile and does not accept trust in a proof.
    pub fn install_marsh_profile(&mut self, raw: &str, signature: &str) -> FixtureResult<String> {
        if self.marsh.admission.is_some() {
            return Err(FixtureError("Marsh profile immutable"));
        }
        let statement = self.marsh_profile_statement(raw)?;
        self.verify(MARSH_PROFILE_DOMAIN, &statement, signature)?;
        let digest = sha(&canonical(&statement)?);
        self.marsh.trust = Some(
            serde_json::from_value(statement["trust"].clone())
                .map_err(|_| FixtureError("invalid trust"))?,
        );
        self.marsh.admission = Some(statement["admission"].clone());
        self.marsh.profile_digest = Some(digest.clone());
        self.marsh.invalidate();
        Ok(digest)
    }
    pub fn marsh_context_statement(
        &self,
        generation: u64,
        digest: &str,
    ) -> FixtureResult<JsonValue> {
        self.active()?;
        if generation > MAX_JSON_INTEGER || !lower_hex(digest, 32) {
            return Err(FixtureError("invalid Marsh observation"));
        }
        let profile = self
            .marsh
            .profile_digest
            .as_ref()
            .ok_or(FixtureError("Marsh profile not installed"))?;
        Ok(
            json!({"schema":"castalia.marsh-fixture-context.v1","sessionId":self.info.session_id,"epoch":self.info.epoch,"profileDigest":profile,"generation":generation,"digest":digest}),
        )
    }
    pub fn set_marsh_context(
        &mut self,
        generation: u64,
        digest: &str,
        signature: &str,
    ) -> FixtureResult<()> {
        let statement = self.marsh_context_statement(generation, digest)?;
        self.verify(MARSH_CONTEXT_DOMAIN, &statement, signature)?;
        if self
            .marsh
            .context
            .as_ref()
            .is_some_and(|c| generation <= c.generation)
        {
            return Err(FixtureError("stale Marsh observation"));
        }
        self.marsh.pending.clear();
        self.marsh.used.clear();
        self.marsh.context = Some(Context {
            generation,
            digest: digest.into(),
        });
        Ok(())
    }
    /// Raw wire input is size bounded and rejects duplicate JSON fields before projection.
    /// `context` contains logical projected addresses; ledger/network projection is the
    /// independent synthetic admission signer's responsibility, not asserted by this API.
    pub fn inspect_marsh_creation(&self, raw: &str) -> FixtureResult<JsonValue> {
        self.active()?;
        let request = checked(codec::parse(raw))?;
        let obj = request
            .as_object()
            .ok_or(FixtureError("invalid Marsh request"))?;
        if obj.len() != 2 || !obj.contains_key("context") || !obj.contains_key("credential") {
            return Err(FixtureError("invalid Marsh request fields"));
        }
        let admission = self
            .marsh
            .admission
            .as_ref()
            .ok_or(FixtureError("Marsh profile not installed"))?;
        let observation = self
            .marsh
            .context
            .as_ref()
            .ok_or(FixtureError("Marsh context not installed"))?;
        let c = &request["credential"];
        let context = &request["context"];
        let message = checked(codec::holder_transcript(context, c))?;
        if checked(codec::deployment(&context["deployment"]))?
            != checked(codec::deployment(&admission["deployment"]))?
        {
            return Err(FixtureError("Marsh deployment mismatch"));
        }
        let owner = self.member_key()?;
        if c["ownerPublicKey"] != owner
            || context["initialController"] != self.info.account.payment_key_hash()
        {
            return Err(FixtureError("Marsh own custody identity mismatch"));
        }
        let trust = crate::portable::Trust {
            v3: Some(admission["membershipTrustPolicy"].clone()),
            v4: None,
        };
        checked(crate::portable::verify_proof(c, &owner, &trust, false))?;
        let (commitment, path) = checked(codec::trust_path(
            &admission["membershipTrustPolicy"],
            c["issuerId"]
                .as_str()
                .ok_or(FixtureError("missing issuer"))?,
            c["issuerKeyId"]
                .as_str()
                .ok_or(FixtureError("missing issuer key"))?,
        ))?;
        if self.marsh.trust.as_ref() != Some(&commitment) {
            return Err(FixtureError("Marsh trust mismatch"));
        }
        checked(codec::verify_trust_path(c, &path, &commitment))?;
        Ok(
            json!({"schema":"castalia.marsh-fixture-admission.v1","label":"synthetic-fixture-admission-only","sessionId":self.info.session_id,"epoch":self.info.epoch,"profileDigest":self.marsh.profile_digest,"contextGeneration":observation.generation,"contextDigest":observation.digest,"account":self.info.account,"memberKey":owner,"context":context,"credential":c,"credentialCommitment":hex::encode(checked(codec::credential_commitment(c))?),"holderTranscriptHash":sha(&message),"trust":commitment,"trustPath":path}),
        )
    }
    pub fn prepare_marsh_creation(
        &mut self,
        raw: &str,
        signature: &str,
    ) -> FixtureResult<MarshFixturePreparation> {
        // Expired handles no longer reserve pending slots. Keep their admission
        // hashes consumed until an authenticated observation/epoch change.
        let now = Instant::now();
        self.marsh
            .pending
            .retain(|_, prepared| now < prepared.deadline);
        if self.marsh.pending.len() >= MAX_PENDING {
            return Err(FixtureError("too many Marsh preparations"));
        }
        let review = self.inspect_marsh_creation(raw)?;
        self.verify(MARSH_ADMISSION_DOMAIN, &review, signature)?;
        let review_hash = sha(&canonical(&review)?);
        if self.marsh.used.len() >= 64 || !self.marsh.used.insert(review_hash.clone()) {
            return Err(FixtureError("reused or exhausted Marsh admission"));
        }
        let message = checked(codec::holder_transcript(
            &review["context"],
            &review["credential"],
        ))?;
        let context = self.marsh.context.as_ref().unwrap();
        let handle = nonce();
        self.marsh.pending.insert(
            handle.clone(),
            MarshPrepared {
                message,
                credential: review["credential"].clone(),
                path: serde_json::from_value(review["trustPath"].clone())
                    .map_err(|_| FixtureError("invalid path"))?,
                review_hash,
                epoch: self.info.epoch,
                generation: context.generation,
                context_digest: context.digest.clone(),
                deadline: Instant::now() + self.ttl,
            },
        );
        Ok(MarshFixturePreparation { handle, review })
    }
    pub fn approve_marsh_creation(&mut self, handle: &str) -> FixtureResult<MarshFixtureProof> {
        // Consume first, including stale/failed approval attempts. No replacement terms.
        let p = self
            .marsh
            .pending
            .remove(handle)
            .ok_or(FixtureError("unknown or consumed Marsh handle"))?;
        self.active()?;
        let c = self
            .marsh
            .context
            .as_ref()
            .ok_or(FixtureError("Marsh context not installed"))?;
        if p.epoch != self.info.epoch
            || p.generation != c.generation
            || p.context_digest != c.digest
            || Instant::now() >= p.deadline
        {
            return Err(FixtureError("stale Marsh preparation"));
        }
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(FixtureError("fixture session closed"))?;
        // The only new private-key use: frozen, validated A3 bytes, retained in custody.
        let signature = wallet.signing_key.sign(&p.message);
        Ok(MarshFixtureProof {
            label: "synthetic-fixture-approval-only".into(),
            proof: json!({"schema":"castalia.marsh-creation-proof.v1","credential":p.credential,"holderSignature":B64.encode(signature.to_bytes())}),
            trust_path: p.path,
            review_hash: p.review_hash,
        })
    }
    pub fn cancel_marsh_creation(&mut self, handle: &str) -> bool {
        self.marsh.pending.remove(handle).is_some()
    }
}
