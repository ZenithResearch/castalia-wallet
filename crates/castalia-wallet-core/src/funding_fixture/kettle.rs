//! Default-off, fresh-only K3 synthetic capability. Never production human consent.
//! The independent owner authenticates actual ledger observation, accepted Add,
//! script-data integrity, fees/minima and compiled preflight. Native code binds
//! those originals to a closed, independently decoded role and accounting review.
mod inspect;
use super::*;

pub const PROFILE_DOMAIN_V3: &str = "castalia/cardano-fixture-profile/v3\0";
pub const CONTEXT_DOMAIN_V3: &str = "castalia/cardano-fixture-context/v3\0";
pub const ADMISSION_DOMAIN_V3: &str = "castalia/cardano-fixture-admission/v3\0";
pub const KETTLE_HASH: &str = "5d50ccd67901c146fc4938371e1ff877d42864833218acf735cb5261";
pub const COMPANION_HASH: &str = "ec17adcfd67ff9c84f4d9d4a0c516482ff5de676c0d9cfda1ed530bf";
pub const ARTIFACT_HASH: &str = "2102de0164ee3b09f925f451338e978dfb6825090d0d6038ab26746488cb00f3";
pub const EXECUTION_HASH: &str = "e293f4cdadf53d216024ba45c822f6c85562d7335e28bfa2c8ad6068e50cf95f";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KettleRef {
    pub tx_hash: String,
    pub output_index: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KettleFixtureProfile {
    pub schema: String,
    pub backend: String,
    pub execution_profile_digest: String,
    pub script_artifact_sha256: String,
    pub kettle_script_hash: String,
    pub companion_script_hash: String,
    pub deployment_id: String,
    pub seed: KettleRef,
    pub descriptor_data_hex: String,
    pub source_content_data_hex: String,
}
impl KettleFixtureProfile {
    /// Public immutable source-admitted fixture profile, never installed implicitly.
    pub fn qualified() -> Self {
        Self {
            schema: "castalia.cardano-fixture-execution-profile.v3".into(),
            backend: "scalus-1.4.1".into(),
            execution_profile_digest: EXECUTION_HASH.into(),
            script_artifact_sha256: ARTIFACT_HASH.into(),
            kettle_script_hash: KETTLE_HASH.into(),
            companion_script_hash: COMPANION_HASH.into(),
            deployment_id: "cf".repeat(32),
            seed: KettleRef {
                tx_hash: "ce".repeat(32),
                output_index: 0,
            },
            descriptor_data_hex: hex::encode(inspect::qualified_descriptor()),
            source_content_data_hex: hex::encode(inspect::qualified_content()),
        }
    }
    fn validate(&self) -> FixtureResult<()> {
        if self != &Self::qualified() {
            return Err(FixtureError("unqualified K3 fixture profile"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KettleInputRole {
    Normal,
    Reference,
    Collateral,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KettleReviewUtxo {
    pub role: KettleInputRole,
    pub tx_hash: String,
    pub output_index: u32,
    pub utxo_cbor_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KettleAcceptedAdd {
    pub tx_hash: String,
    pub output_index: u32,
    pub descriptor_data_hex: String,
    pub source_content_data_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KettleReviewContext {
    pub schema: String,
    pub observed_slot: u64,
    pub accepted_add: KettleAcceptedAdd,
    pub utxos: Vec<KettleReviewUtxo>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KettleInspection {
    pub statement: JsonValue,
    pub review: JsonValue,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KettlePreparation {
    pub handle: String,
    pub review: JsonValue,
}
struct KettlePrepared {
    body_hash: [u8; 32],
    epoch: u64,
    generation: u64,
    context_digest: String,
    deadline: Instant,
}

/// A separate wrapper owns fresh custody; it exposes none of the inner v1/v2 methods.
/// No constructor accepts keys, a saved Wallet, recovery bytes or a caller signer.
pub struct KettleFixtureSession {
    inner: FundingFixtureSession,
    profile: Option<KettleFixtureProfile>,
    profile_digest: Option<String>,
    context: Option<Context>,
    pending: BTreeMap<String, KettlePrepared>,
    used: BTreeSet<String>,
}
impl KettleFixtureSession {
    pub fn fresh(owner: [u8; 32], network: CardanoFundingNetworkV1) -> FixtureResult<Self> {
        Self::fresh_with_ttl(owner, network, Duration::from_secs(30))
    }
    pub fn fresh_with_ttl(
        owner: [u8; 32],
        network: CardanoFundingNetworkV1,
        ttl: Duration,
    ) -> FixtureResult<Self> {
        let key =
            VerifyingKey::from_bytes(&owner).map_err(|_| FixtureError("invalid fixture owner"))?;
        if key.is_weak() {
            return Err(FixtureError("weak fixture owner"));
        }
        if network.network_magic() != 2 || network.genesis_hash() != "12".repeat(32) {
            return Err(FixtureError("unqualified K3 fixture network"));
        }
        Ok(Self {
            inner: FundingFixtureSession::fresh_with_ttl(owner, network, ttl)?,
            profile: None,
            profile_digest: None,
            context: None,
            pending: BTreeMap::new(),
            used: BTreeSet::new(),
        })
    }
    pub fn info(&self) -> &FixtureInfo {
        self.inner.info()
    }
    pub fn profile_statement(&self, profile: &KettleFixtureProfile) -> FixtureResult<JsonValue> {
        self.inner.active()?;
        profile.validate()?;
        Ok(
            json!({"schema":"castalia.cardano-fixture-profile.v3","sessionId":self.info().session_id,"epoch":self.info().epoch,"network":self.info().account.network(),"profile":profile}),
        )
    }
    pub fn set_profile(
        &mut self,
        profile: KettleFixtureProfile,
        signature: &str,
    ) -> FixtureResult<String> {
        if self.profile.is_some() {
            return Err(FixtureError("K3 fixture profile immutable"));
        }
        let statement = self.profile_statement(&profile)?;
        self.inner
            .verify(PROFILE_DOMAIN_V3, &statement, signature)?;
        let digest = sha(&canonical(&statement)?);
        self.profile = Some(profile);
        self.profile_digest = Some(digest.clone());
        Ok(digest)
    }
    pub fn context_statement(&self, generation: u64, digest: &str) -> FixtureResult<JsonValue> {
        self.inner.active()?;
        if generation == 0 || generation > MAX_JSON_INTEGER || !lower_hex(digest, 32) {
            return Err(FixtureError("invalid K3 observation"));
        }
        let profile = self
            .profile_digest
            .as_ref()
            .ok_or(FixtureError("K3 profile not installed"))?;
        Ok(
            json!({"schema":"castalia.cardano-fixture-context.v3","sessionId":self.info().session_id,"epoch":self.info().epoch,"profileDigest":profile,"generation":generation,"digest":digest}),
        )
    }
    pub fn set_context(
        &mut self,
        generation: u64,
        digest: &str,
        signature: &str,
    ) -> FixtureResult<()> {
        let statement = self.context_statement(generation, digest)?;
        self.inner
            .verify(CONTEXT_DOMAIN_V3, &statement, signature)?;
        if self
            .context
            .as_ref()
            .is_some_and(|c| generation <= c.generation)
        {
            return Err(FixtureError("stale K3 observation generation"));
        }
        self.pending.clear();
        self.used.clear();
        self.context = Some(Context {
            generation,
            digest: digest.into(),
        });
        Ok(())
    }
    pub fn inspect(
        &self,
        transaction_hex: &str,
        review_context: &KettleReviewContext,
    ) -> FixtureResult<KettleInspection> {
        self.inner.active()?;
        let profile = self
            .profile
            .as_ref()
            .ok_or(FixtureError("K3 profile not installed"))?;
        let context = self
            .context
            .as_ref()
            .ok_or(FixtureError("K3 context not installed"))?;
        inspect::context_bounds(review_context)?;
        let context_hash = sha(&canonical(review_context)?);
        if context_hash != context.digest {
            return Err(FixtureError("K3 observed context mismatch"));
        }
        let (body_hash, envelope_hash, review) = inspect::registered(
            transaction_hex,
            profile,
            review_context,
            self.info().account.payment_key_hash(),
        )?;
        let statement = json!({"schema":"castalia.cardano-fixture-admission.v3","sessionId":self.info().session_id,"epoch":self.info().epoch,"profileDigest":self.profile_digest,"contextGeneration":context.generation,"contextDigest":context.digest,"paymentKeyHash":self.info().account.payment_key_hash(),"transactionBodyHash":hex::encode(body_hash),"transactionEnvelopeHash":envelope_hash,"reviewHash":sha(&canonical(&review)?),"reviewContextHash":context_hash});
        Ok(KettleInspection { statement, review })
    }
    pub fn prepare(
        &mut self,
        transaction_hex: &str,
        context: &KettleReviewContext,
        signature: &str,
    ) -> FixtureResult<KettlePreparation> {
        // Expiry releases pending capacity but never reauthorizes a used admission.
        self.pending.retain(|_, p| Instant::now() < p.deadline);
        if self.pending.len() >= MAX_PENDING {
            return Err(FixtureError("too many K3 preparations"));
        }
        let inspected = self.inspect(transaction_hex, context)?;
        self.inner
            .verify(ADMISSION_DOMAIN_V3, &inspected.statement, signature)?;
        let id = sha(&canonical(&inspected.statement)?);
        if self.used.len() >= 64 || !self.used.insert(id) {
            return Err(FixtureError("reused or exhausted K3 admission"));
        }
        let body_hash = hex::decode(
            inspected.statement["transactionBodyHash"]
                .as_str()
                .ok_or(FixtureError("missing K3 body hash"))?,
        )
        .map_err(|_| FixtureError("invalid K3 body hash"))?
        .try_into()
        .map_err(|_| FixtureError("invalid K3 body hash"))?;
        let observed = self
            .context
            .as_ref()
            .ok_or(FixtureError("K3 context not installed"))?;
        let handle = nonce();
        self.pending.insert(
            handle.clone(),
            KettlePrepared {
                body_hash,
                epoch: self.info().epoch,
                generation: observed.generation,
                context_digest: observed.digest.clone(),
                deadline: Instant::now() + self.inner.ttl,
            },
        );
        Ok(KettlePreparation {
            handle,
            review: inspected.review,
        })
    }
    pub fn approve(&mut self, handle: &str) -> FixtureResult<FixtureWitness> {
        let p = self
            .pending
            .remove(handle)
            .ok_or(FixtureError("unknown or consumed K3 handle"))?;
        self.inner.active()?;
        let context = self
            .context
            .as_ref()
            .ok_or(FixtureError("K3 context not installed"))?;
        if p.epoch != self.info().epoch
            || p.generation != context.generation
            || p.context_digest != context.digest
            || Instant::now() >= p.deadline
        {
            return Err(FixtureError("stale K3 preparation"));
        }
        let wallet = self
            .inner
            .wallet
            .as_ref()
            .ok_or(FixtureError("K3 session closed"))?;
        let root = Zeroizing::new(wallet.signing_key.to_bytes());
        let (public, signature) =
            crate::chain_accounts::cardano_payment_fixture_witness(&root, &p.body_hash);
        Ok(FixtureWitness {
            label: "synthetic-fixture-approval-only".into(),
            transaction_body_hash: hex::encode(p.body_hash),
            public_key: hex::encode(public),
            signature: hex::encode(signature),
        })
    }
    pub fn cancel(&mut self, handle: &str) -> bool {
        self.pending.remove(handle).is_some()
    }
    pub fn invalidate(&mut self) -> FixtureResult<()> {
        self.pending.clear();
        self.used.clear();
        self.context = None;
        self.inner.invalidate()
    }
    pub fn close(&mut self) {
        self.inner.close();
        self.pending.clear();
        self.used.clear();
        self.context = None;
    }
}
/// Public read-only vector inspection, with no custody or signing capability.
pub fn inspect_public_fixture(
    transaction_hex: &str,
    profile: &KettleFixtureProfile,
    context: &KettleReviewContext,
    payment_key_hash: &str,
) -> FixtureResult<JsonValue> {
    Ok(inspect::registered(transaction_hex, profile, context, payment_key_hash)?.2)
}
