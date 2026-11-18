//! Original-byte role resolution and accounting for the three selected current actions.
use super::super::cbor::Node;
use super::data::*;
use super::*;
#[path = "../current_approval_v2/fixed.rs"]
pub(in crate::funding_fixture) mod fixed_v2;

type Amounts = BTreeMap<String, i128>;

#[derive(Clone, Debug, Deserialize)]
struct Span {
    offset: usize,
    length: usize,
    sha256: String,
}
impl Span {
    fn extract(&self, raw: &str) -> FixtureResult<Vec<u8>> {
        let bytes = raw
            .get(self.offset * 2..(self.offset + self.length) * 2)
            .and_then(|h| hex::decode(h).ok())
            .ok_or(FixtureError("invalid original span"))?;
        ensure(sha(&bytes) == self.sha256, "original span digest")?;
        Ok(bytes)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    policy_id: String,
    asset_name: String,
    quantity: String,
}
#[derive(Clone, Debug, Deserialize)]
struct Value {
    coin: String,
    assets: Vec<Asset>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Datum {
    Inline { span: Span },
    Hash {},
}
#[derive(Clone, Debug, Deserialize)]
struct ScriptRef {
    language: String,
    span: Span,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Output {
    span: Span,
    address: String,
    value: Value,
    datum: Option<Datum>,
    script_ref: Option<ScriptRef>,
}
#[derive(Deserialize)]
struct Redeemer {
    purpose: String,
    index: u32,
    target: Json,
    data: Span,
    memory: String,
    steps: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    body: Span,
    envelope: Span,
    witness_set: Span,
    tag: String,
    fee: String,
    ttl: Option<String>,
    validity_start: Option<String>,
    network_id: Option<u8>,
    script_data_hash: Option<String>,
    total_collateral: Option<String>,
    normal_inputs: Vec<Outpoint>,
    reference_inputs: Vec<Outpoint>,
    collateral_inputs: Vec<Outpoint>,
    required_signers: Vec<String>,
    outputs: Vec<Output>,
    collateral_return: Option<Output>,
    mint: Vec<Asset>,
    redeemers: Vec<Redeemer>,
    vkeys: Vec<Json>,
    native_scripts: Vec<Json>,
    plutus_v3_scripts: Vec<Json>,
}
fn parse_wire(raw: &str) -> FixtureResult<(Wire, String)> {
    let w = current_wire::decode_original_transaction(raw)
        .map_err(|_| FixtureError("current transaction wire"))?;
    let status = w.scalus_output_values();
    ensure(
        status["outputs"]
            .as_array()
            .is_some_and(|o| o.iter().all(|v| v.get("error").is_none()))
            && status["collateralReturn"].get("error").is_none(),
        "Scalus Value compatibility",
    )?;
    let tx: Wire = serde_json::from_value(
        serde_json::to_value(&w).map_err(|_| FixtureError("current wire projection"))?,
    )
    .map_err(|_| FixtureError("current wire fields"))?;
    Ok((tx, w.transaction_id().to_string()))
}
fn nat(s: &str, max: i128) -> FixtureResult<i128> {
    let n = s
        .parse::<i128>()
        .map_err(|_| FixtureError("invalid decimal quantity"))?;
    ensure(
        n >= 0 && n <= max && n.to_string() == s,
        "current canonical decimal quantity",
    )?;
    Ok(n)
}
fn amounts(o: &Output) -> FixtureResult<Amounts> {
    let mut m = BTreeMap::new();
    let coin = nat(&o.value.coin, MAX_Q)?;
    if coin > 0 {
        m.insert(String::new(), coin);
    }
    for a in &o.value.assets {
        let q = nat(&a.quantity, MAX_Q)?;
        ensure(q > 0, "positive holding")?;
        ensure(
            m.insert(format!("{}{}", a.policy_id, a.asset_name), q)
                .is_none(),
            "duplicate holding",
        )?;
    }
    Ok(m)
}
fn accumulate(out: &mut Amounts, source: &Amounts, sign: i128) {
    // At most six decoded normal inputs and five outputs, each quantity <= i63-TOP.
    for (k, v) in source {
        *out.entry(k.clone()).or_insert(0) += v * sign;
    }
    out.retain(|_, q| *q != 0);
}
fn plain(o: &Output, address: &str) -> FixtureResult<i128> {
    ensure(
        o.address == address
            && o.value.assets.is_empty()
            && o.datum.is_none()
            && o.script_ref.is_none(),
        "plain payer/owner role",
    )?;
    let coin = nat(&o.value.coin, MAX_Q)?;
    ensure(coin > 0, "positive operational coin")?;
    Ok(coin)
}
fn data_output(o: &Output, raw: &str) -> FixtureResult<Node> {
    let Some(Datum::Inline { span }) = &o.datum else {
        return Err(FixtureError("inline current datum"));
    };
    data_reader::read(&span.extract(raw)?)
}
fn data_ref(r: &Outpoint) -> FixtureResult<Node> {
    Ok(fields(vec![
        bytes(&decode_fixed::<32>(&r.tx_hash)?),
        number(i128::from(r.output_index)),
    ]))
}
fn str_ref(n: &Node) -> FixtureResult<Outpoint> {
    let a = ctor(n, 0, 2)?;
    Ok(Outpoint {
        tx_hash: hex::encode(octets(&a[0], 32, 32)?),
        output_index: bounded(&a[1], 0, u16::MAX.into())? as u16,
    })
}
fn spend(c: &Wire, raw: &str, r: &Outpoint) -> FixtureResult<Node> {
    let s = c
        .redeemers
        .iter()
        .find(|s| s.purpose == "spend" && s.target == json!(r))
        .ok_or(FixtureError("missing current spending purpose"))?;
    data_reader::read(&s.data.extract(raw)?)
}
struct Origins<'a> {
    parents: BTreeMap<&'a str, (&'a str, Vec<Output>)>,
}
impl<'a> Origins<'a> {
    fn new(c: &'a ReviewContext, w: &Wire) -> FixtureResult<Self> {
        Self::from_creators(&c.creators, w)
    }
    fn from_creators(creators: &'a [Creator], w: &Wire) -> FixtureResult<Self> {
        let ids: BTreeSet<_> = w
            .normal_inputs
            .iter()
            .chain(&w.reference_inputs)
            .chain(&w.collateral_inputs)
            .map(|r| r.tx_hash.as_str())
            .collect();
        ensure(
            (1..=8).contains(&ids.len()) && ids.len() == creators.len(),
            "exact number of original creators",
        )?;
        let mut total = 0usize;
        let mut parents = BTreeMap::new();
        for (expected, p) in ids.into_iter().zip(creators) {
            ensure(expected == p.tx_id, "sorted exact creating transaction set")?;
            total = total
                .checked_add(p.original.len())
                .ok_or(FixtureError("creator bytes"))?;
            ensure(total <= 2 * 65536, "creator original aggregate bound")?;
            let (tx, id) = parse_wire(&p.original)?;
            ensure(
                tx.tag == "normal-tag" && id == p.tx_id,
                "original accepted creator identity",
            )?;
            parents.insert(p.tx_id.as_str(), (p.original.as_str(), tx.outputs));
        }
        Ok(Self { parents })
    }
    fn at(&self, r: &Outpoint) -> FixtureResult<(&Output, &str)> {
        let (raw, out) = self
            .parents
            .get(r.tx_hash.as_str())
            .ok_or(FixtureError("unresolved creating envelope"))?;
        Ok((
            out.get(usize::from(r.output_index))
                .ok_or(FixtureError("unresolved creating output index"))?,
            *raw,
        ))
    }
}
fn code(o: &Output, raw: &str, expected: &str) -> FixtureResult<usize> {
    ensure(
        o.address.len() == 58
            && o.address.starts_with("60")
            && o.value.assets.is_empty()
            && nat(&o.value.coin, MAX_Q)? > 0
            && o.datum.is_none(),
        "plain key-owned code reference",
    )?;
    let s = o.script_ref.as_ref().ok_or(FixtureError("missing code"))?;
    ensure(s.language == "plutus-v3", "current executable language")?;
    let encoded = cbor::parse(&s.span.extract(raw)?)?;
    let pairs = encoded.array()?;
    ensure(
        pairs.len() == 2 && pairs[0].int()? == 3,
        "Plutus V3 script reference",
    )?;
    let code = pairs[1].bytes()?;
    let mut h = blake2::Blake2bVar::new(28).expect("28 bytes");
    use blake2::digest::{Update, VariableOutput};
    h.update(&[3]);
    h.update(code);
    let mut out = [0u8; 28];
    h.finalize_variable(&mut out).expect("28 bytes");
    ensure(
        hex::encode(out) == expected && code.len() == if expected == KETTLE { 16116 } else { 8324 },
        "pinned script bytes and hash",
    )?;
    Ok(code.len())
}
fn enter(hash: &str, is_script: bool) -> String {
    format!("{}{}", if is_script { "70" } else { "60" }, hash)
}
fn state(o: &Output, raw: &str) -> FixtureResult<(String, Vec<String>, i128, String)> {
    let marker = KETTLE.to_owned() + &hex::encode("PROPOSAL_STATE");
    let expected = BTreeMap::from([(String::new(), 5_000_000), (marker, 1)]);
    ensure(
        o.address == enter(KETTLE, true) && o.script_ref.is_none() && amounts(o)? == expected,
        "current singleton reserve and identity",
    )?;
    let n = data_output(o, raw)?;
    let a = ctor(&n, 0, 5)?;
    ensure(
        a[0].int()? == 1 && a[3].int()? == 5_000_000,
        "current state schema/reserve",
    )?;
    let auth = ctor(&a[1], 0, 2)?;
    let controller = hex::encode(octets(&auth[0], 28, 28)?);
    let roster = auth[1]
        .array()?
        .iter()
        .map(|x| Ok(hex::encode(octets(x, 28, 28)?)))
        .collect::<FixtureResult<Vec<_>>>()?;
    ensure(
        (2..=16).contains(&roster.len())
            && roster.iter().collect::<BTreeSet<_>>().len() == roster.len(),
        "current unique recovery roster",
    )?;
    Ok((
        controller,
        roster,
        bounded(&a[2], 0, MAX_Q)?,
        hex::encode(octets(&a[4], 32, 32)?),
    ))
}

fn unit(n: &[Node]) -> FixtureResult<(String, String, String)> {
    let policy = hex::encode(octets(&n[0], 0, 28)?);
    let name = hex::encode(octets(&n[1], 0, 32)?);
    ensure(
        (policy.is_empty() && name.is_empty()) || (policy.len() == 56 && policy != KETTLE),
        "current principal/cap namespace",
    )?;
    Ok((policy.clone() + &name, policy, name))
}

struct PolicyChange {
    name: &'static str,
    effect: Json,
    prior_commit: Option<String>,
    next_commit: String,
    carrier: Option<Outpoint>,
    destination: Option<String>,
    payment: Amounts,
    invoke: Option<Node>,
}
fn policy_change(c: &ReviewContext, outer: &Node, next_root: &str) -> FixtureResult<PolicyChange> {
    let a = ctor(outer, 5, 1)?;
    let (tag, payload) = a[0].constructor()?;
    let (name, len) = match tag {
        0 => ("add", 4),
        1 => ("disable", 2),
        2 => ("registered", 3),
        _ => return Err(FixtureError("unqualified current action")),
    };
    ensure(payload.len() == len, "current registry payload arity")?;
    let evidence = &c.policy;
    let (descriptor, raw_caps, content, prior_use, prior) = if tag == 0 {
        ensure(
            evidence.record.is_none() && evidence.content.is_none(),
            "Add needs authenticated absence",
        )?;
        (&payload[0], &payload[1], payload[2].clone(), None, None)
    } else {
        let record = &payload[0];
        let f = ctor(record, 0, 4)?;
        ctor(&f[1], 1, 0)?;
        let content = evidence
            .content
            .as_deref()
            .ok_or(FixtureError("missing current descriptor content"))?;
        ensure(
            content.len() <= 8192
                && evidence.record.as_deref() == Some(hex::encode(data(record)?).as_str()),
            "prior record and content bounds",
        )?;
        let decoded =
            data_reader::read(&hex::decode(content).map_err(|_| FixtureError("content hex"))?)?;
        ensure(
            hex::encode(data(&decoded)?) == content,
            "canonical source content",
        )?;
        (
            &f[0],
            &f[2],
            decoded,
            Some(octets(&f[3], 32, 32)?.to_vec()),
            Some(record),
        )
    };
    let d = ctor(descriptor, 0, 10)?;
    ensure(
        hex::encode(octets(&d[0], 1, 32)?) == evidence.id
            && hex::encode(octets(&d[2], 28, 28)?) == COMPANION,
        "current policy and executable",
    )?;
    bounded(&d[1], 1, 65535)?;
    bounded(&d[6], 1, 65535)?;
    bounded(&d[7], 1, 1)?;
    let input_bound = bounded(&d[8], 0, 512)? as usize;
    let asset_bound = bounded(&d[9], 1, 8)? as usize;
    let content_fields = ctor(&content, 0, 3)?;
    for (i, (domain, min, max)) in [
        ("parameters", 0, 256),
        ("constraints", 0, 256),
        ("schema", 1, 512),
    ]
    .into_iter()
    .enumerate()
    {
        octets(&content_fields[i], min, max)?;
        ensure(
            commit(
                &format!("castalia/kettle-policy-{domain}/v1"),
                &content_fields[i],
            )? == octets(&d[3 + i], 32, 32)?,
            "source content commitment",
        )?;
    }
    let path = payload
        .last()
        .ok_or(FixtureError("missing registry proof"))?;
    proof_matches(path, &evidence.proof)?;
    ensure(
        map_root(&d[0], prior, &evidence.proof)? == c.head.root,
        "proof against consumed current root",
    )?;
    let mut payment = Amounts::new();
    let mut carrier = None;
    let mut destination = None;
    let mut purpose_hex = None;
    let mut input_hex = None;
    let mut invoke = None;
    let mut next_use = match &prior_use {
        Some(v) => v.clone(),
        None => commit(
            "castalia/kettle-policy-use-initial/v1",
            &list(vec![
                bytes(&decode_fixed::<32>(SCOPE)?),
                bytes(&commit("castalia/kettle-policy-descriptor/v1", descriptor)?),
            ]),
        )?,
    };
    if tag == 2 {
        let terms = &payload[1];
        let t = ctor(terms, 0, 6)?;
        carrier = Some(str_ref(&t[0])?);
        let addr = ctor(&t[1], 0, 2)?;
        let key = ctor(&addr[0], 0, 1)?;
        ctor(&addr[1], 1, 0)?;
        ctor(&t[2], 0, 0)?;
        destination = Some(enter(&hex::encode(octets(&key[0], 28, 28)?), false));
        let input = octets(&t[4], 1, input_bound)?;
        ensure(
            input.first() == Some(&0x5a),
            "pinned companion eligibility input",
        )?;
        input_hex = Some(hex::encode(input));
        purpose_hex = Some(hex::encode(octets(&t[5], 1, 64)?));
        let rows = t[3].array()?;
        ensure(
            (1..=asset_bound).contains(&rows.len()),
            "current debit bound",
        )?;
        let mut prev = None;
        for row in rows {
            let f = ctor(row, 0, 3)?;
            let (k, _, _) = unit(f)?;
            ensure(prev.as_ref().is_none_or(|p| p < &k), "debit order")?;
            prev = Some(k.clone());
            payment.insert(k, bounded(&f[2], 1, MAX_Q)?);
        }
        let eligibility = commit(
            "castalia/kettle-policy-eligibility/v1",
            &fields(vec![
                bytes(&decode_fixed::<32>(SCOPE)?),
                data_ref(&c.head.outpoint)?,
                number(nat(&c.head.epoch, MAX_Q)?),
                bytes(&decode_fixed::<32>(&c.head.root)?),
                bytes(&commit("castalia/kettle-policy-descriptor/v1", descriptor)?),
                terms.clone(),
            ]),
        )?;
        next_use = commit(
            "castalia/kettle-policy-use-next/v1",
            &fields(vec![bytes(&next_use), bytes(&eligibility)]),
        )?;
        let invocation = commit(
            "castalia/kettle-policy-invoke/v1",
            &fields(vec![
                bytes(&eligibility),
                bytes(&next_use),
                bytes(&decode_fixed::<32>(next_root)?),
            ]),
        )?;
        invoke = Some(fields(vec![
            data_ref(&c.head.outpoint)?,
            bytes(&invocation),
        ]));
    }
    let mut unpaid = payment.clone();
    let mut after = Vec::new();
    let mut caps = Vec::new();
    let rows = raw_caps.array()?;
    ensure((1..=8).contains(&rows.len()), "cap count")?;
    let mut prev = None;
    for row in rows {
        let f = ctor(row, 0, 4)?;
        let (k, policy, name) = unit(f)?;
        ensure(prev.as_ref().is_none_or(|p| p < &k), "cap order")?;
        prev = Some(k.clone());
        let max = bounded(&f[2], 1, MAX_Q)?;
        let paid = bounded(&f[3], 0, max)?;
        ensure(tag != 0 || paid == 0, "Add initial paid counters")?;
        let next = paid + unpaid.remove(&k).unwrap_or(0);
        ensure(next <= max, "policy cap exceeded")?;
        after.push(fields(vec![
            f[0].clone(),
            f[1].clone(),
            number(max),
            number(next),
        ]));
        caps.push(json!({
            "policyId": policy, "assetName": name, "maximum": max.to_string(),
            "paidBefore": paid.to_string(), "paidAfter": next.to_string(),
        }));
    }
    ensure(unpaid.is_empty(), "unlisted payout currency")?;
    let record = fields(vec![
        descriptor.clone(),
        bool_node(tag != 1),
        list(after),
        bytes(&next_use),
    ]);
    ensure(
        map_root(&d[0], Some(&record), &evidence.proof)? == next_root,
        "next registry root",
    )?;
    let prior_commit = prior
        .map(|r| commit("castalia/kettle-policy-record/v1", r).map(hex::encode))
        .transpose()?;
    let next_commit = hex::encode(commit("castalia/kettle-policy-record/v1", &record)?);
    let effect = json!({
        "descriptorDataHex": hex::encode(data(descriptor)?),
        "contentDataHex": hex::encode(data(&content)?),
        "caps": caps,
        "enabledBefore": prior.map(|_|true),
        "enabledAfter": tag != 1,
        "priorUse": prior_use.map(hex::encode),
        "nextUse": hex::encode(next_use),
        "purposeHex": purpose_hex,
        "policyInputHex": input_hex,
    });
    Ok(PolicyChange {
        name,
        effect,
        prior_commit,
        next_commit,
        carrier,
        destination,
        payment,
        invoke,
    })
}

fn effect(o: &Output, raw: &str) -> FixtureResult<Json> {
    ensure(o.script_ref.is_none(), "unpinned output code")?;
    let datum = match &o.datum {
        Some(Datum::Inline { span }) => {
            Some(json!({"kind":"inline","dataHex":hex::encode(span.extract(raw)?)}))
        }
        None => None,
        _ => return Err(FixtureError("unqualified output datum hash")),
    };
    let mut assets = o.value.assets.clone();
    assets.sort_by(|a, b| (&a.policy_id, &a.asset_name).cmp(&(&b.policy_id, &b.asset_name)));
    Ok(json!({"address":o.address,"coin":o.value.coin,"assets":assets,"datum":datum}))
}
fn ordinary(o: &Output) -> FixtureResult<Amounts> {
    ensure(
        o.address == enter(KETTLE, true)
            && o.datum.is_none()
            && o.script_ref.is_none()
            && o.value.assets.iter().all(|a| a.policy_id != KETTLE),
        "ordinary funding origin",
    )?;
    let v = amounts(o)?;
    ensure(!v.is_empty(), "empty ordinary funding")?;
    Ok(v)
}
fn minimum(o: &Output) -> FixtureResult<i128> {
    let min = (160 + o.span.length as i128) * 4310;
    ensure(
        nat(&o.value.coin, MAX_Q)? >= min,
        "output below fixture minimum",
    )?;
    Ok(min)
}
fn script_data_integrity(tx: &Wire, raw: &str) -> FixtureResult<(String, String)> {
    let witnesses = tx.witness_set.extract(raw)?;
    ensure(
        witnesses.starts_with(&[0xa1, 0x05]),
        "unsigned exact key-5 witness map",
    )?;
    let original_redeemers = &witnesses[2..];
    let view = hex::decode(include_str!("cost_view.hex").trim()).expect("fixed language view hex");
    let script_hash = hex::encode(hash32(&[original_redeemers, &view].concat()));
    ensure(
        tx.script_data_hash.as_deref() == Some(&script_hash),
        "original script-data integrity",
    )?;
    Ok((script_hash, sha(original_redeemers)))
}

fn projected_fee(signed_size: usize, ref_bytes: usize, memory: i128, steps: i128) -> i128 {
    155381
        + 44 * (signed_size as i128 - 1)
        + 15 * ref_bytes as i128
        + (577000 * memory + 721 * steps + 9_999_999) / 10_000_000
}

pub(super) fn inspect(raw: &str, c: &ReviewContext) -> FixtureResult<Json> {
    ensure(
        c.schema == "castalia.kettle-current-approval-context.v1"
            && c.profile_id == PROFILE
            && lower_hex(&c.source_id, 32)
            && lower_hex(&c.point, 32)
            && (1..=MAX_SAFE).contains(&c.generation)
            && c.slot <= MAX_SAFE,
        "current source identity",
    )?;
    ensure(
        c.creators.len() <= 8
            && c.creators.iter().map(|x| x.original.len()).sum::<usize>() <= 131072
            && c.policy.record.as_ref().is_none_or(|r| r.len() <= 8192)
            && c.policy.content.as_ref().is_none_or(|r| r.len() <= 8192)
            && c.policy.proof.siblings.len() <= 256
            && c.evaluated.len() <= 4,
        "current context aggregate",
    )?;
    let (tx, tx_id) = parse_wire(raw)?;
    ensure(
        tx.body.offset == 1
            && tx.witness_set.offset == 1 + tx.body.length
            && tx.witness_set.offset + tx.witness_set.length + 2 == tx.envelope.length
            && raw.starts_with("84")
            && raw.ends_with("f5f6")
            && tx.tag == "normal-tag"
            && tx.envelope.sha256 == c.envelope_sha256
            && tx.network_id.is_none_or(|n| n == 0)
            && tx.mint.is_empty()
            && tx.vkeys.is_empty()
            && tx.native_scripts.is_empty()
            && tx.plutus_v3_scripts.is_empty(),
        "unsigned original current action",
    )?;
    let ttl = nat(
        tx.ttl
            .as_deref()
            .ok_or(FixtureError("bounded action needs TTL"))?,
        MAX_Q,
    )?;
    let start = nat(tx.validity_start.as_deref().unwrap_or("0"), MAX_Q)?;
    ensure(
        start <= i128::from(c.slot) && ttl > i128::from(c.slot) && ttl - i128::from(c.slot) <= 120,
        "current slot outside bounded action interval",
    )?;
    let (script_hash, redeemers_sha) = script_data_integrity(&tx, raw)?;
    let origins = Origins::new(c, &tx)?;
    ensure(
        tx.normal_inputs.contains(&c.head.outpoint)
            && tx.collateral_inputs.len() == 1
            && (2..=5).contains(&tx.normal_inputs.len()),
        "current normal singleton and role counts",
    )?;
    let (state_in, state_raw) = origins.at(&c.head.outpoint)?;
    let (controller, roster, epoch, root) = state(state_in, state_raw)?;
    ensure(
        root == c.head.root && epoch.to_string() == c.head.epoch,
        "consumed current head",
    )?;
    let state_out = tx
        .outputs
        .first()
        .ok_or(FixtureError("current successor absent"))?;
    let (next_c, next_r, next_e, next_root) = state(state_out, raw)?;
    ensure(
        next_c == controller && next_r == roster && next_e == epoch + 1,
        "same authority, next epoch",
    )?;
    let outer = spend(&tx, raw, &c.head.outpoint)?;
    let pol = policy_change(c, &outer, &next_root)?;
    let registered = pol.name == "registered";
    let mut payer = None;
    let mut funding = Vec::new();
    let mut available = Amounts::new();
    let mut carrier_seen = false;
    for r in &tx.normal_inputs {
        let (o, origin) = origins.at(r)?;
        if r == &c.head.outpoint {
            continue;
        }
        if Some(r) == pol.carrier.as_ref() {
            ensure(
                registered
                    && o.address == enter(COMPANION, true)
                    && o.script_ref.is_none()
                    && o.value.assets.is_empty(),
                "current carrier role",
            )?;
            let carrier_data = data_output(o, origin)?;
            let args = ctor(&carrier_data, 0, 2)?;
            let owner = enter(&hex::encode(octets(&args[0], 28, 28)?), false);
            octets(&args[1], 16, 16)?;
            let returned = tx
                .outputs
                .get(2)
                .ok_or(FixtureError("carrier full return"))?;
            ensure(
                plain(returned, &owner)? == nat(&o.value.coin, MAX_Q)?
                    && spend(&tx, raw, r)?
                        == *pol.invoke.as_ref().ok_or(FixtureError("missing Invoke"))?,
                "carrier return and Invoke",
            )?;
            carrier_seen = true;
        } else if o.address == enter(KETTLE, true) {
            ensure(registered && funding.len() < 2, "unexpected funding input")?;
            let v = ordinary(o)?;
            accumulate(&mut available, &v, 1);
            let follow = spend(&tx, raw, r)?;
            let link = ctor(&follow, 6, 1)?;
            ensure(
                str_ref(&link[0])? == c.head.outpoint,
                "funding follows exact consumed state",
            )?;
            funding.push(r.clone());
        } else {
            ensure(
                payer.is_none() && o.address.len() == 58 && o.address.starts_with("60"),
                "one ordinary fee payer",
            )?;
            payer = Some((r, o.address.as_str(), plain(o, &o.address)?));
        }
    }
    let (payer_ref, payer_address, payer_coin) = payer.ok_or(FixtureError("missing fee payer"))?;
    let payer_key = &payer_address[2..];
    ensure(
        payer_key != controller && !roster.iter().any(|k| k == payer_key),
        "distinct funding payer and current authorities",
    )?;
    ensure(
        carrier_seen == registered
            && (!registered || !funding.is_empty())
            && tx.redeemers.len() == 1 + funding.len() + usize::from(registered),
        "current exact spending purposes",
    )?;
    let residual = if registered {
        ensure(
            (4..=5).contains(&tx.outputs.len()),
            "registered output roles",
        )?;
        let payment = &tx.outputs[1];
        ensure(
            Some(&payment.address) == pol.destination.as_ref()
                && payment.datum.is_none()
                && payment.script_ref.is_none()
                && amounts(payment)? == pol.payment,
            "exact policy payout",
        )?;
        accumulate(&mut available, &pol.payment, -1);
        if tx.outputs.len() == 5 {
            ensure(
                ordinary(&tx.outputs[3])? == available,
                "full native principal balance",
            )?;
            Some(3)
        } else {
            ensure(available.is_empty(), "full native drain balance")?;
            None
        }
    } else {
        ensure(tx.outputs.len() == 2, "admin state and payer roles")?;
        None
    };
    let fee = nat(&tx.fee, MAX_Q)?;
    let payer_index = tx.outputs.len() - 1;
    ensure(
        plain(&tx.outputs[payer_index], payer_address)? + fee == payer_coin,
        "separate payer fee/change equation",
    )?;
    let collateral_ref = &tx.collateral_inputs[0];
    let (ci, _) = origins.at(collateral_ref)?;
    let cr = tx
        .collateral_return
        .as_ref()
        .ok_or(FixtureError("collateral return required"))?;
    let risk = plain(ci, payer_address)? - plain(cr, payer_address)?;
    ensure(
        Some(risk.to_string()).as_ref() == tx.total_collateral.as_ref() && risk * 100 >= fee * 150,
        "exact collateral risk",
    )?;
    ensure(
        tx.required_signers.iter().any(|s| s == payer_key),
        "payer must sign",
    )?;
    let mut signers = tx.required_signers.clone();
    signers.sort();
    match pol.name {
        "add" => ensure(
            signers.len() == 2 && signers.contains(&controller),
            "current controller+fee payer",
        )?,
        "registered" => ensure(
            signers.len() == 1,
            "only external payer for registered payout",
        )?,
        "disable" => ensure(
            signers.len() == 3 && signers.iter().filter(|k| roster.contains(k)).count() == 2,
            "two distinct current recovery signers+fee payer",
        )?,
        _ => return Err(FixtureError("unsupported role")),
    }
    let (mut k_ref, mut p_ref, mut ref_bytes) = (None, None, 0usize);
    ensure(
        tx.reference_inputs.len() == 1 + usize::from(registered),
        "exact code reference set",
    )?;
    for r in &tx.reference_inputs {
        let (o, parent) = origins.at(r)?;
        if code(o, parent, KETTLE).is_ok() {
            ensure(k_ref.is_none(), "duplicate K code")?;
            k_ref = Some(r);
            ref_bytes += 16116
        } else {
            ref_bytes += code(o, parent, COMPANION)?;
            ensure(registered && p_ref.is_none(), "unexpected P code")?;
            p_ref = Some(r);
        }
    }
    ensure(
        k_ref.is_some() && p_ref.is_some() == registered,
        "live expected executable pair",
    )?;
    ensure(
        tx.redeemers.len() == c.evaluated.len()
            && c.evaluated.windows(2).all(|w| w[0].index < w[1].index),
        "source evaluation coverage",
    )?;
    let (mut memory, mut steps) = (0i128, 0i128);
    for e in &c.evaluated {
        let r = tx
            .redeemers
            .iter()
            .find(|r| r.purpose == "spend" && r.index == e.index)
            .ok_or(FixtureError("missing exact evaluated purpose"))?;
        let m = nat(&r.memory, 17_500_000)?;
        let s = nat(&r.steps, 10_000_000_000)?;
        let used_m = nat(&e.memory, m)?;
        let used_s = nat(&e.steps, s)?;
        ensure(
            e.purpose == "spend" && used_m > 0 && used_s > 0,
            "unmeasured or underdeclared purpose",
        )?;
        memory += m;
        steps += s;
    }
    ensure(
        memory <= 17_500_000 && steps <= 10_000_000_000,
        "aggregate declared execution",
    )?;
    let signed_size = tx.envelope.length + 5 + 101 * signers.len();
    ensure(signed_size <= 16_384, "final witness/envelope size")?;
    let min_fee = projected_fee(signed_size, ref_bytes, memory, steps);
    ensure(fee >= min_fee, "reference-inclusive minimum fee")?;
    let mins = tx
        .outputs
        .iter()
        .map(|o| minimum(o).map(|q| q.to_string()))
        .collect::<FixtureResult<Vec<_>>>()?;
    let effects = tx
        .outputs
        .iter()
        .map(|o| effect(o, raw))
        .collect::<FixtureResult<Vec<_>>>()?;
    Ok(json!({
        "schema": "castalia.kettle-current-approval-review.v1",
        "contextDigest": sha(&canonical(c)?),
        "transactionBodyHash": tx_id,
        "transactionEnvelopeHash": tx.envelope.sha256,
        "action": pol.name,
        "policyId": c.policy.id,
        "priorRecordCommitment": pol.prior_commit,
        "nextRecordCommitment": pol.next_commit,
        "priorRoot": root,
        "nextRoot": next_root,
        "priorEpoch": epoch.to_string(),
        "nextEpoch": next_e.to_string(),
        "controllerKeyHash": controller,
        "recoveryKeyHashes": roster,
        "roles": {
            "state": c.head.outpoint,
            "payer": payer_ref,
            "collateral": collateral_ref,
            "kettleCode": k_ref,
            "companionCode": p_ref,
            "carrier": pol.carrier,
            "funding": funding,
        },
        "outputs": {
            "state": 0,
            "payer": payer_index,
            "carrier": registered.then_some(2),
            "residual": residual,
            "payment": registered.then_some(1),
        },
        "outputEffects": effects,
        "collateralReturnEffect": effect(cr,raw)?,
        "policy": pol.effect,
        "requiredSignerKeyHashes": signers,
        "scriptDataHash": script_hash,
        "redeemersSha256": redeemers_sha,
        "projectedSignedBytes": signed_size,
        "referenceScriptBytes": ref_bytes,
        "fee": tx.fee,
        "minFee": min_fee.to_string(),
        "collateralAtRisk": risk.to_string(),
        "minimumOutputCoins": mins,
        "collateralReturnMinimum": minimum(cr)?.to_string(),
    }))
}
