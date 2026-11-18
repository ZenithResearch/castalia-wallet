//! Nine-action v2 dispatch and the six fixed/current-request effects. No witness creation here.
use super::*;
use crate::funding_fixture::current_approval as v1;
use crate::funding_fixture::current_approval_v2::{
    Evidence, PROFILE as V2_PROFILE, ReviewContext as Context,
};

fn state_view(controller: &str, roster: &[String], epoch: i128, root: &str) -> Json {
    json!({"controller":controller,"roster":roster,"epoch":epoch.to_string(),"root":root})
}

fn policy(raw: &str, c: &Context, evidence: v1::PolicyEvidence) -> FixtureResult<Json> {
    ensure(
        c.evaluated.iter().all(|entry| entry.purpose == "spend"),
        "policy expects Spend-only evaluation",
    )?;
    let context = v1::ReviewContext {
        schema: "castalia.kettle-current-approval-context.v1".into(),
        profile_id: v1::PROFILE.into(),
        source_id: c.source_id.clone(),
        point: c.point.clone(),
        generation: c.generation,
        slot: c.slot,
        head: c.head.clone(),
        envelope_sha256: c.envelope_sha256.clone(),
        creators: c.creators.clone(),
        policy: evidence,
        evaluated: c.evaluated.clone(),
    };
    let inner = v1::inspect_public(raw, &context)?;
    let mut prior = json!({"controller":inner["controllerKeyHash"],"roster":inner["recoveryKeyHashes"],"epoch":inner["priorEpoch"],"root":inner["priorRoot"]});
    let mut after = prior.clone();
    prior["outpoint"] = json!(c.head.outpoint);
    prior["role"] = json!("normal");
    after["outputIndex"] = json!(0);
    after["epoch"] = inner["nextEpoch"].clone();
    after["root"] = inner["nextRoot"].clone();
    let mut roles = inner["roles"].clone();
    roles["request"] = Json::Null;
    roles["seed"] = Json::Null;
    let mut outputs = inner["outputs"].clone();
    outputs["request"] = Json::Null;
    outputs["authorReturn"] = Json::Null;
    let mut result = json!({"schema":"castalia.kettle-current-approval-review.v2","contextDigest":sha(&canonical(c)?),
        "stateBefore":prior,"stateAfter":after,"roles":roles,"outputs":outputs});
    for key in [
        "action",
        "transactionBodyHash",
        "transactionEnvelopeHash",
        "outputEffects",
        "collateralReturnEffect",
        "requiredSignerKeyHashes",
        "scriptDataHash",
        "redeemersSha256",
        "projectedSignedBytes",
        "referenceScriptBytes",
        "fee",
        "minFee",
        "collateralAtRisk",
        "minimumOutputCoins",
        "collateralReturnMinimum",
    ] {
        result[key] = inner[key].clone();
    }
    result["effects"] = json!({"kind":"policy","review":inner});
    Ok(result)
}

#[derive(Clone)]
struct Terms {
    recipient: String,
    purpose: String,
    rows: Vec<Asset>,
    value: Amounts,
}
fn terms(fields: &[Node]) -> FixtureResult<Terms> {
    let address = ctor(&fields[0], 0, 2)?;
    let cred = ctor(&address[0], 0, 1)?;
    ctor(&address[1], 1, 0)?;
    ctor(&fields[1], 0, 0)?;
    let recipient = enter(&hex::encode(octets(&cred[0], 28, 28)?), false);
    let raw = octets(&fields[3], 1, 64)?;
    std::str::from_utf8(raw).map_err(|_| FixtureError("current request UTF-8 purpose"))?;
    let gross = fields[2].array()?;
    ensure((1..=2).contains(&gross.len()), "fixed payment row count")?;
    let mut rows = Vec::new();
    let mut value = Amounts::new();
    let mut last = None;
    for item in gross {
        let fs = ctor(item, 0, 3)?;
        let (key, policy_id, asset_name) = unit(fs)?;
        let q = bounded(&fs[2], 1, MAX_Q)?;
        ensure(
            last.as_ref().is_none_or(|v: &String| v < &key),
            "fixed payment asset order",
        )?;
        last = Some(key.clone());
        value.insert(key, q);
        rows.push(Asset {
            policy_id,
            asset_name,
            quantity: q.to_string(),
        });
    }
    Ok(Terms {
        recipient,
        purpose: hex::encode(raw),
        rows,
        value,
    })
}
struct Request {
    view: Json,
    terms: Terms,
    author: String,
    revision: i128,
    reserve: i128,
}
fn request_name(seed: &Outpoint) -> FixtureResult<String> {
    let mut bytes = b"castalia/teapot/request-id/v1\0".to_vec();
    bytes.extend(data(&data_ref(seed)?)?);
    Ok(hex::encode(hash32(&bytes)))
}
fn request(
    o: &Output,
    raw: &str,
    point: &Outpoint,
    seed: &Outpoint,
    id: &str,
) -> FixtureResult<Request> {
    let reserve = nat(&o.value.coin, MAX_Q)?;
    ensure(
        o.address == enter(KETTLE, true)
            && o.script_ref.is_none()
            && reserve > 0
            && request_name(seed)? == id
            && amounts(o)?
                == Amounts::from([(String::new(), reserve), (KETTLE.to_owned() + id, 1)]),
        "exact current request and reserve",
    )?;
    let n = data_output(o, raw)?;
    ensure(data(&n)?.len() <= 4096, "current canonical request size")?;
    let fields = ctor(&n, 1, 6)?;
    let author = hex::encode(octets(&fields[0], 28, 28)?);
    let revision = bounded(&fields[1], 0, MAX_Q)?;
    let terms = terms(&fields[2..])?;
    let view = json!({"id":id,"seed":seed,"outpoint":point,"revision":revision.to_string(),"author":author,"recipient":terms.recipient,
        "purpose":terms.purpose,"reserve":reserve.to_string(),"payment":terms.rows});
    Ok(Request {
        view,
        terms,
        author,
        revision,
        reserve,
    })
}
fn mint(tx: &Wire, raw: &str, id: &str, qty: i8) -> FixtureResult<Node> {
    ensure(
        tx.mint.len() == 1
            && tx.mint[0].policy_id == KETTLE
            && tx.mint[0].asset_name == id
            && tx.mint[0].quantity == qty.to_string(),
        "exact current request mint",
    )?;
    let row = tx
        .redeemers
        .iter()
        .find(|r| r.purpose == "mint" && r.target == KETTLE)
        .ok_or(FixtureError("current Kettle Mint purpose"))?;
    data_reader::read(&row.data.extract(raw)?)
}
#[derive(Default)]
struct Route {
    action: &'static str,
    effects: Json,
    requested: Option<Outpoint>,
    seed: Option<Outpoint>,
    author: Option<String>,
    deposit: i128,
    terms: Option<Terms>,
    refund: i128,
}
fn index(n: &Node, i: i128) -> FixtureResult<()> {
    ensure(n.int()? == i, "protected output index")
}
fn route(
    c: &Context,
    tx: &Wire,
    raw: &str,
    txid: &str,
    origins: &Origins,
    is_normal: bool,
    before: &Json,
    after: &Json,
) -> FixtureResult<Route> {
    let head = &c.head.outpoint;
    let next_output = Outpoint {
        tx_hash: txid.to_owned(),
        output_index: 0,
    };
    let mut plan = Route::default();
    match &c.evidence {
        Evidence::None {} => {
            ensure(is_normal && tx.mint.is_empty(), "fixed state Spend only")?;
            let action = spend(tx, raw, head)?;
            match action.constructor()? {
                (0, [t, s, p]) => {
                    index(s, 0)?;
                    index(p, 1)?;
                    let terms = terms(ctor(t, 0, 4)?)?;
                    plan.action = "direct";
                    plan.effects = json!({"kind":"direct","purpose":terms.purpose});
                    plan.terms = Some(terms);
                }
                (4, [change, s]) => {
                    index(s, 0)?;
                    match change.constructor()? {
                        (0, [key]) => {
                            ensure(
                                after["controller"] == hex::encode(octets(key, 28, 28)?)
                                    && before["roster"] == after["roster"],
                                "current controller replacement",
                            )?;
                            plan.action = "restore";
                        }
                        (1, [keys]) => {
                            let roster = keys
                                .array()?
                                .iter()
                                .map(|n| Ok(hex::encode(octets(n, 28, 28)?)))
                                .collect::<FixtureResult<Vec<_>>>()?;
                            ensure(
                                before["controller"] == after["controller"]
                                    && after["roster"] == json!(roster),
                                "current roster replacement",
                            )?;
                            plan.action = "replace";
                        }
                        _ => return Err(FixtureError("unsupported current authority change")),
                    }
                    plan.effects = json!({"kind":"authority"});
                }
                _ => return Err(FixtureError("fixed evidence disagrees with state purpose")),
            }
        }
        Evidence::RequestAbsence { id } => {
            ensure(!is_normal, "Create requires reference singleton")?;
            let issue = mint(tx, raw, id, 1)?;
            let f = ctor(&issue, 0, 3)?;
            let seed = str_ref(&f[0])?;
            index(&f[2], 0)?;
            let next = request(&tx.outputs[0], raw, &next_output, &seed, id)?;
            ensure(
                next.revision == 0 && next.author == hex::encode(octets(&f[1], 28, 28)?),
                "initial request author and revision",
            )?;
            plan.action = "create";
            plan.author = Some(next.author);
            plan.deposit = next.reserve;
            plan.seed = Some(seed);
            plan.effects = json!({"kind":"request","before":null,"after":next.view});
        }
        Evidence::CurrentRequest { id, seed, outpoint } => {
            ensure(
                tx.normal_inputs.contains(outpoint) && outpoint != head,
                "current request actual normal input",
            )?;
            let (o, parent) = origins.at(outpoint)?;
            let prior = request(o, parent, outpoint, seed, id)?;
            let follow = spend(tx, raw, outpoint)?;
            plan.requested = Some(outpoint.clone());
            plan.author = Some(prior.author.clone());
            if is_normal {
                let action = spend(tx, raw, head)?;
                let f = ctor(&action, 1, 4)?;
                ensure(
                    str_ref(&f[0])? == *outpoint && str_ref(&ctor(&follow, 3, 1)?[0])? == *head,
                    "linked current proposal pay",
                )?;
                index(&f[1], 0)?;
                index(&f[2], 1)?;
                index(&f[3], 2)?;
                let burn = mint(tx, raw, id, -1)?;
                let b = ctor(&burn, 1, 2)?;
                ensure(
                    str_ref(&b[0])? == *head && str_ref(&b[1])? == *outpoint,
                    "exact request retirement",
                )?;
                plan.action = "proposalPay";
                plan.refund = prior.reserve;
                plan.terms = Some(prior.terms);
                plan.effects = json!({"kind":"request","before":prior.view,"after":null});
            } else {
                index(&ctor(&follow, 2, 1)?[0], 0)?;
                ensure(tx.mint.is_empty(), "revision cannot mint")?;
                let next = request(&tx.outputs[0], raw, &next_output, seed, id)?;
                ensure(
                    next.author == prior.author
                        && next.revision == prior.revision + 1
                        && next.reserve == prior.reserve,
                    "current request author, revision and reserve",
                )?;
                plan.action = "revise";
                plan.effects = json!({"kind":"request","before":prior.view,"after":next.view});
            }
        }
        Evidence::Policy { .. } => return Err(FixtureError("wrong current action evidence")),
    }
    if is_normal && !matches!(plan.action, "restore" | "replace") {
        ensure(
            before["controller"] == after["controller"] && before["roster"] == after["roster"],
            "fixed payout changed authority",
        )?;
    }
    Ok(plan)
}

fn budget(tx: &Wire, evaluated: &[v1::Evaluation]) -> FixtureResult<(i128, i128)> {
    ensure(
        evaluated.len() == tx.redeemers.len(),
        "all original purposes evaluated",
    )?;
    let mut prev = None;
    let mut mem = 0;
    let mut steps = 0;
    for e in evaluated {
        let tag = match e.purpose.as_str() {
            "spend" => 0,
            "mint" => 1,
            _ => return Err(FixtureError("unsupported evaluated purpose")),
        };
        let key = (tag, e.index);
        ensure(
            prev.is_none_or(|p| p < key),
            "ordered distinct evaluated pointers",
        )?;
        prev = Some(key);
        let r = tx
            .redeemers
            .iter()
            .find(|r| r.index == e.index && r.purpose == e.purpose)
            .ok_or(FixtureError("current measured purpose missing"))?;
        let m = nat(&r.memory, 17_500_000)?;
        let s = nat(&r.steps, 10_000_000_000)?;
        ensure(
            nat(&e.memory, m)? > 0 && nat(&e.steps, s)? > 0,
            "unmeasured or underdeclared current purpose",
        )?;
        mem += m;
        steps += s;
    }
    ensure(
        mem <= 17_500_000 && steps <= 10_000_000_000,
        "aggregate declared execution",
    )?;
    Ok((mem, steps))
}

pub(in crate::funding_fixture) fn inspect(raw: &str, c: &Context) -> FixtureResult<Json> {
    ensure(
        c.schema == "castalia.kettle-current-approval-context.v2"
            && c.profile_id == V2_PROFILE
            && lower_hex(&c.source_id, 32)
            && lower_hex(&c.point, 32)
            && lower_hex(&c.head.root, 32)
            && (1..=MAX_SAFE).contains(&c.generation)
            && c.slot <= MAX_SAFE,
        "current v2 source identity",
    )?;
    ensure(
        (1..=8).contains(&c.creators.len())
            && c.creators.iter().map(|p| p.original.len()).sum::<usize>() <= 131072
            && (1..=5).contains(&c.evaluated.len()),
        "current v2 context bound",
    )?;
    if let Evidence::Policy {
        id,
        record,
        content,
        proof,
    } = &c.evidence
    {
        ensure(
            (2..=64).contains(&id.len())
                && record.as_ref().is_none_or(|r| r.len() <= 8192)
                && content.as_ref().is_none_or(|r| r.len() <= 8192)
                && proof.bitmap.len() == 64
                && proof.siblings.len() <= 256
                && proof.siblings.iter().all(|s| s.len() == 64),
            "bounded current policy evidence",
        )?;
        return policy(
            raw,
            c,
            v1::PolicyEvidence {
                id: id.clone(),
                record: record.clone(),
                content: content.clone(),
                proof: proof.clone(),
            },
        );
    }
    let (tx, txid) = parse_wire(raw)?;
    ensure(
        tx.body.offset == 1
            && tx.witness_set.offset == 1 + tx.body.length
            && tx.witness_set.offset + tx.witness_set.length + 2 == tx.envelope.length
            && raw.starts_with("84")
            && raw.ends_with("f5f6")
            && tx.tag == "normal-tag"
            && tx.envelope.sha256 == c.envelope_sha256
            && tx.network_id.is_none_or(|n| n == 0)
            && tx.vkeys.is_empty()
            && tx.native_scripts.is_empty()
            && tx.plutus_v3_scripts.is_empty()
            && (1..=5).contains(&tx.normal_inputs.len())
            && tx.collateral_inputs.len() == 1
            && (2..=5).contains(&tx.outputs.len()),
        "unsigned original current action",
    )?;
    let ttl = nat(
        tx.ttl
            .as_deref()
            .ok_or(FixtureError("current action TTL required"))?,
        MAX_Q,
    )?;
    let start = nat(tx.validity_start.as_deref().unwrap_or("0"), MAX_Q)?;
    let slot = i128::from(c.slot);
    ensure(
        start <= slot && slot < ttl && ttl - slot <= 120,
        "current source slot and validity",
    )?;
    let (script_hash, redeemers_sha) = script_data_integrity(&tx, raw)?;
    let origins = Origins::from_creators(&c.creators, &tx)?;
    let head = &c.head.outpoint;
    let is_normal = tx.normal_inputs.contains(head);
    ensure(
        is_normal != tx.reference_inputs.contains(head),
        "one actual singleton role",
    )?;
    let (s, parent) = origins.at(head)?;
    let (controller, roster, epoch, root) = state(s, parent)?;
    ensure(
        root == c.head.root && c.head.epoch == epoch.to_string(),
        "current observed singleton",
    )?;
    let mut before = state_view(&controller, &roster, epoch, &root);
    before["outpoint"] = json!(head);
    before["role"] = json!(if is_normal { "normal" } else { "reference" });
    let after = if is_normal {
        let (next_c, next_r, next_e, next_root) = state(&tx.outputs[0], raw)?;
        ensure(
            next_e == epoch + 1 && next_root == root,
            "fixed successor registry and epoch",
        )?;
        let mut next = state_view(&next_c, &next_r, next_e, &next_root);
        next["outputIndex"] = json!(0);
        next
    } else {
        Json::Null
    };
    let plan = route(c, &tx, raw, &txid, &origins, is_normal, &before, &after)?;
    let code_refs: Vec<_> = tx.reference_inputs.iter().filter(|r| *r != head).collect();
    ensure(code_refs.len() == 1, "one executable Kettle code reference")?;
    let k_ref = code_refs[0];
    let (k_output, k_parent) = origins.at(k_ref)?;
    let code_bytes = code(k_output, k_parent, KETTLE)?;

    let mut payer = None;
    let mut funding = Vec::new();
    let mut available = Amounts::new();
    for r in &tx.normal_inputs {
        if r == head || plan.requested.as_ref() == Some(r) {
            continue;
        }
        let (o, _) = origins.at(r)?;
        if o.address == enter(KETTLE, true) {
            ensure(
                plan.terms.is_some() && funding.len() < 2,
                "unexpected ordinary funding",
            )?;
            accumulate(&mut available, &ordinary(o)?, 1);
            funding.push(r);
            let follow = spend(&tx, raw, r)?;
            ensure(
                str_ref(&ctor(&follow, 6, 1)?[0])? == *head,
                "bound ordinary funding Spend",
            )?;
        } else {
            ensure(
                payer.is_none() && o.address.len() == 58 && o.address.starts_with("60"),
                "one enterprise fee payer",
            )?;
            payer = Some((r, &o.address, plain(o, &o.address)?));
        }
    }
    let (payer_ref, payer_address, payer_coin) = payer.ok_or(FixtureError("missing fee input"))?;
    if let Some(seed) = &plan.seed {
        ensure(seed == payer_ref, "request seed is the normal fee input")?;
    }
    let payer_key = &payer_address[2..];
    ensure(
        payer_key != controller && !roster.iter().any(|r| r == payer_key),
        "payer distinct from current authority",
    )?;
    let pay = plan.action == "proposalPay";
    let payer_i = tx.outputs.len() - 1;
    let mut residual = None;
    if let Some(terms) = &plan.terms {
        ensure(!funding.is_empty(), "payout with current ordinary funding")?;
        let payment = &tx.outputs[1];
        ensure(
            payment.address == terms.recipient
                && payment.datum.is_none()
                && payment.script_ref.is_none()
                && amounts(payment)? == terms.value,
            "complete approved payment",
        )?;
        let base = if pay { 4 } else { 3 };
        ensure(
            tx.outputs.len() == base || tx.outputs.len() == base + 1,
            "current payout protected output count",
        )?;
        let mut disbursed = terms.value.clone();
        if tx.outputs.len() == base + 1 {
            residual = Some(base - 1);
            accumulate(&mut disbursed, &ordinary(&tx.outputs[base - 1])?, 1);
        }
        ensure(available == disbursed, "full native principal balance")?;
        if pay {
            ensure(
                plain(
                    &tx.outputs[2],
                    &enter(
                        plan.author.as_ref().ok_or(FixtureError("missing author"))?,
                        false,
                    ),
                )? == plan.refund,
                "full distinct author reserve return",
            )?;
        }
    } else {
        ensure(tx.outputs.len() == 2, "exact admin/request output roles")?;
    }
    let expected_purposes = match plan.action {
        "proposalPay" => 3 + funding.len(),
        "direct" => 1 + funding.len(),
        _ => 1,
    };
    ensure(
        tx.redeemers.len() == expected_purposes,
        "exact named ledger purpose set",
    )?;
    let fee = nat(&tx.fee, MAX_Q)?;
    ensure(
        plain(&tx.outputs[payer_i], payer_address)? + fee + plan.deposit == payer_coin,
        "complete fee/reserve/change equation",
    )?;
    let coll_ref = &tx.collateral_inputs[0];
    let (ci, _) = origins.at(coll_ref)?;
    let cr = tx
        .collateral_return
        .as_ref()
        .ok_or(FixtureError("collateral return required"))?;
    let risk = plain(ci, payer_address)? - plain(cr, payer_address)?;
    ensure(
        tx.total_collateral.as_ref() == Some(&risk.to_string()) && risk * 100 >= fee * 150,
        "exact current collateral",
    )?;
    let mut signers = tx.required_signers.clone();
    signers.sort();
    ensure(signers.iter().any(|s| s == payer_key), "payer required")?;
    match plan.action {
        "direct" | "proposalPay" => ensure(
            signers.len() == 2 && signers.contains(&controller),
            "current controller required",
        )?,
        "restore" | "replace" => ensure(
            signers.len() == 3 && signers.iter().filter(|k| roster.contains(k)).count() == 2,
            "two selected current recovery credentials",
        )?,
        "create" | "revise" => ensure(
            signers.len() == 2
                && plan
                    .author
                    .as_ref()
                    .is_some_and(|a| a != payer_key && signers.contains(a)),
            "current request author and payer",
        )?,
        _ => return Err(FixtureError("unrecognized fixed action")),
    }
    let (memory, steps) = budget(&tx, &c.evaluated)?;
    let size = tx.envelope.length + 5 + 101 * signers.len();
    ensure(size <= 16384, "projected signed envelope size")?;
    let minimum_fee = projected_fee(size, code_bytes, memory, steps);
    ensure(fee >= minimum_fee, "reference-inclusive fee")?;
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
    let req_out = matches!(plan.action, "create" | "revise").then_some(0);
    Ok(
        json!({"schema":"castalia.kettle-current-approval-review.v2","contextDigest":sha(&canonical(c)?),"transactionBodyHash":txid,
        "transactionEnvelopeHash":tx.envelope.sha256,"action":plan.action,"stateBefore":before,"stateAfter":after,
        "roles":{"state":head,"payer":payer_ref,"collateral":coll_ref,"kettleCode":k_ref,"companionCode":null,"carrier":null,
          "request":plan.requested,"seed":plan.seed,"funding":funding},
        "outputs":{"state":is_normal.then_some(0),"payer":payer_i,"carrier":null,"residual":residual,
          "payment":plan.terms.is_some().then_some(1),"request":req_out,"authorReturn":pay.then_some(2)},
        "outputEffects":effects,"collateralReturnEffect":effect(cr,raw)?,"effects":plan.effects,"requiredSignerKeyHashes":signers,
        "scriptDataHash":script_hash,"redeemersSha256":redeemers_sha,"projectedSignedBytes":size,"referenceScriptBytes":code_bytes,
        "fee":fee.to_string(),"minFee":minimum_fee.to_string(),"collateralAtRisk":risk.to_string(),
        "minimumOutputCoins":mins,"collateralReturnMinimum":minimum(cr)?.to_string()}),
    )
}
