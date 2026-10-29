//! Closed v2 synthetic review. Owner receipts attest independently resolved
//! context, script integrity and compiled-validator preflight. Actual witnesses
//! and successful ledger submission remain separate; this parser binds review bytes.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureAllowedScript {
    pub hash: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_key_hash: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureReviewUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub utxo_cbor_hex: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureReviewContext {
    pub schema: String,
    pub utxos: Vec<FixtureReviewUtxo>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Ref {
    hash: String,
    index: u32,
}
impl Ref {
    fn node(n: &Node, data: bool) -> FixtureResult<Self> {
        let a = if data {
            let (c, a) = n.constructor()?;
            if c != 0 {
                return Err(FixtureError("invalid Data input reference"));
            }
            a
        } else {
            n.array()?
        };
        if a.len() != 2 || a[0].bytes()?.len() != 32 {
            return Err(FixtureError("invalid input reference"));
        }
        Ok(Self {
            hash: hex::encode(a[0].bytes()?),
            index: u32::try_from(a[1].int()?).map_err(|_| FixtureError("invalid input index"))?,
        })
    }
    fn json(&self) -> JsonValue {
        json!({"txHash":self.hash,"outputIndex":self.index})
    }
}
struct Evidence {
    reference: Ref,
    raw: Vec<u8>,
    output: Node,
    normal: bool,
    used: bool,
}
struct Request {
    name: String,
    author: String,
    revision: i128,
    datum: Vec<u8>,
    purpose: String,
}
fn bounded_hex(s: &str, max: usize) -> FixtureResult<Vec<u8>> {
    if s.is_empty() || s.len() > max * 2 || !lower_hex(s, s.len() / 2) {
        return Err(FixtureError("invalid bounded review hex"));
    }
    hex::decode(s).map_err(|_| FixtureError("invalid review hex"))
}
fn output_parts(output: &Node) -> FixtureResult<(&Node, &Node, Option<&Node>)> {
    match &output.value {
        Value::Map(_) => {
            output.closed_map(&[0, 1, 2])?;
            Ok((output.required(0)?, output.required(1)?, output.field(2)?))
        }
        Value::Array(a) if a.len() == 2 => Ok((&a[0], &a[1], None)),
        _ => Err(FixtureError("unsupported review output")),
    }
}
fn inline(output: &Node, raw: &[u8]) -> FixtureResult<Vec<u8>> {
    let (_, _, datum) = output_parts(output)?;
    let a = datum
        .ok_or(FixtureError("inline review datum required"))?
        .array()?;
    if a.len() != 2 || a[0].int()? != 1 {
        return Err(FixtureError("inline review datum required"));
    }
    let bytes = match &a[1].value {
        Value::Tag(24, n) => n.bytes()?.to_vec(),
        _ => raw[a[1].start..a[1].end].to_vec(),
    };
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err(FixtureError("review datum size limit"));
    }
    cbor::parse(&bytes)?;
    Ok(bytes)
}
fn coin_and_assets(output: &Node) -> FixtureResult<(i128, Vec<(Vec<u8>, Vec<u8>, i128)>)> {
    let (_, value, _) = output_parts(output)?;
    match &value.value {
        Value::Int(n) if *n >= 0 => Ok((*n, vec![])),
        Value::Array(a) if a.len() == 2 => {
            let coin = a[0].int()?;
            if coin < 0 {
                return Err(FixtureError("negative review output coin"));
            }
            let mut assets = vec![];
            for (policy, names) in a[1].map()? {
                if policy.bytes()?.len() != 28 {
                    return Err(FixtureError("invalid output asset policy"));
                }
                for (name, q) in names.map()? {
                    if name.bytes()?.len() > 32 || q.int()? <= 0 {
                        return Err(FixtureError("invalid output asset"));
                    }
                    assets.push((policy.bytes()?.to_vec(), name.bytes()?.to_vec(), q.int()?));
                }
            }
            Ok((coin, assets))
        }
        _ => Err(FixtureError("unsupported output value")),
    }
}
fn script_address(output: &Node, hash: &str) -> FixtureResult<()> {
    let a = output_parts(output)?.0.bytes()?;
    let mut expected = vec![0x70];
    expected.extend(hex::decode(hash).map_err(|_| FixtureError("invalid script hash"))?);
    if a != expected {
        return Err(FixtureError("review role at wrong enterprise script"));
    }
    Ok(())
}
fn token(output: &Node, hash: &str) -> FixtureResult<Vec<(Vec<u8>, i128)>> {
    let policy = hex::decode(hash).map_err(|_| FixtureError("invalid policy hash"))?;
    Ok(coin_and_assets(output)?
        .1
        .into_iter()
        .filter(|a| a.0 == policy)
        .map(|a| (a.1, a.2))
        .collect())
}
fn state(output: &Node, raw: &[u8], hash: &str, role: &str) -> FixtureResult<Vec<u8>> {
    script_address(output, hash)?;
    let name = if role == "teapot" {
        b"TEAPOT_STATE_V1".as_slice()
    } else {
        b"MARSH_STATE_V1".as_slice()
    };
    if token(output, hash)? != vec![(name.to_vec(), 1)] {
        return Err(FixtureError("authentic review state NFT required"));
    }
    let raw_datum = inline(output, raw)?;
    let d = cbor::parse(&raw_datum)?;
    let (c, f) = d.constructor()?;
    if c != 0 || f.len() != if role == "teapot" { 5 } else { 6 } || f[0].int()? != 1 {
        return Err(FixtureError("invalid review state schema"));
    }
    if role == "teapot" {
        if f[1].bytes()?.len() != 28 {
            return Err(FixtureError("invalid review controller"));
        }
        let roster = f[2].array()?;
        let mut seen = BTreeSet::new();
        if roster.len() < 2 || roster.len() > 16 {
            return Err(FixtureError("invalid review roster"));
        }
        for n in roster {
            let k = n.bytes()?;
            if k.len() != 28 || !seen.insert(k.to_vec()) {
                return Err(FixtureError("invalid review roster"));
            }
        }
    } else {
        if f[1].end - f[1].start > 256 || f[2].end - f[2].start > 2048 {
            return Err(FixtureError("invalid Marsh receiver size"));
        }
        let carries = f[3].array()?;
        if carries.len() < 4 || carries.len() > 16 {
            return Err(FixtureError("invalid Marsh carries"));
        }
        for n in carries {
            let (c, a) = n.constructor()?;
            if c != 0 || a.len() != 3 || !(0..1000).contains(&a[2].int()?) {
                return Err(FixtureError("invalid Marsh carry"));
            }
        }
    }
    let epoch = if role == "teapot" { 3 } else { 4 };
    let reserve = epoch + 1;
    if f[epoch].int()? < 0
        || f[reserve].int()? < 0
        || f[reserve].int()? > coin_and_assets(output)?.0
    {
        return Err(FixtureError("invalid state epoch/reserve"));
    }
    Ok(raw_datum)
}
fn purpose(n: &Node) -> FixtureResult<String> {
    let p = n.bytes()?;
    if p.is_empty() || p.len() > 512 {
        return Err(FixtureError("invalid funding purpose"));
    }
    Ok(std::str::from_utf8(p)
        .map_err(|_| FixtureError("invalid UTF-8 funding purpose"))?
        .to_owned())
}
fn request(output: &Node, raw: &[u8], hash: &str) -> FixtureResult<Request> {
    script_address(output, hash)?;
    let (coin, assets) = coin_and_assets(output)?;
    if coin <= 0
        || coin > i64::MAX.into()
        || assets.len() != 1
        || assets[0].0 != hex::decode(hash).map_err(|_| FixtureError("invalid request policy"))?
        || assets[0].1.len() != 32
        || assets[0].2 != 1
    {
        return Err(FixtureError("authentic request NFT/reserve required"));
    }
    let datum = inline(output, raw)?;
    let parsed = cbor::parse(&datum)?;
    let (c, f) = parsed.constructor()?;
    if c != 1 || f.len() != 6 || f[0].bytes()?.len() != 28 || f[1].int()? < 0 {
        return Err(FixtureError("invalid request datum"));
    }
    if f[2].end - f[2].start > 256 || f[3].end - f[3].start > 2048 {
        return Err(FixtureError("request destination bounds"));
    }
    let gross = f[4].array()?;
    let mut seen = BTreeSet::new();
    if gross.is_empty() || gross.len() > 16 {
        return Err(FixtureError("invalid request gross count"));
    }
    for n in gross {
        let (c, a) = n.constructor()?;
        if c != 0 || a.len() != 3 {
            return Err(FixtureError("invalid request asset"));
        }
        let p = a[0].bytes()?;
        let name = a[1].bytes()?;
        let q = a[2].int()?;
        if (p.is_empty() && !name.is_empty())
            || (!p.is_empty() && p.len() != 28)
            || name.len() > 32
            || hex::encode(p) == hash
            || q <= 0
            || q > i64::MAX.into()
            || !seen.insert((p.to_vec(), name.to_vec()))
        {
            return Err(FixtureError("invalid request gross asset"));
        }
    }
    Ok(Request {
        name: hex::encode(&assets[0].1),
        author: hex::encode(f[0].bytes()?),
        revision: f[1].int()?,
        purpose: purpose(&f[5])?,
        datum,
    })
}
fn request_json(r: &Request, input: Option<&Ref>, index: Option<usize>) -> JsonValue {
    json!({"assetName":r.name,"authorKeyHash":r.author,"revision":r.revision.to_string(),"datumHex":hex::encode(&r.datum),"inputReference":input.map(Ref::json),"outputIndex":index})
}
fn find_state(e: &mut [Evidence], hash: &str, role: &str, normal: bool) -> FixtureResult<Vec<u8>> {
    let mut found = None;
    for (i, v) in e.iter().enumerate() {
        if v.normal == normal && state(&v.output, &v.raw, hash, role).is_ok() {
            if found.is_some() {
                return Err(FixtureError("ambiguous state evidence"));
            }
            found = Some(i);
        }
    }
    let i = found.ok_or(FixtureError("required authentic state evidence missing"))?;
    if e[i].used {
        return Err(FixtureError("reused review state evidence"));
    }
    e[i].used = true;
    state(&e[i].output, &e[i].raw, hash, role)
}
fn body_state(outputs: &[Node], raw: &[u8], hash: &str, role: &str) -> FixtureResult<Vec<u8>> {
    let found = outputs
        .iter()
        .filter_map(|o| state(o, raw, hash, role).ok())
        .collect::<Vec<_>>();
    if found.len() != 1 {
        return Err(FixtureError("unique created state required"));
    }
    Ok(found[0].clone())
}
fn at_output<'a>(outputs: &'a [Node], n: &Node) -> FixtureResult<(usize, &'a Node)> {
    let i = usize::try_from(n.int()?).map_err(|_| FixtureError("invalid role output index"))?;
    Ok((
        i,
        outputs.get(i).ok_or(FixtureError("missing role output"))?,
    ))
}
fn exact_mint(body: &Node, hash: &str, name: &str, quantity: i128) -> FixtureResult<()> {
    let m = body.required(9)?.map()?;
    if m.len() != 1 || hex::encode(m[0].0.bytes()?) != hash {
        return Err(FixtureError("unexpected mint policy"));
    }
    let a = m[0].1.map()?;
    if a.len() != 1 || hex::encode(a[0].0.bytes()?) != name || a[0].1.int()? != quantity {
        return Err(FixtureError("unexpected protocol mint"));
    }
    Ok(())
}
fn payer(e: &mut [Evidence], payment: &str) -> FixtureResult<()> {
    let selected = hex::decode(payment).map_err(|_| FixtureError("invalid selected key"))?;
    let mut found = None;
    for (i, v) in e.iter().enumerate() {
        let a = output_parts(&v.output)?.0.bytes()?;
        if v.normal
            && a.len() >= 29
            && matches!(a[0] >> 4, 0 | 2 | 4 | 6)
            && a[0] & 15 == 0
            && a[1..29] == selected
        {
            if found.is_some() {
                return Err(FixtureError("ambiguous payer evidence"));
            }
            found = Some(i);
        }
    }
    let i = found.ok_or(FixtureError(
        "selected signer has no evidenced normal payer role",
    ))?;
    if e[i].used {
        return Err(FixtureError("reused payer evidence"));
    }
    e[i].used = true;
    Ok(())
}
fn selected_state_role(raw: &[u8], payment: &str, recovery: bool) -> FixtureResult<bool> {
    let d = cbor::parse(raw)?;
    let (_, f) = d.constructor()?;
    if recovery {
        Ok(f[2]
            .array()?
            .iter()
            .any(|n| n.bytes().is_ok_and(|b| hex::encode(b) == payment)))
    } else {
        Ok(hex::encode(f[1].bytes()?) == payment)
    }
}

pub(super) fn inspect(
    raw: &[u8],
    profile: &FixtureProfile,
    payment: &str,
    context: &FixtureReviewContext,
) -> FixtureResult<([u8; 32], FixtureReview)> {
    if context.schema != "castalia.cardano-fixture-review-context.v1" || context.utxos.len() > 3 {
        return Err(FixtureError("invalid review context schema/count"));
    }
    let parsed = cbor::parse(raw)?;
    let tx = parsed.array()?;
    if tx.len() != 4 || tx[2].value != Value::Bool(true) || tx[3].value != Value::Null {
        return Err(FixtureError("unsupported transaction envelope"));
    }
    let body = &tx[0];
    body.closed_map(&[0, 1, 2, 3, 8, 9, 11, 13, 14, 15, 16, 17, 18])?;
    if check_refs(body.required(0)?)? == 0 {
        return Err(FixtureError("no consumed inputs"));
    }
    let mut count = body.required(0)?.set()?.len();
    for k in [13, 18] {
        if let Some(n) = body.field(k)? {
            count += check_refs(n)?;
        }
    }
    if count > 64
        || body.required(2)?.int()? < 0
        || body.required(11)?.bytes()?.len() != 32
        || body.field(15)?.is_some_and(|n| n.int().ok() != Some(0))
    {
        return Err(FixtureError("invalid bounded testnet body"));
    }
    let outputs = body.required(1)?.array()?;
    if outputs.is_empty() || outputs.len() > 64 {
        return Err(FixtureError("invalid output count"));
    }
    for o in outputs {
        check_output(o)?;
    }
    if let Some(o) = body.field(16)? {
        check_output(o)?;
    }
    let signers = body.required(14)?.set()?;
    let mut seen = BTreeSet::new();
    if signers.is_empty() || signers.len() > 16 {
        return Err(FixtureError("invalid signer count"));
    }
    for n in signers {
        let b = n.bytes()?;
        if b.len() != 28 || !seen.insert(hex::encode(b)) {
            return Err(FixtureError("invalid required signer"));
        }
    }
    if !seen.contains(payment) {
        return Err(FixtureError("derived payment signer missing"));
    }
    let normal = body
        .required(0)?
        .set()?
        .iter()
        .map(|n| Ref::node(n, false))
        .collect::<FixtureResult<BTreeSet<_>>>()?;
    let refs = if let Some(r) = body.field(18)? {
        r.set()?
            .iter()
            .map(|n| Ref::node(n, false))
            .collect::<FixtureResult<BTreeSet<_>>>()?
    } else {
        BTreeSet::new()
    };
    if !normal.is_disjoint(&refs) {
        return Err(FixtureError("normal/reference overlap"));
    }
    let mut evidence = vec![];
    let mut total = 0usize;
    let mut last = None;
    for v in &context.utxos {
        if !lower_hex(&v.tx_hash, 32) {
            return Err(FixtureError("invalid evidence reference hash"));
        }
        let reference = Ref {
            hash: v.tx_hash.clone(),
            index: v.output_index,
        };
        if last.as_ref().is_some_and(|r| r >= &reference) {
            return Err(FixtureError("unsorted or duplicate review evidence"));
        }
        last = Some(reference.clone());
        let is_normal = normal.contains(&reference);
        if !is_normal && !refs.contains(&reference) {
            return Err(FixtureError(
                "evidence not in original normal/reference inputs",
            ));
        }
        let bytes = bounded_hex(&v.utxo_cbor_hex, 32768)?;
        total += bytes.len();
        if total > 32768 {
            return Err(FixtureError("review context byte limit"));
        }
        let node = cbor::parse(&bytes)?;
        let pair = node.array()?;
        if pair.len() != 2 || Ref::node(&pair[0], false)? != reference {
            return Err(FixtureError("resolved UTxO reference substitution"));
        }
        check_output(&pair[1])?;
        evidence.push(Evidence {
            reference,
            raw: bytes,
            output: pair[1].clone(),
            normal: is_normal,
            used: false,
        });
    }
    let witnesses = &tx[1];
    witnesses.closed_map(&[0, 4, 5, 7])?;
    if witnesses.field(4)?.is_some() {
        return Err(FixtureError("v2 uses qualified inline datums only"));
    }
    let scripts = witnesses.required(7)?.set()?;
    if scripts.len() != 1 {
        return Err(FixtureError("one admitted V3 script required"));
    }
    let mut h = Blake2bVar::new(28).expect("fixed digest");
    let mut out = [0u8; 28];
    Update::update(&mut h, &[3]);
    Update::update(&mut h, scripts[0].bytes()?);
    h.finalize_variable(&mut out).expect("fixed digest");
    let hash = hex::encode(out);
    let allowed = profile
        .allowed_scripts
        .iter()
        .find(|s| s.hash == hash)
        .ok_or(FixtureError("unadmitted typed script"))?;
    let role = allowed.role.as_str();
    let redeemers = witnesses.required(5)?.array()?;
    if redeemers.is_empty() || redeemers.len() > 32 {
        return Err(FixtureError("invalid redeemer count"));
    }
    let mut spends = vec![];
    let mut mints = vec![];
    let mut pointers = BTreeSet::new();
    let mut reviews = vec![];
    for r in redeemers {
        let a = r.array()?;
        if a.len() != 4 {
            return Err(FixtureError("invalid redeemer shape"));
        }
        let tag = a[0].int()?;
        let index = a[1].int()?;
        if !(0..=1).contains(&tag) || !(0..64).contains(&index) || !pointers.insert((tag, index)) {
            return Err(FixtureError("invalid redeemer pointer"));
        }
        let budget = a[3].array()?;
        if budget.len() != 2 || budget.iter().any(|n| n.int().map_or(true, |q| q < 0)) {
            return Err(FixtureError("invalid execution budget"));
        }
        if tag == 0 {
            spends.push(&a[2]);
        } else {
            mints.push(&a[2]);
        }
        reviews.push((tag,index,json!({"tag":if tag==0{"spend"}else{"mint"},"index":index,"dataHex":hex::encode(&raw[a[2].start..a[2].end])})));
    }
    reviews.sort_by_key(|r| (r.0, r.1));
    if spends.windows(2).any(|p| p[0] != p[1]) {
        return Err(FixtureError("differing spend actions"));
    }
    let action = spends
        .first()
        .or(mints.first())
        .ok_or(FixtureError("missing action"))?;
    let (c, f) = action.constructor()?;
    let mut req_json = JsonValue::Null;
    let mut p = None;
    let kind;
    let state_datum;
    let mut participation = None;
    if spends.is_empty() {
        if mints.len() != 1 {
            return Err(FixtureError("exactly one mint action required"));
        }
        if c == 0 && f.is_empty() {
            state_datum = body_state(outputs, raw, &hash, role)?;
            let name = if role == "teapot" {
                STATE_TOKEN
            } else {
                "4d415253485f53544154455f5631"
            };
            exact_mint(body, &hash, name, 1)?;
            if role == "teapot" {
                kind = "teapot-bootstrap";
                if selected_state_role(&state_datum, payment, false)? {
                    participation = Some("controller");
                }
            } else {
                kind = "marsh-bootstrap";
                let mut authenticated = None;
                for s in profile
                    .allowed_scripts
                    .iter()
                    .filter(|s| s.role == "teapot")
                {
                    if let Ok(d) = find_state(&mut evidence, &s.hash, "teapot", false) {
                        if authenticated.is_some() {
                            return Err(FixtureError("ambiguous Teapot bootstrap reference"));
                        }
                        authenticated = Some(d);
                    }
                }
                if authenticated.is_none() {
                    return Err(FixtureError("authentic Teapot reference evidence required"));
                }
            }
        } else if role == "teapot" && c == 1 && f.len() == 3 {
            kind = "teapot-request-create";
            state_datum = find_state(&mut evidence, &hash, role, false)?;
            let request_seed = Ref::node(&f[0], true)?;
            if !normal.contains(&request_seed) {
                return Err(FixtureError("request seed not consumed"));
            }
            let (index, output) = at_output(outputs, &f[2])?;
            let request = request(output, raw, &hash)?;
            if request.author != hex::encode(f[1].bytes()?) || request.revision != 0 {
                return Err(FixtureError("request author/revision mismatch"));
            }
            exact_mint(body, &hash, &request.name, 1)?;
            p = Some(request.purpose.clone());
            if request.author == payment {
                participation = Some("request-author");
            }
            req_json = request_json(&request, None, Some(index));
        } else {
            return Err(FixtureError("unsupported typed mint action"));
        }
    } else {
        if role == "teapot" && c == 3 && f.len() == 1 && mints.is_empty() {
            kind = "teapot-request-revise";
            state_datum = find_state(&mut evidence, &hash, role, false)?;
            let candidates = evidence
                .iter()
                .enumerate()
                .filter(|(_, e)| e.normal && request(&e.output, &e.raw, &hash).is_ok())
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                return Err(FixtureError("consumed request evidence required"));
            }
            let i = candidates[0];
            let prior = request(&evidence[i].output, &evidence[i].raw, &hash)?;
            evidence[i].used = true;
            let (index, output) = at_output(outputs, &f[0])?;
            let next = request(output, raw, &hash)?;
            if next.author != prior.author
                || next.name != prior.name
                || next.revision != prior.revision + 1
            {
                return Err(FixtureError("invalid request revision continuity"));
            }
            if next.author == payment {
                participation = Some("request-author");
            }
            p = Some(next.purpose.clone());
            req_json = request_json(&next, Some(&evidence[i].reference), Some(index));
            if body.field(9)?.is_some() {
                return Err(FixtureError("request revision cannot mint"));
            }
        } else {
            state_datum = find_state(&mut evidence, &hash, role, true)?;
            if role == "teapot" && c == 4 && f.len() == 6 && mints.len() == 1 {
                kind = "teapot-linked-payout";
                let reference = Ref::node(&f[0], true)?;
                let (mc, mf) = mints[0].constructor()?;
                if mc != 2 || mf.len() != 1 || Ref::node(&mf[0], true)? != reference {
                    return Err(FixtureError("linked retirement reference mismatch"));
                }
                let i = evidence
                    .iter()
                    .position(|e| e.normal && e.reference == reference)
                    .ok_or(FixtureError("linked request evidence missing"))?;
                let request = request(&evidence[i].output, &evidence[i].raw, &hash)?;
                if evidence[i].used {
                    return Err(FixtureError("reused linked evidence"));
                }
                evidence[i].used = true;
                exact_mint(body, &hash, &request.name, -1)?;
                p = Some(request.purpose.clone());
                req_json = request_json(&request, Some(&reference), None);
                if selected_state_role(&state_datum, payment, false)? {
                    participation = Some("controller");
                }
            } else if !mints.is_empty() || body.field(9)?.is_some() {
                return Err(FixtureError("unexpected mixed funding actions"));
            } else if role == "teapot" {
                match (c, f.len()) {
                    (0, 2) => {
                        kind = "teapot-restore-controller";
                        if selected_state_role(&state_datum, payment, true)? {
                            participation = Some("recovery");
                        }
                    }
                    (1, 2) => {
                        kind = "teapot-replace-recovery";
                        if selected_state_role(&state_datum, payment, true)? {
                            participation = Some("recovery");
                        }
                    }
                    (2, 8) => {
                        kind = "teapot-direct-payout";
                        p = Some(purpose(&f[3])?);
                        if selected_state_role(&state_datum, payment, false)? {
                            participation = Some("controller");
                        }
                    }
                    _ => return Err(FixtureError("unsupported Teapot spend action")),
                }
            } else {
                match (c, f.len()) {
                    (0, 3) => kind = "marsh-reset-receiver",
                    (1, 7) => {
                        kind = "marsh-release";
                        p = Some(purpose(&f[1])?);
                    }
                    _ => return Err(FixtureError("unsupported Marsh spend action")),
                }
            }
        }
    }
    if role == "marsh" && allowed.creator_key_hash.as_deref() == Some(payment) {
        participation = Some("controller");
    }
    if participation.is_none() {
        payer(&mut evidence, payment)?;
        participation = Some("input-payer");
    }
    if evidence.iter().any(|e| !e.used) {
        return Err(FixtureError("unrelated review evidence"));
    }
    let mut extension = BTreeMap::new();
    extension.insert("schema".into(), json!("castalia.cardano-fixture-review.v2"));
    extension.insert("fundRole".into(), json!(role));
    extension.insert(
        "redeemers".into(),
        json!(reviews.into_iter().map(|r| r.2).collect::<Vec<_>>()),
    );
    extension.insert("request".into(), req_json);
    extension.insert("stateDatumHex".into(), json!(hex::encode(state_datum)));
    extension.insert(
        "participation".into(),
        json!({"paymentKeyHash":payment,"role":participation}),
    );
    Ok((
        hash32(&raw[body.start..body.end]),
        FixtureReview {
            kind: kind.into(),
            fund_script_hash: hash,
            state_asset_name: if role == "teapot" {
                STATE_TOKEN.into()
            } else {
                "4d415253485f53544154455f5631".into()
            },
            redeemer_data_hex: String::new(),
            purpose: p,
            extension,
        },
    ))
}
