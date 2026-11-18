//! Bounded original-CBOR inspection for the one source-pinned K3 fixture.
//! This is not a VM, node verifier, min-UTxO calculator, or human approval UI.
use super::*;
const MAXIMUM: i128 = 9_223_372_036_854_775_807;
const STATE_NAME: &str = "50524f504f53414c5f5354415445";
fn require(ok: bool, message: &'static str) -> FixtureResult<()> {
    if ok {
        Ok(())
    } else {
        Err(FixtureError(message))
    }
}
fn hex_bytes(s: &str, max: usize) -> FixtureResult<Vec<u8>> {
    require(
        !s.is_empty() && s.len() <= max * 2 && lower_hex(s, s.len() / 2),
        "invalid bounded K3 hex",
    )?;
    hex::decode(s).map_err(|_| FixtureError("invalid K3 hex"))
}
fn hash_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().to_vec()
}
fn blake(raw: &[u8], len: usize) -> Vec<u8> {
    let mut h = Blake2bVar::new(len).expect("fixed digest");
    Update::update(&mut h, raw);
    let mut out = vec![0; len];
    h.finalize_variable(&mut out).expect("fixed digest");
    out
}
fn node(value: Value) -> Node {
    Node {
        start: 0,
        end: 0,
        value,
    }
}
fn bytes(v: &[u8]) -> Node {
    node(Value::Bytes(v.to_vec()))
}
fn number(v: i128) -> Node {
    node(Value::Int(v))
}
fn list(v: Vec<Node>) -> Node {
    node(Value::Array(v))
}
fn fields(v: Vec<Node>) -> Node {
    node(Value::Tag(121, Box::new(list(v))))
}
fn header(major: u8, n: u64, out: &mut Vec<u8>) {
    let base = major << 5;
    if n < 24 {
        out.push(base + n as u8)
    } else if n <= 255 {
        out.extend([base + 24, n as u8])
    } else if n <= 65535 {
        out.push(base + 25);
        out.extend((n as u16).to_be_bytes())
    } else if n <= u32::MAX.into() {
        out.push(base + 26);
        out.extend((n as u32).to_be_bytes())
    } else {
        out.push(base + 27);
        out.extend(n.to_be_bytes())
    }
}
fn serialize(n: &Node, out: &mut Vec<u8>) -> FixtureResult<()> {
    match &n.value {
        Value::Int(i) => {
            let magnitude = if *i < 0 { -1 - *i } else { *i };
            header(
                if *i < 0 { 1 } else { 0 },
                u64::try_from(magnitude).map_err(|_| FixtureError("K3 Data integer range"))?,
                out,
            )
        }
        Value::Bytes(b) => {
            if b.len() <= 64 {
                header(2, b.len() as u64, out);
                out.extend(b)
            } else {
                out.push(0x5f);
                for chunk in b.chunks(64) {
                    header(2, chunk.len() as u64, out);
                    out.extend(chunk)
                }
                out.push(0xff)
            }
        }
        Value::Array(a) => {
            if a.is_empty() {
                out.push(0x80)
            } else {
                out.push(0x9f);
                for c in a {
                    serialize(c, out)?
                }
                out.push(0xff)
            }
        }
        Value::Map(a) => {
            header(5, a.len() as u64, out);
            for (k, v) in a {
                serialize(k, out)?;
                serialize(v, out)?
            }
        }
        Value::Tag(t, v) if (121..=127).contains(t) || (1280..=1400).contains(t) => {
            header(6, *t, out);
            serialize(v, out)?
        }
        _ => return Err(FixtureError("unsupported K3 Data encoding")),
    }
    Ok(())
}
fn data(n: &Node) -> FixtureResult<Vec<u8>> {
    let mut b = vec![];
    serialize(n, &mut b)?;
    Ok(b)
}
fn commit(domain: &str, n: &Node) -> FixtureResult<Vec<u8>> {
    Ok(hash_parts(&[domain.as_bytes(), &[0], &data(n)?]))
}
fn qualified_content_node() -> Node {
    fields(vec![
        bytes(&[0xaa]),
        bytes(&[0xbb]),
        bytes(b"fixture input bytes"),
    ])
}
fn qualified_descriptor_node() -> Node {
    fields(vec![
        bytes(b"drink"),
        number(1),
        bytes(&hex::decode(COMPANION_HASH).unwrap()),
        bytes(&commit("castalia/kettle-policy-parameters/v1", &bytes(&[0xaa])).unwrap()),
        bytes(&commit("castalia/kettle-policy-constraints/v1", &bytes(&[0xbb])).unwrap()),
        bytes(
            &commit(
                "castalia/kettle-policy-schema/v1",
                &bytes(b"fixture input bytes"),
            )
            .unwrap(),
        ),
        number(1),
        number(1),
        number(4),
        number(2),
    ])
}
pub(super) fn qualified_content() -> Vec<u8> {
    data(&qualified_content_node()).unwrap()
}
pub(super) fn qualified_descriptor() -> Vec<u8> {
    data(&qualified_descriptor_node()).unwrap()
}
fn constr(n: &Node, index: u64, count: usize) -> FixtureResult<&[Node]> {
    let (t, f) = n.constructor()?;
    require(t == index && f.len() == count, "wrong K3 Data constructor")?;
    Ok(f)
}
fn sized(n: &Node, count: usize) -> FixtureResult<&[u8]> {
    let b = n.bytes()?;
    require(b.len() == count, "wrong K3 byte width")?;
    Ok(b)
}
fn integer(n: &Node, min: i128, max: i128) -> FixtureResult<i128> {
    let i = n.int()?;
    require(i >= min && i <= max, "K3 integer bound")?;
    Ok(i)
}
fn original(raw: &[u8], n: &Node) -> String {
    hex::encode(&raw[n.start..n.end])
}
fn ref_node(n: &Node, is_data: bool) -> FixtureResult<KettleRef> {
    let a = if is_data {
        constr(n, 0, 2)?
    } else {
        n.array()?
    };
    require(a.len() == 2, "invalid K3 reference")?;
    Ok(KettleRef {
        tx_hash: hex::encode(sized(&a[0], 32)?),
        output_index: u32::try_from(a[1].int()?).map_err(|_| FixtureError("K3 reference index"))?,
    })
}
fn ref_data(r: &KettleRef) -> Node {
    fields(vec![
        bytes(&hex::decode(&r.tx_hash).unwrap()),
        number(r.output_index.into()),
    ])
}
fn refs(body: &Node, key: i128, expected: usize) -> FixtureResult<Vec<KettleRef>> {
    let a = body.required(key)?.set()?;
    require(a.len() == expected, "K3 input count")?;
    let values = a
        .iter()
        .map(|n| ref_node(n, false))
        .collect::<FixtureResult<Vec<_>>>()?;
    require(
        values.windows(2).all(|w| w[0] < w[1]),
        "K3 input set must be exact and ordered",
    )?;
    Ok(values)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Amounts {
    coin: i128,
    assets: BTreeMap<String, i128>,
}
fn amounts(n: &Node) -> FixtureResult<Amounts> {
    let (coin, m) = match &n.value {
        Value::Int(_) => (integer(n, 0, MAXIMUM)?, None),
        Value::Array(a) if a.len() == 2 => (integer(&a[0], 0, MAXIMUM)?, Some(&a[1])),
        _ => return Err(FixtureError("invalid K3 Value")),
    };
    let mut assets = BTreeMap::new();
    if let Some(m) = m {
        for (p, names) in m.map()? {
            let policy = hex::encode(sized(p, 28)?);
            require(!names.map()?.is_empty(), "empty K3 policy map")?;
            for (name, q) in names.map()? {
                require(name.bytes()?.len() <= 32, "K3 asset name bound")?;
                let unit = format!("{}{}", policy, hex::encode(name.bytes()?));
                require(
                    assets.insert(unit, integer(q, 1, MAXIMUM)?).is_none(),
                    "duplicate K3 asset",
                )?;
            }
        }
    }
    require(assets.len() <= 7, "K3 Value entry bound")?;
    Ok(Amounts { coin, assets })
}
fn ada(coin: i128) -> Amounts {
    Amounts {
        coin,
        assets: BTreeMap::new(),
    }
}
fn quantity(v: &Amounts, unit: &str) -> i128 {
    if unit == "lovelace" {
        v.coin
    } else {
        *v.assets.get(unit).unwrap_or(&0)
    }
}
fn assets_json(v: &Amounts) -> JsonValue {
    let mut rows = vec![json!({"unit":"lovelace","quantity":v.coin.to_string()})];
    rows.extend(
        v.assets
            .iter()
            .map(|(u, q)| json!({"unit":u,"quantity":q.to_string()})),
    );
    json!(rows)
}
struct Output {
    address: Vec<u8>,
    value: Amounts,
    datum: Option<Vec<u8>>,
    script: Option<String>,
}
fn script_hash(n: &Node) -> FixtureResult<String> {
    let Value::Tag(24, wrapped) = &n.value else {
        return Err(FixtureError("K3 code reference requires tag24"));
    };
    let raw = wrapped.bytes()?;
    require(raw.len() <= 20000, "K3 reference code bound")?;
    let parsed = cbor::parse(raw)?;
    let a = parsed.array()?;
    require(
        a.len() == 2 && a[0].int()? == 3,
        "K3 requires actual V3 reference code",
    )?;
    let mut preimage = vec![3];
    preimage.extend(a[1].bytes()?);
    let hash = hex::encode(blake(&preimage, 28));
    let expected_size = match hash.as_str() {
        KETTLE_HASH => 15122,
        COMPANION_HASH => 6069,
        _ => return Err(FixtureError("K3 reference executable not source-admitted")),
    };
    require(
        a[1].bytes()?.len() == expected_size,
        "K3 pinned reference code length mismatch",
    )?;
    Ok(hash)
}
fn output(n: &Node, raw: &[u8]) -> FixtureResult<Output> {
    if let Value::Array(a) = &n.value {
        require(a.len() == 2, "K3 plain legacy output shape")?;
        let address = a[0].bytes()?.to_vec();
        require(
            address.len() == 29 && (address[0] == 0x60 || address[0] == 0x70),
            "K3 requires exact testnet enterprise address",
        )?;
        return Ok(Output {
            address,
            value: amounts(&a[1])?,
            datum: None,
            script: None,
        });
    }
    n.closed_map(&[0, 1, 2, 3])?;
    let address = n.required(0)?.bytes()?.to_vec();
    require(
        address.len() == 29 && (address[0] == 0x60 || address[0] == 0x70),
        "K3 requires exact testnet enterprise address",
    )?;
    let value = amounts(n.required(1)?)?;
    let datum = if let Some(d) = n.field(2)? {
        let a = d.array()?;
        require(a.len() == 2 && a[0].int()? == 1, "K3 inline datum only")?;
        let b = if let Value::Tag(24, v) = &a[1].value {
            v.bytes()?.to_vec()
        } else {
            raw[a[1].start..a[1].end].to_vec()
        };
        require(!b.is_empty() && b.len() <= 4096, "K3 datum bound")?;
        cbor::parse(&b)?;
        Some(b)
    } else {
        None
    };
    let script = n.field(3)?.map(script_hash).transpose()?;
    Ok(Output {
        address,
        value,
        datum,
        script,
    })
}
fn enterprise(hash: &str, script: bool) -> Vec<u8> {
    let mut b = vec![if script { 0x70 } else { 0x60 }];
    b.extend(hex::decode(hash).unwrap());
    b
}
fn plain(o: &Output, address: &[u8]) -> FixtureResult<()> {
    require(
        o.address == address
            && o.datum.is_none()
            && o.script.is_none()
            && o.value.assets.is_empty()
            && o.value.coin > 0,
        "K3 plain ADA role mismatch",
    )
}
fn output_json(o: &Output) -> JsonValue {
    json!({"addressHex":hex::encode(&o.address),"assets":assets_json(&o.value)})
}
struct Evidence {
    role: KettleInputRole,
    reference: KettleRef,
    output: Output,
}
pub(super) fn context_bounds(ctx: &KettleReviewContext) -> FixtureResult<()> {
    require(
        ctx.schema == "castalia.cardano-fixture-review-context.v3"
            && ctx.observed_slot <= MAX_JSON_INTEGER
            && ctx.utxos.len() == 6,
        "K3 context schema/count",
    )?;
    require(
        lower_hex(&ctx.accepted_add.tx_hash, 32)
            && ctx.accepted_add.output_index == 0
            && ctx.accepted_add.descriptor_data_hex.len() <= 8192
            && ctx.accepted_add.source_content_data_hex.len() <= 8192,
        "K3 Add observation bound",
    )?;
    let mut size = 0usize;
    for u in &ctx.utxos {
        require(
            lower_hex(&u.tx_hash, 32) && u.utxo_cbor_hex.len() <= 65536,
            "K3 UTxO bound",
        )?;
        size += u.utxo_cbor_hex.len();
    }
    require(size <= 65536, "K3 aggregate UTxO bound")
}
fn evidence(
    ctx: &KettleReviewContext,
    normal: &[KettleRef],
    reference: &[KettleRef],
    collateral: &[KettleRef],
) -> FixtureResult<Vec<Evidence>> {
    let expected = normal
        .iter()
        .map(|r| (KettleInputRole::Normal, r.clone()))
        .chain(
            reference
                .iter()
                .map(|r| (KettleInputRole::Reference, r.clone())),
        )
        .chain(
            collateral
                .iter()
                .map(|r| (KettleInputRole::Collateral, r.clone())),
        )
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for (u, (role, r)) in ctx.utxos.iter().zip(expected) {
        require(
            u.role == role
                && u.tx_hash == r.tx_hash
                && u.output_index == r.output_index
                && seen.insert(r.clone()),
            "K3 context exact role/reference mismatch",
        )?;
        let raw = hex_bytes(&u.utxo_cbor_hex, 32768)?;
        let pair = cbor::parse(&raw)?;
        let a = pair.array()?;
        require(
            a.len() == 2 && ref_node(&a[0], false)? == r,
            "K3 original UTxO reference mismatch",
        )?;
        out.push(Evidence {
            role,
            reference: r,
            output: output(&a[1], &raw)?,
        });
    }
    Ok(out)
}
fn by_address<'a>(
    e: &'a [Evidence],
    role: KettleInputRole,
    address: &[u8],
) -> FixtureResult<&'a Evidence> {
    let matches = e
        .iter()
        .filter(|e| e.role == role && e.output.address == address)
        .collect::<Vec<_>>();
    require(matches.len() == 1, "K3 role not unique")?;
    Ok(matches[0])
}
fn state(o: &Output) -> FixtureResult<(Node, Vec<u8>)> {
    require(
        o.address == enterprise(KETTLE_HASH, true) && o.script.is_none(),
        "K3 state address/code mismatch",
    )?;
    let marker = format!("{KETTLE_HASH}{STATE_NAME}");
    require(
        o.value.assets.get(&marker) == Some(&1)
            && o.value
                .assets
                .keys()
                .filter(|u| u.starts_with(KETTLE_HASH))
                .count()
                == 1,
        "K3 singleton namespace mismatch",
    )?;
    let raw = o
        .datum
        .clone()
        .ok_or(FixtureError("K3 state datum missing"))?;
    let parsed = cbor::parse(&raw)?;
    let f = constr(&parsed, 0, 5)?;
    require(f[0].int()? == 1, "K3 state version")?;
    let authority = constr(&f[1], 0, 2)?;
    sized(&authority[0], 28)?;
    let roster = authority[1].array()?;
    require((2..=16).contains(&roster.len()), "K3 roster bound")?;
    let mut seen = BTreeSet::new();
    for k in roster {
        require(seen.insert(sized(k, 28)?), "duplicate K3 recovery key")?;
    }
    integer(&f[2], 0, MAXIMUM)?;
    let reserve = integer(&f[3], 1, MAXIMUM)?;
    require(reserve <= o.value.coin, "K3 reserve uncovered")?;
    sized(&f[4], 32)?;
    Ok((parsed, raw))
}
fn map_root(scope: &[u8], key: &[u8], record: &Node, path: &Node) -> FixtureResult<Vec<u8>> {
    let p = constr(path, 0, 2)?;
    let bitmap = sized(&p[0], 32)?;
    let siblings = p[1].array()?;
    require(
        siblings.len() <= 256
            && bitmap
                .iter()
                .map(|b| b.count_ones() as usize)
                .sum::<usize>()
                == siblings.len(),
        "K3 registry proof shape",
    )?;
    let leaf = commit("castalia/kettle-policy-record/v1", record)?;
    let mut current = hash_parts(&[&[1], scope, key, &leaf]);
    let mut default = hash_parts(&[&[0], scope]);
    let mut offset = 0;
    for level in 0..256 {
        let other = if bitmap[level / 8] & (1 << (level % 8)) != 0 {
            let s = sized(&siblings[offset], 32)?.to_vec();
            offset += 1;
            s
        } else {
            default.clone()
        };
        current = if key[31 - level / 8] & (1 << (level % 8)) != 0 {
            hash_parts(&[&[2], scope, &other, &current])
        } else {
            hash_parts(&[&[2], scope, &current, &other])
        };
        default = hash_parts(&[&[2], scope, &default, &default]);
    }
    Ok(current)
}
fn unit(item: &[Node]) -> FixtureResult<String> {
    let p = item[0].bytes()?;
    let n = item[1].bytes()?;
    require(
        (p.is_empty() && n.is_empty()) || (p.len() == 28 && n.len() <= 32),
        "K3 unit encoding",
    )?;
    let u = if p.is_empty() {
        "lovelace".into()
    } else {
        format!("{}{}", hex::encode(p), hex::encode(n))
    };
    require(
        !u.starts_with(KETTLE_HASH),
        "K3 protocol namespace in principal/caps",
    )?;
    Ok(u)
}
fn unit_order(u: &str) -> String {
    if u == "lovelace" {
        String::new()
    } else {
        u.into()
    }
}

/// Inspect the original unsigned envelope; no reconstructed transaction is signed.
pub(super) fn registered(
    transaction_hex: &str,
    profile: &KettleFixtureProfile,
    ctx: &KettleReviewContext,
    payment: &str,
) -> FixtureResult<([u8; 32], String, JsonValue)> {
    profile.validate()?;
    context_bounds(ctx)?;
    require(lower_hex(payment, 28), "K3 payment credential width")?;
    require(
        ctx.accepted_add.descriptor_data_hex == profile.descriptor_data_hex
            && ctx.accepted_add.source_content_data_hex == profile.source_content_data_hex,
        "K3 accepted Add content mismatch",
    )?;
    let raw = hex_bytes(transaction_hex, 16384)?;
    let parsed = cbor::parse(&raw)?;
    let envelope = parsed.array()?;
    require(
        envelope.len() == 4
            && envelope[2].value == Value::Bool(true)
            && envelope[3].value == Value::Null,
        "K3 unsigned envelope shape",
    )?;
    let body = &envelope[0];
    body.closed_map(&[0, 1, 2, 3, 8, 11, 13, 14, 15, 16, 17, 18])?;
    let witness = &envelope[1];
    witness.closed_map(&[5])?;
    require(
        raw[witness.start] == 0xa1 && raw.len() + 106 <= 16384,
        "K3 projected single-witness envelope bound",
    )?;
    let now = i128::from(ctx.observed_slot);
    let ttl = integer(body.required(3)?, 0, MAX_JSON_INTEGER.into())?;
    require(
        ttl > now && ttl <= now + 120,
        "K3 stale or excessive validity interval",
    )?;
    if let Some(start) = body.field(8)? {
        require(
            integer(start, 0, MAX_JSON_INTEGER.into())? <= now,
            "K3 transaction not yet valid",
        )?;
    }
    if let Some(network) = body.field(15)? {
        require(network.int()? == 0, "K3 network mismatch")?;
    }
    let fee = integer(body.required(2)?, 1, MAXIMUM)?;
    let script_data_hash = hex::encode(sized(body.required(11)?, 32)?);
    let required = body.required(14)?.set()?;
    require(
        required.len() == 1 && hex::encode(sized(&required[0], 28)?) == payment,
        "K3 explicit payer signer required",
    )?;
    let normal = refs(body, 0, 3)?;
    let references = refs(body, 18, 2)?;
    let collateral = refs(body, 13, 1)?;
    let ev = evidence(ctx, &normal, &references, &collateral)?;
    let own = enterprise(payment, false);
    let state_input = by_address(&ev, KettleInputRole::Normal, &enterprise(KETTLE_HASH, true))?;
    let carrier = by_address(
        &ev,
        KettleInputRole::Normal,
        &enterprise(COMPANION_HASH, true),
    )?;
    let payer = by_address(&ev, KettleInputRole::Normal, &own)?;
    plain(&payer.output, &own)?;
    let collateral_input = by_address(&ev, KettleInputRole::Collateral, &own)?;
    plain(&collateral_input.output, &own)?;
    let code = |hash: &str| -> FixtureResult<&Evidence> {
        let found = ev
            .iter()
            .filter(|e| {
                e.role == KettleInputRole::Reference && e.output.script.as_deref() == Some(hash)
            })
            .collect::<Vec<_>>();
        require(found.len() == 1, "K3 missing role-tagged code reference")?;
        let e = found[0];
        require(
            e.output.address[0] == 0x60
                && e.output.datum.is_none()
                && e.output.value == ada(e.output.value.coin)
                && e.output.value.coin > 0,
            "K3 code reference role mismatch",
        )?;
        Ok(e)
    };
    let kettle_code = code(KETTLE_HASH)?;
    let companion_code = code(COMPANION_HASH)?;
    require(
        state_input.reference
            == KettleRef {
                tx_hash: ctx.accepted_add.tx_hash.clone(),
                output_index: ctx.accepted_add.output_index,
            },
        "K3 observed live Add head mismatch",
    )?;
    let os = body.required(1)?.array()?;
    require(os.len() == 4, "K3 four exact output roles required")?;
    let outs = os
        .iter()
        .map(|n| output(n, &raw))
        .collect::<FixtureResult<Vec<_>>>()?;
    let next = &outs[0];
    let payout = &outs[1];
    let back = &outs[2];
    let change = &outs[3];
    require(
        outs.iter().all(|o| o.script.is_none()),
        "K3 unexpected output executable",
    )?;
    let (old_state, old_state_raw) = state(&state_input.output)?;
    let (new_state, new_state_raw) = state(next)?;
    require(
        data(&old_state)? == old_state_raw && data(&new_state)? == new_state_raw,
        "K3 noncanonical state Data",
    )?;
    let old = constr(&old_state, 0, 5)?;
    let new = constr(&new_state, 0, 5)?;
    require(
        old[2].int()? == 1
            && new[2].int()? == 2
            && old[0] == new[0]
            && old[1] == new[1]
            && old[3] == new[3],
        "K3 current state authority/epoch/reserve mismatch",
    )?;
    let before_root = sized(&old[4], 32)?;
    let after_root = sized(&new[4], 32)?;
    let reserve = old[3].int()?;
    let authority = constr(&old[1], 0, 2)?;
    let redeemers = witness.required(5)?.array()?;
    require(
        redeemers.len() == 2,
        "K3 exactly two spending purposes required",
    )?;
    let mut selected = BTreeMap::new();
    let mut review_redeemers = BTreeMap::new();
    let mut memory = 0;
    let mut steps = 0;
    for r in redeemers {
        let a = r.array()?;
        require(a.len() == 4 && a[0].int()? == 0, "K3 non-spend purpose")?;
        let i = usize::try_from(a[1].int()?).map_err(|_| FixtureError("K3 spend index"))?;
        require(
            i < normal.len() && selected.insert(i, &a[2]).is_none(),
            "K3 duplicate or foreign spend index",
        )?;
        let ex = a[3].array()?;
        require(ex.len() == 2, "K3 execution budget shape")?;
        let m = integer(&ex[0], 1, 17_500_000)?;
        let s = integer(&ex[1], 1, 10_000_000_000)?;
        memory += m;
        steps += s;
        require(
            data(&a[2])? == raw[a[2].start..a[2].end],
            "K3 noncanonical redeemer Data",
        )?;
        review_redeemers.insert(i,json!({"index":i,"dataHex":original(&raw,&a[2]),"memory":m.to_string(),"steps":s.to_string()}));
    }
    require(
        memory <= 17_500_000 && steps <= 10_000_000_000,
        "K3 aggregate execution budget",
    )?;
    // Exact source-pinned V3 code totals 21,191 bytes, inside the first 25,600-byte
    // reference-fee band. One tagged singleton vkey adds 106 bytes to this closed
    // unsigned witness map (key0 + tag258 + array1 + [bytes32,bytes64]).
    let signed_size = (raw.len() + 106) as i128;
    let minimum_fee = 155381
        + 44 * signed_size
        + (577000 * memory + 721 * steps + 9_999_999) / 10_000_000
        + 15 * 21191;
    require(
        fee >= minimum_fee,
        "K3 fee omits execution, linear or actual reference-code cost",
    )?;
    let select = |r: &KettleRef| -> FixtureResult<&Node> {
        let i = normal
            .iter()
            .position(|x| x == r)
            .ok_or(FixtureError("K3 missing normal purpose"))?;
        selected.get(&i).copied().ok_or(FixtureError(
            "K3 purpose does not match actual normal input",
        ))
    };
    let outer = constr(select(&state_input.reference)?, 5, 1)?;
    let action = constr(&outer[0], 2, 3)?;
    let record = &action[0];
    let terms = &action[1];
    let proof = &action[2];
    let prior = constr(record, 0, 4)?;
    require(
        data(&prior[0])? == qualified_descriptor(),
        "K3 substituted descriptor",
    )?;
    constr(&prior[1], 1, 0)?;
    let path = constr(proof, 0, 2)?;
    require(
        sized(&path[0], 32)? == [0; 32] && path[1].array()?.is_empty(),
        "K3 only first Add from empty registry admitted",
    )?;
    let scope = commit(
        "castalia/kettle-registry-scope/v1",
        &list(vec![bytes(&[0xcf; 32]), bytes(&[0xce; 32]), bytes(&[0; 4])]),
    )?;
    let descriptor_digest = commit("castalia/kettle-policy-descriptor/v1", &prior[0])?;
    let initial_use = commit(
        "castalia/kettle-policy-use-initial/v1",
        &list(vec![bytes(&scope), bytes(&descriptor_digest)]),
    )?;
    require(
        sized(&prior[3], 32)? == initial_use,
        "K3 prior use is not initial accepted Add",
    )?;
    let key = commit("castalia/kettle-policy-key/v1", &bytes(b"drink"))?;
    require(
        map_root(&scope, &key, record, proof)? == before_root,
        "K3 authenticated prior leaf/root mismatch",
    )?;
    let t = constr(terms, 0, 6)?;
    require(
        ref_node(&t[0], true)? == carrier.reference,
        "K3 carrier reference mismatch",
    )?;
    let destination = constr(&t[1], 0, 2)?;
    let credential = constr(&destination[0], 0, 1)?;
    let receiver = hex::encode(sized(&credential[0], 28)?);
    constr(&destination[1], 1, 0)?;
    constr(&t[2], 0, 0)?;
    require(
        payout.address == enterprise(&receiver, false) && payout.datum.is_none(),
        "K3 exact payout address/datum mismatch",
    )?;
    let policy_input = t[4].bytes()?;
    require(
        (1..=4).contains(&policy_input.len()) && policy_input[0] == 0x5a,
        "K3 policy input outside admitted predicate",
    )?;
    let purpose_raw = t[5].bytes()?;
    require((1..=64).contains(&purpose_raw.len()), "K3 purpose bound")?;
    let purpose =
        std::str::from_utf8(purpose_raw).map_err(|_| FixtureError("K3 purpose is not UTF-8"))?;
    let rows = t[3].array()?;
    require((1..=2).contains(&rows.len()), "K3 debit row bound")?;
    let mut debit = BTreeMap::new();
    let mut last = None;
    let mut payout_expected = ada(0);
    for row in rows {
        let r = constr(row, 0, 3)?;
        let u = unit(r)?;
        let order = unit_order(&u);
        require(
            last.as_ref().is_none_or(|p| p < &order),
            "K3 debit ordering/duplicate",
        )?;
        last = Some(order);
        let q = integer(&r[2], 1, MAXIMUM)?;
        if u == "lovelace" {
            payout_expected.coin = q
        } else {
            payout_expected.assets.insert(u.clone(), q);
        }
        debit.insert(u, q);
    }
    require(
        payout.value == payout_expected,
        "K3 exact payout Value mismatch",
    )?;
    let caps = prior[2].array()?;
    require((1..=8).contains(&caps.len()), "K3 cap row bound")?;
    let mut new_caps = vec![];
    let mut cap_reviews = vec![];
    let mut cap_units = BTreeSet::new();
    last = None;
    for cap in caps {
        let c = constr(cap, 0, 4)?;
        let u = unit(c)?;
        let order = unit_order(&u);
        require(
            last.as_ref().is_none_or(|p| p < &order),
            "K3 cap ordering/duplicate",
        )?;
        last = Some(order);
        let maximum = integer(&c[2], 1, MAXIMUM)?;
        require(c[3].int()? == 0, "K3 expected paid-zero accepted Add")?;
        let paid = *debit.get(&u).unwrap_or(&0);
        require(paid <= maximum, "K3 policy cap exceeded")?;
        new_caps.push(fields(vec![
            c[0].clone(),
            c[1].clone(),
            number(maximum),
            number(paid),
        ]));
        cap_reviews.push(json!({"unit":u,"maximum":maximum.to_string(),"paidBefore":"0","debit":paid.to_string(),"paidAfter":paid.to_string()}));
        cap_units.insert(u);
    }
    require(
        debit.keys().all(|u| cap_units.contains(u)),
        "K3 debit not covered by caps",
    )?;
    let eligible = commit(
        "castalia/kettle-policy-eligibility/v1",
        &fields(vec![
            bytes(&scope),
            ref_data(&state_input.reference),
            number(1),
            bytes(before_root),
            bytes(&descriptor_digest),
            terms.clone(),
        ]),
    )?;
    let next_use = commit(
        "castalia/kettle-policy-use-next/v1",
        &fields(vec![bytes(&initial_use), bytes(&eligible)]),
    )?;
    let next_record = fields(vec![
        prior[0].clone(),
        prior[1].clone(),
        list(new_caps),
        bytes(&next_use),
    ]);
    require(
        map_root(&scope, &key, &next_record, proof)? == after_root,
        "K3 updated authenticated root mismatch",
    )?;
    let action_digest = commit(
        "castalia/kettle-policy-invoke/v1",
        &fields(vec![bytes(&eligible), bytes(&next_use), bytes(after_root)]),
    )?;
    require(
        select(&carrier.reference)?
            == &fields(vec![
                ref_data(&state_input.reference),
                bytes(&action_digest),
            ]),
        "K3 companion purpose not linked to state action",
    )?;
    let carrier_raw = carrier
        .output
        .datum
        .as_ref()
        .ok_or(FixtureError("K3 carrier datum missing"))?;
    let carrier_datum = cbor::parse(carrier_raw)?;
    let keeper = constr(&carrier_datum, 0, 2)?;
    let keeper_hash = hex::encode(sized(&keeper[0], 28)?);
    sized(&keeper[1], 16)?;
    require(
        carrier.output.script.is_none()
            && carrier.output.value == ada(carrier.output.value.coin)
            && carrier.output.value.coin > 0,
        "K3 carrier principal role mismatch",
    )?;
    plain(back, &enterprise(&keeper_hash, false))?;
    require(
        back.value == carrier.output.value,
        "K3 exact carrier reserve return",
    )?;
    let all_units = state_input
        .output
        .value
        .assets
        .keys()
        .chain(next.value.assets.keys())
        .chain(payout.value.assets.keys())
        .map(String::as_str)
        .chain(std::iter::once("lovelace"))
        .collect::<BTreeSet<_>>();
    for u in all_units {
        require(
            quantity(&state_input.output.value, u)
                == quantity(&next.value, u) + quantity(&payout.value, u),
            "K3 whole principal conservation mismatch",
        )?;
    }
    plain(change, &own)?;
    require(
        payer.output.value.coin == fee + change.value.coin,
        "K3 external payer conservation mismatch",
    )?;
    let collateral_return = output(body.required(16)?, &raw)?;
    plain(&collateral_return, &own)?;
    let at_risk = integer(body.required(17)?, 1, MAXIMUM)?;
    require(
        collateral_input.output.value.coin == collateral_return.value.coin + at_risk
            && at_risk >= (fee * 150 + 99) / 100,
        "K3 collateral liability mismatch",
    )?;
    let body_hash: [u8; 32] = blake(&raw[body.start..body.end], 32).try_into().unwrap();
    let mut review = json!({"schema":"castalia.cardano-fixture-review.v3","kind":"kettle-registered-pour","paymentKeyHash":payment,"transactionBodyHash":hex::encode(body_hash),"scriptDataHash":script_data_hash,
 "stateRef":state_input.reference,"carrierRef":carrier.reference,"payerRef":payer.reference,"collateralRef":collateral_input.reference,"kettleCodeRef":kettle_code.reference,"companionCodeRef":companion_code.reference});
    let details = json!({"policyId":hex::encode(b"drink"),"descriptorDataHex":profile.descriptor_data_hex,"sourceContentDataHex":profile.source_content_data_hex,"priorRecordDataHex":original(&raw,record),"termsDataHex":original(&raw,terms),"proofDataHex":original(&raw,proof),"stateDatumHex":hex::encode(old_state_raw),"nextStateDatumHex":hex::encode(new_state_raw),"beforeRoot":hex::encode(before_root),"afterRoot":hex::encode(after_root),"priorUse":hex::encode(initial_use),"nextUse":hex::encode(next_use),"actionDigest":hex::encode(action_digest)});
    let amounts = json!({"feeLovelace":fee.to_string(),"payerInputLovelace":payer.output.value.coin.to_string(),"payerChangeLovelace":change.value.coin.to_string(),"collateralInputLovelace":collateral_input.output.value.coin.to_string(),"collateralReturnLovelace":collateral_return.value.coin.to_string(),"collateralAtRiskLovelace":at_risk.to_string(),"reserveLovelace":reserve.to_string()});
    let roles = json!({"stateBefore":output_json(&state_input.output),"stateAfter":output_json(next),"payout":output_json(payout),"carrierReturn":output_json(back),"payerChange":output_json(change),"caps":cap_reviews,"redeemers":review_redeemers.into_values().collect::<Vec<_>>(),"purposeHex":hex::encode(purpose_raw),"purpose":purpose,"policyInputHex":hex::encode(policy_input),"epochBefore":"1","epochAfter":"2","controllerKeyHash":hex::encode(authority[0].bytes()?),"recoveryKeyHashes":authority[1].array()?.iter().map(|k|k.bytes().map(hex::encode)).collect::<FixtureResult<Vec<_>>>()?});
    for part in [details, amounts, roles] {
        review
            .as_object_mut()
            .unwrap()
            .extend(part.as_object().unwrap().clone());
    }
    Ok((body_hash, sha(&raw), review))
}
