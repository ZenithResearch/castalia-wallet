//! Bounded original-CBOR inspection for the one source-pinned K3 admin-v4 fixture.
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
        "invalid bounded K3 admin-v4 hex",
    )?;
    hex::decode(s).map_err(|_| FixtureError("invalid K3 admin-v4 hex"))
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
                u64::try_from(magnitude)
                    .map_err(|_| FixtureError("K3 admin-v4 Data integer range"))?,
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
        _ => return Err(FixtureError("unsupported K3 admin-v4 Data encoding")),
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
    require(
        t == index && f.len() == count,
        "wrong K3 admin-v4 Data constructor",
    )?;
    Ok(f)
}
fn sized(n: &Node, count: usize) -> FixtureResult<&[u8]> {
    let b = n.bytes()?;
    require(b.len() == count, "wrong K3 admin-v4 byte width")?;
    Ok(b)
}
fn integer(n: &Node, min: i128, max: i128) -> FixtureResult<i128> {
    let i = n.int()?;
    require(i >= min && i <= max, "K3 admin-v4 integer bound")?;
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
    require(a.len() == 2, "invalid K3 admin-v4 reference")?;
    Ok(KettleRef {
        tx_hash: hex::encode(sized(&a[0], 32)?),
        output_index: u32::try_from(a[1].int()?)
            .map_err(|_| FixtureError("K3 admin-v4 reference index"))?,
    })
}

fn refs(body: &Node, key: i128, expected: usize) -> FixtureResult<Vec<KettleRef>> {
    let a = body.required(key)?.set()?;
    require(a.len() == expected, "K3 admin-v4 input count")?;
    let values = a
        .iter()
        .map(|n| ref_node(n, false))
        .collect::<FixtureResult<Vec<_>>>()?;
    require(
        values.windows(2).all(|w| w[0] < w[1]),
        "K3 admin-v4 input set must be exact and ordered",
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
        _ => return Err(FixtureError("invalid K3 admin-v4 Value")),
    };
    let mut assets = BTreeMap::new();
    if let Some(m) = m {
        for (p, names) in m.map()? {
            let policy = hex::encode(sized(p, 28)?);
            require(!names.map()?.is_empty(), "empty K3 admin-v4 policy map")?;
            for (name, q) in names.map()? {
                require(name.bytes()?.len() <= 32, "K3 admin-v4 asset name bound")?;
                let unit = format!("{}{}", policy, hex::encode(name.bytes()?));
                require(
                    assets.insert(unit, integer(q, 1, MAXIMUM)?).is_none(),
                    "duplicate K3 admin-v4 asset",
                )?;
            }
        }
    }
    require(assets.len() <= 7, "K3 admin-v4 Value entry bound")?;
    Ok(Amounts { coin, assets })
}
fn ada(coin: i128) -> Amounts {
    Amounts {
        coin,
        assets: BTreeMap::new(),
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
        return Err(FixtureError("K3 admin-v4 code reference requires tag24"));
    };
    let raw = wrapped.bytes()?;
    require(raw.len() <= 20000, "K3 admin-v4 reference code bound")?;
    let parsed = cbor::parse(raw)?;
    let a = parsed.array()?;
    require(
        a.len() == 2 && a[0].int()? == 3,
        "K3 admin-v4 requires actual V3 reference code",
    )?;
    let mut preimage = vec![3];
    preimage.extend(a[1].bytes()?);
    let hash = hex::encode(blake(&preimage, 28));
    let expected_size = match hash.as_str() {
        KETTLE_HASH => 15122,
        COMPANION_HASH => 6069,
        _ => {
            return Err(FixtureError(
                "K3 admin-v4 reference executable not source-admitted",
            ));
        }
    };
    require(
        a[1].bytes()?.len() == expected_size,
        "K3 admin-v4 pinned reference code length mismatch",
    )?;
    Ok(hash)
}
fn output(n: &Node, raw: &[u8]) -> FixtureResult<Output> {
    if let Value::Array(a) = &n.value {
        require(a.len() == 2, "K3 admin-v4 plain legacy output shape")?;
        let address = a[0].bytes()?.to_vec();
        require(
            address.len() == 29 && (address[0] == 0x60 || address[0] == 0x70),
            "K3 admin-v4 requires exact testnet enterprise address",
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
        "K3 admin-v4 requires exact testnet enterprise address",
    )?;
    let value = amounts(n.required(1)?)?;
    let datum = if let Some(d) = n.field(2)? {
        let a = d.array()?;
        require(
            a.len() == 2 && a[0].int()? == 1,
            "K3 admin-v4 inline datum only",
        )?;
        let b = if let Value::Tag(24, v) = &a[1].value {
            v.bytes()?.to_vec()
        } else {
            raw[a[1].start..a[1].end].to_vec()
        };
        require(!b.is_empty() && b.len() <= 4096, "K3 admin-v4 datum bound")?;
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
        "K3 admin-v4 plain ADA role mismatch",
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
pub(super) fn context_bounds(ctx: &AdminReviewContext) -> FixtureResult<()> {
    require(
        ctx.schema == "castalia.cardano-fixture-review-context.v4"
            && ctx.observed_slot <= MAX_JSON_INTEGER
            && ctx.utxos.len() == 4,
        "admin context schema/count",
    )?;
    let valid_ref = |r: &KettleRef| lower_hex(&r.tx_hash, 32) && r.output_index == 0;
    match &ctx.history {
        AdminHistory::FixtureGenesis { state_ref } => require(
            valid_ref(state_ref) && state_ref.tx_hash == "11".repeat(32),
            "admin genesis anchor",
        )?,
        AdminHistory::AcceptedRegisteredPour {
            accepted_add_ref,
            accepted_pour_ref,
            descriptor_data_hex,
            source_content_data_hex,
            prior_record_data_hex,
        } => require(
            valid_ref(accepted_add_ref)
                && valid_ref(accepted_pour_ref)
                && accepted_add_ref != accepted_pour_ref
                && descriptor_data_hex.len() <= 8192
                && source_content_data_hex.len() <= 8192
                && prior_record_data_hex.len() <= 8192,
            "admin accepted history bounds",
        )?,
    }
    let mut total = 0usize;
    for u in &ctx.utxos {
        require(
            lower_hex(&u.tx_hash, 32) && u.utxo_cbor_hex.len() <= 65536,
            "admin original UTxO bounds",
        )?;
        total += u.utxo_cbor_hex.len();
    }
    require(total <= 65536, "admin aggregate context bytes")
}

fn evidence(
    ctx: &AdminReviewContext,
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
            "K3 admin-v4 context exact role/reference mismatch",
        )?;
        let raw = hex_bytes(&u.utxo_cbor_hex, 32768)?;
        let pair = cbor::parse(&raw)?;
        let a = pair.array()?;
        require(
            a.len() == 2 && ref_node(&a[0], false)? == r,
            "K3 admin-v4 original UTxO reference mismatch",
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
    require(matches.len() == 1, "K3 admin-v4 role not unique")?;
    Ok(matches[0])
}
fn state(o: &Output) -> FixtureResult<(Node, Vec<u8>)> {
    require(
        o.address == enterprise(KETTLE_HASH, true) && o.script.is_none(),
        "K3 admin-v4 state address/code mismatch",
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
        "K3 admin-v4 singleton namespace mismatch",
    )?;
    let raw = o
        .datum
        .clone()
        .ok_or(FixtureError("K3 admin-v4 state datum missing"))?;
    let parsed = cbor::parse(&raw)?;
    let f = constr(&parsed, 0, 5)?;
    require(f[0].int()? == 1, "K3 admin-v4 state version")?;
    let authority = constr(&f[1], 0, 2)?;
    sized(&authority[0], 28)?;
    let roster = authority[1].array()?;
    require((2..=16).contains(&roster.len()), "K3 admin-v4 roster bound")?;
    let mut seen = BTreeSet::new();
    for k in roster {
        require(
            seen.insert(sized(k, 28)?),
            "duplicate K3 admin-v4 recovery key",
        )?;
    }
    integer(&f[2], 0, MAXIMUM)?;
    let reserve = integer(&f[3], 1, MAXIMUM)?;
    require(reserve <= o.value.coin, "K3 admin-v4 reserve uncovered")?;
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
        "K3 admin-v4 registry proof shape",
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
        "K3 admin-v4 unit encoding",
    )?;
    let u = if p.is_empty() {
        "lovelace".into()
    } else {
        format!("{}{}", hex::encode(p), hex::encode(n))
    };
    require(
        !u.starts_with(KETTLE_HASH),
        "K3 admin-v4 protocol namespace in principal/caps",
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

fn empty_root(scope: &[u8]) -> Vec<u8> {
    let mut root = hash_parts(&[&[0], scope]);
    for _ in 0..256 {
        root = hash_parts(&[&[2], scope, &root, &root]);
    }
    root
}

pub(super) fn admin(
    transaction_hex: &str,
    profile: &AdminFixtureProfile,
    ctx: &AdminReviewContext,
    payment: &str,
    role: AdminRole,
) -> FixtureResult<([u8; 32], String, JsonValue)> {
    profile.validate()?;
    context_bounds(ctx)?;
    require(lower_hex(payment, 28), "admin native key width")?;
    let raw = hex_bytes(transaction_hex, 16384)?;
    let parsed = cbor::parse(&raw)?;
    let envelope = parsed.array()?;
    require(
        envelope.len() == 4
            && envelope[2].value == Value::Bool(true)
            && envelope[3].value == Value::Null,
        "admin unsigned envelope",
    )?;
    let body = &envelope[0];
    body.closed_map(&[0, 1, 2, 3, 8, 11, 13, 14, 15, 16, 17, 18])?;
    let witness = &envelope[1];
    witness.closed_map(&[5])?;
    require(raw[witness.start] == 0xa1, "admin unsigned witness map")?;
    let now = i128::from(ctx.observed_slot);
    let ttl = integer(body.required(3)?, 0, MAX_JSON_INTEGER.into())?;
    require(
        ttl > now && ttl <= now + 120,
        "admin stale/excessive validity",
    )?;
    if let Some(start) = body.field(8)? {
        require(
            integer(start, 0, MAX_JSON_INTEGER.into())? <= now,
            "admin not-yet-valid body",
        )?;
    }
    if let Some(network) = body.field(15)? {
        require(network.int()? == 0, "admin wrong network")?;
    }
    let fee = integer(body.required(2)?, 1, MAXIMUM)?;
    let script_data_hash = hex::encode(sized(body.required(11)?, 32)?);
    let normal = refs(body, 0, 2)?;
    let references = refs(body, 18, 1)?;
    let collateral = refs(body, 13, 1)?;
    let ev = evidence(ctx, &normal, &references, &collateral)?;
    let state_input = by_address(&ev, KettleInputRole::Normal, &enterprise(KETTLE_HASH, true))?;
    let payer = ev
        .iter()
        .find(|e| e.role == KettleInputRole::Normal && e.reference != state_input.reference)
        .ok_or(FixtureError("admin payer missing"))?;
    require(
        payer.output.address[0] == 0x60,
        "admin payer must be enterprise key",
    )?;
    let payer_hash = hex::encode(&payer.output.address[1..]);
    let payer_address = enterprise(&payer_hash, false);
    plain(&payer.output, &payer_address)?;
    let collateral_input = by_address(&ev, KettleInputRole::Collateral, &payer_address)?;
    plain(&collateral_input.output, &payer_address)?;
    let code = ev
        .iter()
        .find(|e| e.role == KettleInputRole::Reference)
        .ok_or(FixtureError("admin code ref missing"))?;
    require(
        code.output.script.as_deref() == Some(KETTLE_HASH)
            && code.output.address[0] == 0x60
            && code.output.datum.is_none()
            && code.output.value == ada(code.output.value.coin)
            && code.output.value.coin > 0,
        "admin sole Kettle reference role",
    )?;
    let os = body.required(1)?.array()?;
    require(os.len() == 2, "admin exact state/change outputs")?;
    let next = output(&os[0], &raw)?;
    let change = output(&os[1], &raw)?;
    plain(&change, &payer_address)?;
    let (old_state, old_raw) = state(&state_input.output)?;
    let (new_state, new_raw) = state(&next)?;
    require(
        data(&old_state)? == old_raw && data(&new_state)? == new_raw,
        "admin canonical state Data",
    )?;
    let old = constr(&old_state, 0, 5)?;
    let new = constr(&new_state, 0, 5)?;
    let epoch = old[2].int()?;
    require(
        new[2].int()? == epoch + 1
            && old[0] == new[0]
            && old[1] == new[1]
            && old[3] == new[3]
            && state_input.output.value == next.value,
        "admin complete state/Value preservation",
    )?;
    let authority = constr(&old[1], 0, 2)?;
    let controller = hex::encode(sized(&authority[0], 28)?);
    let roster = authority[1]
        .array()?
        .iter()
        .map(|n| sized(n, 28).map(hex::encode))
        .collect::<FixtureResult<Vec<_>>>()?;
    require(
        controller != payer_hash && !roster.contains(&controller) && !roster.contains(&payer_hash),
        "admin selected fixture roles must be disjoint",
    )?;
    let required = body
        .required(14)?
        .set()?
        .iter()
        .map(|n| sized(n, 28).map(hex::encode))
        .collect::<FixtureResult<Vec<_>>>()?;
    require(
        required.windows(2).all(|w| w[0] < w[1]),
        "admin required signer set must be unique and sorted",
    )?;
    let rs = witness.required(5)?.array()?;
    require(rs.len() == 1, "admin sole real spending purpose")?;
    let r = rs[0].array()?;
    require(
        r.len() == 4 && r[0].int()? == 0,
        "admin spending redeemer shape",
    )?;
    let index = usize::try_from(r[1].int()?).map_err(|_| FixtureError("admin spend index"))?;
    require(
        normal.get(index) == Some(&state_input.reference),
        "admin Spend index must name actual state",
    )?;
    require(
        data(&r[2])? == raw[r[2].start..r[2].end],
        "admin canonical redeemer Data",
    )?;
    let outer = constr(&r[2], 5, 1)?;
    let (tag, args) = outer[0].constructor()?;
    require(tag <= 1, "admin action not admitted")?;
    let add = tag == 0;
    let expected_count = if add { 2 } else { 3 };
    require(
        required.len() == expected_count && required.contains(&payer_hash),
        "admin exact required signer cardinality",
    )?;
    let authority_signers = required
        .iter()
        .filter(|k| *k != &payer_hash)
        .cloned()
        .collect::<Vec<_>>();
    if add {
        require(
            authority_signers == vec![controller.clone()],
            "admin current controller required",
        )?;
    } else {
        require(
            authority_signers.len() == 2 && authority_signers.iter().all(|k| roster.contains(k)),
            "admin two distinct current recovery signers required",
        )?;
    }
    require(
        match role {
            AdminRole::Controller => add && payment == controller,
            AdminRole::Recovery => !add && authority_signers.iter().any(|k| k == payment),
            AdminRole::FeePayer => payment == payer_hash,
        },
        "admin native key/immutable role mismatch",
    )?;
    let ex = r[3].array()?;
    require(ex.len() == 2, "admin declared budget shape")?;
    let memory = integer(&ex[0], 1, 17_500_000)?;
    let steps = integer(&ex[1], 1, 10_000_000_000)?;
    let signed_size = raw.len() + 5 + 101 * expected_count;
    require(signed_size <= 16384, "admin projected signed size")?;
    // The decoded reference program was independently checked for both exact hash
    // and raw payload length 15,122. Only that one reference is admitted above.
    let reference_bytes = 15122;
    let minimum_fee = 155381
        + 44 * signed_size as i128
        + (577000 * memory + 721 * steps + 9_999_999) / 10_000_000
        + 15 * reference_bytes;
    require(
        fee >= minimum_fee,
        "admin fee below exact projected/reference minimum",
    )?;
    let scope = commit(
        "castalia/kettle-registry-scope/v1",
        &list(vec![bytes(&[0xcf; 32]), bytes(&[0xce; 32]), bytes(&[0; 4])]),
    )?;
    let descriptor = qualified_descriptor_node();
    let descriptor_digest = commit("castalia/kettle-policy-descriptor/v1", &descriptor)?;
    let initial_use = commit(
        "castalia/kettle-policy-use-initial/v1",
        &list(vec![bytes(&scope), bytes(&descriptor_digest)]),
    )?;
    let key = commit("castalia/kettle-policy-key/v1", &bytes(b"drink"))?;
    let before_root = sized(&old[4], 32)?;
    let after_root = sized(&new[4], 32)?;
    let (caps, proof, prior_record, prior_use, next_record) = if add {
        require(
            args.len() == 4 && epoch == 0,
            "admin Add arity/current epoch",
        )?;
        require(
            data(&args[0])? == qualified_descriptor() && data(&args[2])? == qualified_content(),
            "admin Add pinned descriptor/content",
        )?;
        let AdminHistory::FixtureGenesis { state_ref } = &ctx.history else {
            return Err(FixtureError("admin Add requires admitted fixture genesis"));
        };
        require(
            state_ref == &state_input.reference && before_root == empty_root(&scope),
            "admin Add exact genesis/absence root",
        )?;
        let record = fields(vec![
            descriptor.clone(),
            node(Value::Tag(122, Box::new(list(vec![])))),
            args[1].clone(),
            bytes(&initial_use),
        ]);
        (&args[1], &args[3], None, None, record)
    } else {
        require(
            args.len() == 2 && epoch == 2,
            "admin Disable arity/current epoch",
        )?;
        let prior = constr(&args[0], 0, 4)?;
        constr(&prior[1], 1, 0)?;
        require(
            data(&prior[0])? == qualified_descriptor(),
            "admin Disable descriptor mismatch",
        )?;
        let AdminHistory::AcceptedRegisteredPour {
            accepted_add_ref: _,
            accepted_pour_ref,
            descriptor_data_hex,
            source_content_data_hex,
            prior_record_data_hex,
        } = &ctx.history
        else {
            return Err(FixtureError(
                "admin Disable requires accepted Registered history",
            ));
        };
        require(
            accepted_pour_ref == &state_input.reference
                && descriptor_data_hex == &profile.descriptor_data_hex
                && source_content_data_hex == &profile.source_content_data_hex
                && prior_record_data_hex == &original(&raw, &args[0]),
            "admin accepted live history/record mismatch",
        )?;
        let used = sized(&prior[3], 32)?.to_vec();
        require(
            used != initial_use,
            "admin Disable fixture requires exercised policy use",
        )?;
        let record = fields(vec![
            prior[0].clone(),
            fields(vec![]),
            prior[2].clone(),
            prior[3].clone(),
        ]);
        (&prior[2], &args[1], Some(&args[0]), Some(used), record)
    };
    let path = constr(proof, 0, 2)?;
    require(
        sized(&path[0], 32)? == [0; 32] && path[1].array()?.is_empty(),
        "admin selected single-leaf proof",
    )?;
    let cap_nodes = caps.array()?;
    require((1..=8).contains(&cap_nodes.len()), "admin cap row bound")?;
    let mut cap_views = vec![];
    let mut last = None;
    let mut any_paid = false;
    for cap in cap_nodes {
        let c = constr(cap, 0, 4)?;
        let unit = unit(c)?;
        let order = unit_order(&unit);
        require(
            last.as_ref().is_none_or(|p| p < &order),
            "admin cap order/duplicate",
        )?;
        last = Some(order);
        let max = integer(&c[2], 1, MAXIMUM)?;
        let paid = integer(&c[3], 0, max)?;
        require(!add || paid == 0, "admin Add must start unpaid")?;
        any_paid |= paid > 0;
        cap_views.push(json!({"unit":unit,"maximum":max.to_string(),"paidBefore":paid.to_string(),"paidAfter":paid.to_string()}));
    }
    require(
        add || any_paid,
        "admin Disable fixture requires positive prior paid",
    )?;
    if let Some(prior) = prior_record {
        require(
            map_root(&scope, &key, prior, proof)? == before_root,
            "admin authenticated prior membership",
        )?;
    }
    require(
        map_root(&scope, &key, &next_record, proof)? == after_root,
        "admin exact updated registry root",
    )?;
    require(
        payer.output.value.coin == fee + change.value.coin,
        "admin external payer conservation",
    )?;
    let collateral_return = output(body.required(16)?, &raw)?;
    plain(&collateral_return, &payer_address)?;
    let at_risk = integer(body.required(17)?, 1, MAXIMUM)?;
    require(
        collateral_input.output.value.coin == collateral_return.value.coin + at_risk
            && at_risk >= (fee * 150 + 99) / 100,
        "admin payer collateral allocation",
    )?;
    let body_hash: [u8; 32] = blake(&raw[body.start..body.end], 32).try_into().unwrap();
    let envelope_hash = sha(&raw);
    let use_after = if add {
        initial_use
    } else {
        prior_use.clone().unwrap()
    };
    let mut common = json!({"schema":"castalia.cardano-fixture-common-review.v4","kind":if add{"kettle-policy-add"}else{"kettle-policy-disable"},"transactionBodyHash":hex::encode(body_hash),"transactionEnvelopeHash":envelope_hash,"scriptDataHash":script_data_hash,"stateRef":state_input.reference,"payerRef":payer.reference,"collateralRef":collateral_input.reference,"kettleCodeRef":code.reference,"policyId":hex::encode(b"drink"),"descriptorDataHex":profile.descriptor_data_hex,"sourceContentDataHex":profile.source_content_data_hex});
    let records = json!({"priorRecordDataHex":prior_record.map(|n|original(&raw,n)),"nextRecordDataHex":hex::encode(data(&next_record)?),"proofDataHex":original(&raw,proof),"stateDatumHex":hex::encode(old_raw),"nextStateDatumHex":hex::encode(new_raw),"beforeRoot":hex::encode(before_root),"afterRoot":hex::encode(after_root),"priorUse":prior_use.map(hex::encode),"nextUse":hex::encode(use_after),"epochBefore":epoch.to_string(),"epochAfter":(epoch+1).to_string(),"controllerKeyHash":controller,"recoveryKeyHashes":roster,"authoritySignerKeyHashes":authority_signers,"feePayerKeyHash":payer_hash,"requiredSignerKeyHashes":required});
    let cost = json!({"projectedWitnessCount":expected_count,"projectedSignedSize":signed_size,"referenceScriptBytes":reference_bytes,"minimumFeeLovelace":minimum_fee.to_string(),"feeLovelace":fee.to_string(),"payerInputLovelace":payer.output.value.coin.to_string(),"payerChangeLovelace":change.value.coin.to_string(),"collateralInputLovelace":collateral_input.output.value.coin.to_string(),"collateralReturnLovelace":collateral_return.value.coin.to_string(),"collateralAtRiskLovelace":at_risk.to_string(),"reserveLovelace":old[3].int()?.to_string()});
    let values = json!({"stateBefore":output_json(&state_input.output),"stateAfter":output_json(&next),"payerChange":output_json(&change),"caps":cap_views,"redeemers":[{"index":index,"dataHex":original(&raw,&r[2]),"memory":memory.to_string(),"steps":steps.to_string()}]});
    for part in [records, cost, values] {
        common
            .as_object_mut()
            .unwrap()
            .extend(part.as_object().unwrap().clone());
    }
    let review = json!({"schema":"castalia.cardano-fixture-review.v4","commonReviewHash":sha(&canonical(&common)?),"common":common,"participation":{"paymentKeyHash":payment,"role":role}});
    Ok((body_hash, envelope_hash, review))
}
