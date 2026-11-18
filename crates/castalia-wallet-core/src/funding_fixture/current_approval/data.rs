//! Canonical Plutus Data commitments and scoped sparse-map paths for the current instance.
use super::super::cbor::{Node, Value};
use super::*;

pub(super) fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    Digest::finalize(h).into()
}
fn node(value: Value) -> Node {
    Node {
        start: 0,
        end: 0,
        value,
    }
}
pub(super) fn bytes(v: &[u8]) -> Node {
    node(Value::Bytes(v.to_vec()))
}
pub(super) fn number(v: i128) -> Node {
    node(Value::Int(v))
}
pub(super) fn list(v: Vec<Node>) -> Node {
    node(Value::Array(v))
}
pub(super) fn fields(v: Vec<Node>) -> Node {
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
                u64::try_from(magnitude).map_err(|_| FixtureError("current Data integer range"))?,
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
        _ => return Err(FixtureError("unsupported current Data encoding")),
    }
    Ok(())
}
pub(super) fn data(n: &Node) -> FixtureResult<Vec<u8>> {
    let mut b = vec![];
    serialize(n, &mut b)?;
    Ok(b)
}
pub(super) fn commit(domain: &str, n: &Node) -> FixtureResult<Vec<u8>> {
    Ok(digest(&[domain.as_bytes(), &[0], &data(n)?]).to_vec())
}

pub(super) fn ctor(n: &Node, index: u64, count: usize) -> FixtureResult<&[Node]> {
    let (i, items) = n.constructor()?;
    ensure(
        i == index && items.len() == count,
        "current Data constructor",
    )?;
    Ok(items)
}
pub(super) fn octets(n: &Node, min: usize, max: usize) -> FixtureResult<&[u8]> {
    let b = n.bytes()?;
    ensure((min..=max).contains(&b.len()), "current Data bytes")?;
    Ok(b)
}
pub(super) fn bounded(n: &Node, min: i128, max: i128) -> FixtureResult<i128> {
    let q = n.int()?;
    ensure((min..=max).contains(&q), "current Data integer")?;
    Ok(q)
}
pub(super) fn bool_node(value: bool) -> Node {
    node(Value::Tag(
        if value { 122 } else { 121 },
        Box::new(list(vec![])),
    ))
}
pub(super) fn map_root(id: &Node, record: Option<&Node>, path: &Proof) -> FixtureResult<String> {
    let scope = decode_fixed::<32>(SCOPE)?;
    let key = commit("castalia/kettle-policy-key/v1", id)?;
    let bitmap = decode_fixed::<32>(&path.bitmap)?;
    ensure(
        path.siblings.len()
            == bitmap
                .iter()
                .map(|b| b.count_ones() as usize)
                .sum::<usize>(),
        "current proof cardinality",
    )?;
    let mut empty = digest(&[&[0], &scope]);
    let mut cur = match record {
        Some(r) => digest(&[
            &[1],
            &scope,
            &key,
            &commit("castalia/kettle-policy-record/v1", r)?,
        ]),
        None => empty,
    };
    let mut siblings = path.siblings.iter();
    for level in 0..256 {
        let side = if (bitmap[level / 8] >> (level % 8)) & 1 != 0 {
            let h = decode_fixed::<32>(
                siblings
                    .next()
                    .ok_or(FixtureError("missing proof sibling"))?,
            )?;
            ensure(h != empty, "explicit default sparse sibling")?;
            h
        } else {
            empty
        };
        cur = if (key[31 - level / 8] >> (level % 8)) & 1 != 0 {
            digest(&[&[2], &scope, &side, &cur])
        } else {
            digest(&[&[2], &scope, &cur, &side])
        };
        empty = digest(&[&[2], &scope, &empty, &empty]);
    }
    Ok(hex::encode(cur))
}
pub(super) fn proof_matches(n: &Node, proof: &Proof) -> FixtureResult<()> {
    let rows = ctor(n, 0, 2)?;
    ensure(
        hex::encode(octets(&rows[0], 32, 32)?) == proof.bitmap,
        "current proof bitmap",
    )?;
    let sib = rows[1].array()?;
    ensure(
        sib.len() == proof.siblings.len() && sib.len() <= 256,
        "current proof count",
    )?;
    for (a, b) in sib.iter().zip(&proof.siblings) {
        ensure(
            hex::encode(octets(a, 32, 32)?) == *b,
            "current proof sibling",
        )?;
    }
    Ok(())
}
