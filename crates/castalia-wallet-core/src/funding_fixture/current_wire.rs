//! Pure, opt-in observations of the original bytes in the current Kettle fixture wire subset.
//! Decoding does not establish acceptance, authorization, or the provenance of an output.

use blake2::{Blake2b, digest::consts::U32};
use serde::Serialize;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_BYTES: usize = 16_384;
const ROLE_LIMIT: usize = 256;
const DATA_DEPTH: usize = 32;
const DATA_ROWS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WireError {
    #[error("encoding")]
    Encoding,
    #[error("bound")]
    Bound,
    #[error("unsupported")]
    Unsupported,
    #[error("duplicate")]
    Duplicate,
}
use WireError::*;
type Result<T> = std::result::Result<T, WireError>;

#[derive(Debug, Serialize)]
pub struct Span {
    pub offset: usize,
    pub length: usize,
    pub sha256: String,
}

fn original(hex_bytes: &str) -> Result<Vec<u8>> {
    if hex_bytes.is_empty() || hex_bytes.len() > MAX_BYTES * 2 {
        return Err(Bound);
    }
    if !hex_bytes
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Encoding);
    }
    hex::decode(hex_bytes).map_err(|_| Encoding)
}

struct Head {
    major: u8,
    extra: u8,
    arg: Option<u64>,
}

struct Cursor<'a> {
    raw: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self {
            raw,
            pos: 0,
            end: raw.len(),
        }
    }
    fn peek(&self) -> Result<u8> {
        if self.pos >= self.end {
            Err(Encoding)
        } else {
            Ok(self.raw[self.pos])
        }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.end - self.pos {
            return Err(Encoding);
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.raw[start..self.pos])
    }
    fn span(&self, start: usize) -> Span {
        Span {
            offset: start,
            length: self.pos - start,
            sha256: hex::encode(Sha256::digest(&self.raw[start..self.pos])),
        }
    }
    // Every header consumes at least one distinct original byte, including inside tag 24.
    fn head(&mut self) -> Result<Head> {
        let first = self.take(1)?[0];
        let extra = first & 31;
        let arg = match extra {
            0..=23 => Some(u64::from(extra)),
            24..=27 => {
                let n = 1usize << (extra - 24);
                let mut bytes = [0u8; 8];
                bytes[8 - n..].copy_from_slice(self.take(n)?);
                Some(u64::from_be_bytes(bytes))
            }
            31 => None,
            _ => return Err(Encoding),
        };
        Ok(Head {
            major: first >> 5,
            extra,
            arg,
        })
    }
    fn uint(&mut self, max: u64) -> Result<u64> {
        let h = self.head()?;
        if h.major != 0 {
            return Err(Encoding);
        }
        let n = h.arg.ok_or(Encoding)?;
        if n > max { Err(Bound) } else { Ok(n) }
    }
    fn mint_int(&mut self) -> Result<i64> {
        let h = self.head()?;
        if h.major > 1 {
            return Err(Encoding);
        }
        let n = i64::try_from(h.arg.ok_or(Encoding)?).map_err(|_| Bound)?;
        Ok(if h.major == 0 { n } else { !n })
    }
    fn tag(&mut self, expected: u64) -> Result<()> {
        let h = self.head()?;
        if h.major == 6 && h.arg == Some(expected) {
            Ok(())
        } else {
            Err(Unsupported)
        }
    }
    fn simple(&mut self, allowed: &[u8]) -> Result<u8> {
        let h = self.head()?;
        if h.major == 7 && allowed.contains(&h.extra) {
            Ok(h.extra)
        } else {
            Err(Unsupported)
        }
    }
    fn collection(
        &mut self,
        major: u8,
        max: usize,
        mut read: impl FnMut(&mut Self, usize) -> Result<()>,
    ) -> Result<usize> {
        let h = self.head()?;
        if h.major != major {
            return Err(Encoding);
        }
        if let Some(n) = h.arg {
            if n > max as u64 {
                return Err(Bound);
            }
            let n = n as usize;
            if n * (if major == 5 { 2 } else { 1 }) > self.end - self.pos {
                return Err(Encoding);
            }
            for i in 0..n {
                read(self, i)?
            }
            return Ok(n);
        }
        let mut n = 0;
        while self.peek()? != 0xff {
            if n == max {
                return Err(Bound);
            }
            read(self, n)?;
            n += 1;
        }
        self.pos += 1;
        Ok(n)
    }
    fn tuple<T>(&mut self, len: u64, read: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let h = self.head()?;
        if h.major != 4 || h.arg.is_some_and(|n| n != len) {
            return Err(Encoding);
        }
        let result = read(self)?;
        if h.arg.is_none() && self.take(1)?[0] != 0xff {
            return Err(Encoding);
        }
        Ok(result)
    }
    fn payload(&mut self, n: Option<u64>, max: usize) -> Result<&'a [u8]> {
        let n = n.ok_or(Encoding)?;
        if n > max as u64 {
            return Err(Bound);
        }
        self.take(n as usize)
    }
    fn byte_chunks(
        &mut self,
        min: usize,
        max: usize,
        max_chunk: usize,
        mut read: impl FnMut(&[u8]),
    ) -> Result<()> {
        let h = self.head()?;
        if h.major != 2 {
            return Err(Encoding);
        }
        let length = if h.arg.is_some() {
            let b = self.payload(h.arg, max_chunk.min(max))?;
            read(b);
            b.len()
        } else {
            let mut total = 0;
            while self.peek()? != 0xff {
                let piece = self.head()?;
                if piece.major != 2 {
                    return Err(Encoding);
                }
                let b = self.payload(piece.arg, max_chunk.min(max - total))?;
                total += b.len();
                read(b);
            }
            self.pos += 1;
            total
        };
        if length < min { Err(Bound) } else { Ok(()) }
    }
    fn bytes(&mut self, min: usize, max: usize) -> Result<String> {
        let mut bytes = Vec::new();
        self.byte_chunks(min, max, max, |b| bytes.extend_from_slice(b))?;
        Ok(hex::encode(bytes))
    }
    fn embedded<T>(&mut self, read: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.tag(24)?;
        let h = self.head()?;
        if h.major != 2 || h.arg.is_none() {
            return Err(Unsupported);
        }
        let len = h.arg.ok_or(Unsupported)?;
        if len > MAX_BYTES as u64 {
            return Err(Bound);
        }
        if len as usize > self.end - self.pos {
            return Err(Encoding);
        }
        let outer_end = self.end;
        self.end = self.pos + len as usize;
        let result = read(self)?;
        self.finish()?;
        self.end = outer_end;
        Ok(result)
    }
    fn finish(&self) -> Result<()> {
        if self.pos == self.end {
            Ok(())
        } else {
            Err(Encoding)
        }
    }
    fn closed(
        &mut self,
        allowed: &[u8],
        mut read: impl FnMut(&mut Self, u8) -> Result<()>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        self.collection(5, allowed.len(), |c, _| {
            let key = c.uint(255)? as u8;
            if !allowed.contains(&key) {
                return Err(Unsupported);
            }
            if !seen.insert(key) {
                return Err(Duplicate);
            }
            read(c, key)
        })?;
        Ok(())
    }
    fn set<T, K: Ord>(
        &mut self,
        mut read: impl FnMut(&mut Self) -> Result<T>,
        key: impl Fn(&T) -> K,
    ) -> Result<Vec<T>> {
        if self.peek()? >> 5 == 6 {
            self.tag(258)?;
        }
        let mut values = Vec::new();
        let mut keys = BTreeSet::new();
        self.collection(4, ROLE_LIMIT, |c, _| {
            let v = read(c)?;
            if !keys.insert(key(&v)) {
                return Err(Duplicate);
            }
            values.push(v);
            Ok(())
        })?;
        if values.is_empty() {
            Err(Unsupported)
        } else {
            Ok(values)
        }
    }
}

fn decimal<S: serde::Serializer, T: std::fmt::Display>(
    v: &T,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.collect_str(v)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    policy_id: String,
    asset_name: String,
    #[serde(serialize_with = "decimal")]
    quantity: i128,
}
fn asset_map(c: &mut Cursor, mint: bool) -> Result<Vec<Asset>> {
    let mut policies = BTreeSet::new();
    let mut assets = Vec::new();
    c.collection(5, MAX_BYTES / 2, |c, _| {
        let policy_id = c.bytes(28, 28)?;
        if !policies.insert(policy_id.clone()) {
            return Err(Duplicate);
        }
        let mut names = BTreeSet::new();
        let count = c.collection(5, MAX_BYTES / 2, |c, _| {
            let asset_name = c.bytes(0, 32)?;
            if !names.insert(asset_name.clone()) {
                return Err(Duplicate);
            }
            let quantity = if mint {
                i128::from(c.mint_int()?)
            } else {
                i128::from(c.uint(u64::MAX)?)
            };
            if quantity == 0 {
                return Err(Unsupported);
            }
            assets.push(Asset {
                policy_id: policy_id.clone(),
                asset_name,
                quantity,
            });
            Ok(())
        })?;
        if count == 0 {
            return Err(Unsupported);
        }
        Ok(())
    })?;
    Ok(assets)
}

#[derive(Debug, Serialize)]
pub struct OutputValue {
    span: Span,
    shape: &'static str,
    #[serde(serialize_with = "decimal")]
    coin: u64,
    assets: Vec<Asset>,
}
fn value(c: &mut Cursor) -> Result<OutputValue> {
    let start = c.pos;
    let first = c.peek()?;
    let (coin, assets, shape) = if first >> 5 == 0 {
        (c.uint(u64::MAX)?, Vec::new(), "coin")
    } else {
        let (coin, assets) = c.tuple(2, |c| Ok((c.uint(u64::MAX)?, asset_map(c, false)?)))?;
        (
            coin,
            assets,
            if first == 0x9f {
                "indefinite-pair"
            } else {
                "definite-pair"
            },
        )
    };
    Ok(OutputValue {
        span: c.span(start),
        coin,
        assets,
        shape,
    })
}

fn data(c: &mut Cursor, depth: usize) -> Result<()> {
    if depth > DATA_DEPTH {
        return Err(Bound);
    }
    let child = |c: &mut Cursor, _| data(c, depth + 1);
    match c.peek()? >> 5 {
        0 | 1 => {
            c.head()?.arg.ok_or(Encoding)?;
        }
        2 => c.byte_chunks(0, MAX_BYTES, 64, |_| {})?,
        4 => {
            c.collection(4, DATA_ROWS, child)?;
        }
        5 => {
            c.collection(5, DATA_ROWS, |c, _| {
                data(c, depth + 1)?;
                data(c, depth + 1)
            })?;
        }
        6 => match c.head()?.arg {
            Some(2 | 3) => c.byte_chunks(0, MAX_BYTES, 64, |_| {})?,
            Some(102) => c.tuple(2, |c| {
                c.uint(u64::MAX)?;
                c.collection(4, DATA_ROWS, child)?;
                Ok(())
            })?,
            Some(121..=127 | 1280..=1400) => {
                c.collection(4, DATA_ROWS, child)?;
            }
            _ => return Err(Unsupported),
        },
        _ => return Err(Unsupported),
    }
    Ok(())
}
fn data_span(c: &mut Cursor) -> Result<Span> {
    let start = c.pos;
    data(c, 0)?;
    Ok(c.span(start))
}
fn native_script(c: &mut Cursor, depth: usize) -> Result<()> {
    if depth > DATA_DEPTH {
        return Err(Bound);
    }
    c.tuple(2, |c| {
        match c.uint(u64::MAX)? {
            0 => {
                c.bytes(28, 28)?;
            }
            1 => {
                c.collection(4, ROLE_LIMIT, |c, _| native_script(c, depth + 1))?;
            }
            5 => {
                c.uint(u64::MAX)?;
            }
            _ => return Err(Unsupported),
        }
        Ok(())
    })
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Datum {
    Hash { hash: String },
    Inline { span: Span },
}
#[derive(Debug, Serialize)]
struct ScriptRef {
    language: &'static str,
    span: Span,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    span: Span,
    address: String,
    value: OutputValue,
    datum: Option<Datum>,
    script_ref: Option<ScriptRef>,
}

fn output(c: &mut Cursor) -> Result<Output> {
    let start = c.pos;
    let (mut address, mut amount, mut datum, mut script_ref) = (None, None, None, None);
    if c.peek()? >> 5 == 4 {
        let count = c.collection(4, 3, |c, i| {
            match i {
                0 => address = Some(c.bytes(1, 128)?),
                1 => amount = Some(value(c)?),
                _ => {
                    datum = Some(Datum::Hash {
                        hash: c.bytes(32, 32)?,
                    })
                }
            }
            Ok(())
        })?;
        if count < 2 {
            return Err(Encoding);
        }
    } else {
        c.closed(&[0, 1, 2, 3], |c, key| {
            match key {
                0 => address = Some(c.bytes(1, 128)?),
                1 => amount = Some(value(c)?),
                2 => {
                    datum = Some(c.tuple(2, |c| {
                        if c.uint(1)? == 0 {
                            Ok(Datum::Hash {
                                hash: c.bytes(32, 32)?,
                            })
                        } else {
                            Ok(Datum::Inline {
                                span: c.embedded(data_span)?,
                            })
                        }
                    })?)
                }
                3 => {
                    script_ref = Some(c.embedded(|c| {
                        let start = c.pos;
                        let language = c.tuple(2, |c| match c.uint(u64::MAX)? {
                            0 => {
                                native_script(c, 0)?;
                                Ok("native")
                            }
                            3 => {
                                c.byte_chunks(1, MAX_BYTES, MAX_BYTES, |_| {})?;
                                Ok("plutus-v3")
                            }
                            _ => Err(Unsupported),
                        })?;
                        Ok(ScriptRef {
                            span: c.span(start),
                            language,
                        })
                    })?)
                }
                _ => unreachable!(),
            }
            Ok(())
        })?;
    }
    Ok(Output {
        span: c.span(start),
        address: address.ok_or(Encoding)?,
        value: amount.ok_or(Encoding)?,
        datum,
        script_ref,
    })
}
/// Decode one standalone original output. Its span offsets start at zero.
pub fn decode_original_output(original_hex: &str) -> Result<Output> {
    let raw = original(original_hex)?;
    let mut c = Cursor::new(&raw);
    let o = output(&mut c)?;
    c.finish()?;
    Ok(o)
}

#[derive(Debug, Serialize, Clone, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "camelCase")]
struct Outpoint {
    tx_hash: String,
    output_index: u16,
}
fn inputs(c: &mut Cursor) -> Result<Vec<Outpoint>> {
    c.set(
        |c| {
            c.tuple(2, |c| {
                Ok(Outpoint {
                    tx_hash: c.bytes(32, 32)?,
                    output_index: c.uint(u16::MAX.into())? as u16,
                })
            })
        },
        Clone::clone,
    )
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Body {
    body: Span,
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
}
fn body(c: &mut Cursor) -> Result<Body> {
    let start = c.pos;
    let (mut normal, mut outputs, mut fee) = (None, None, None);
    let (
        mut ttl,
        mut validity_start,
        mut network_id,
        mut script_data_hash,
        mut total_collateral,
        mut collateral_return,
    ) = (None, None, None, None, None, None);
    let (mut reference_inputs, mut collateral_inputs, mut required_signers, mut mint) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.closed(&[0, 1, 2, 3, 8, 9, 11, 13, 14, 15, 16, 17, 18], |c, key| {
        match key {
            0 => normal = Some(inputs(c)?),
            1 => {
                let mut rows = Vec::new();
                c.collection(4, ROLE_LIMIT, |c, _| {
                    rows.push(output(c)?);
                    Ok(())
                })?;
                outputs = Some(rows);
            }
            2 => fee = Some(c.uint(u64::MAX)?.to_string()),
            3 => ttl = Some(c.uint(u64::MAX)?.to_string()),
            8 => validity_start = Some(c.uint(u64::MAX)?.to_string()),
            9 => {
                mint = asset_map(c, true)?;
                if mint.is_empty() {
                    return Err(Unsupported);
                }
            }
            11 => script_data_hash = Some(c.bytes(32, 32)?),
            13 => collateral_inputs = inputs(c)?,
            14 => required_signers = c.set(|c| c.bytes(28, 28), Clone::clone)?,
            15 => network_id = Some(c.uint(1)? as u8),
            16 => collateral_return = Some(output(c)?),
            17 => total_collateral = Some(c.uint(u64::MAX)?.to_string()),
            18 => reference_inputs = inputs(c)?,
            _ => unreachable!(),
        }
        Ok(())
    })?;
    let normal_inputs = normal.ok_or(Encoding)?;
    let outputs = outputs.ok_or(Encoding)?;
    let fee = fee.ok_or(Encoding)?;
    let mut roles = BTreeSet::new();
    if !normal_inputs
        .iter()
        .chain(&reference_inputs)
        .chain(&collateral_inputs)
        .all(|r| roles.insert(r))
    {
        return Err(Duplicate);
    }
    Ok(Body {
        body: c.span(start),
        fee,
        ttl,
        validity_start,
        network_id,
        script_data_hash,
        total_collateral,
        normal_inputs,
        reference_inputs,
        collateral_inputs,
        required_signers,
        outputs,
        collateral_return,
        mint,
    })
}

fn redeemers(c: &mut Cursor, tx: &Body) -> Result<Vec<Json>> {
    let mut normal: Vec<_> = tx.normal_inputs.iter().collect();
    normal.sort_unstable();
    let policies: Vec<_> = tx
        .mint
        .iter()
        .map(|a| &a.policy_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut seen = BTreeSet::new();
    let mut pointer = |c: &mut Cursor| -> Result<(&'static str, u32, Json)> {
        let tag = c.uint(u64::MAX)?;
        let index = c.uint(u32::MAX.into())? as u32;
        if !seen.insert((tag, index)) {
            return Err(Duplicate);
        }
        match tag {
            0 => Ok((
                "spend",
                index,
                json!(normal.get(index as usize).ok_or(Unsupported)?),
            )),
            1 => Ok((
                "mint",
                index,
                json!(policies.get(index as usize).ok_or(Unsupported)?),
            )),
            _ => Err(Unsupported),
        }
    };
    let payload = |c: &mut Cursor| {
        let span = data_span(c)?;
        c.tuple(2, |c| {
            Ok((
                span,
                c.uint(u64::MAX)?.to_string(),
                c.uint(u64::MAX)?.to_string(),
            ))
        })
    };
    let mut rows = Vec::new();
    let map_form = c.peek()? >> 5 != 4;
    let major = if map_form { 5 } else { 4 };
    c.collection(major, ROLE_LIMIT, |c, _| {
        let ((purpose, index, target), (data, memory, steps)) = if map_form {
            (c.tuple(2, &mut pointer)?, c.tuple(2, payload)?)
        } else {
            c.tuple(4, |c| Ok((pointer(c)?, payload(c)?)))?
        };
        rows.push(json!({
            "purpose": purpose,
            "index": index,
            "target": target,
            "data": data,
            "memory": memory,
            "steps": steps,
        }));
        Ok(())
    })?;
    if rows.is_empty() {
        Err(Unsupported)
    } else {
        Ok(rows)
    }
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VKey {
    public_key: String,
    signature: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Witnesses {
    witness_set: Span,
    redeemers: Vec<Json>,
    vkeys: Vec<VKey>,
    native_scripts: Vec<Span>,
    plutus_v3_scripts: Vec<Span>,
}
fn witnesses(c: &mut Cursor, tx: &Body) -> Result<Witnesses> {
    let start = c.pos;
    let (mut vkeys, mut native_scripts, mut plutus_v3_scripts, mut reds) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    c.closed(&[0, 1, 5, 7], |c, key| {
        match key {
            0 => {
                vkeys = c.set(
                    |c| {
                        c.tuple(2, |c| {
                            Ok(VKey {
                                public_key: c.bytes(32, 32)?,
                                signature: c.bytes(64, 64)?,
                            })
                        })
                    },
                    |v| v.public_key.clone(),
                )?
            }
            1 => {
                native_scripts = c.set(
                    |c| {
                        let start = c.pos;
                        native_script(c, 0)?;
                        Ok(c.span(start))
                    },
                    |s| s.sha256.clone(),
                )?
            }
            5 => reds = redeemers(c, tx)?,
            7 => {
                plutus_v3_scripts = c
                    .set(
                        |c| {
                            let start = c.pos;
                            let code = c.bytes(1, MAX_BYTES)?;
                            Ok((c.span(start), code))
                        },
                        |(_, code)| code.clone(),
                    )?
                    .into_iter()
                    .map(|(span, _)| span)
                    .collect()
            }
            _ => unreachable!(),
        }
        Ok(())
    })?;
    Ok(Witnesses {
        witness_set: c.span(start),
        redeemers: reds,
        vkeys,
        native_scripts,
        plutus_v3_scripts,
    })
}

#[derive(Debug, Serialize)]
pub struct WireObservation {
    schema: &'static str,
    envelope: Span,
    #[serde(flatten)]
    body: Body,
    #[serde(flatten)]
    witnesses: Witnesses,
    tag: &'static str,
    #[serde(skip)]
    tx_id: String,
}
impl WireObservation {
    /// Blake2b-256 of the original encoded body. A wire identifier alone carries no receipt.
    pub fn transaction_id(&self) -> &str {
        &self.tx_id
    }
    /// Scalus 1.4.1 fixture representability of the decoded output Values.
    pub fn scalus_output_values(&self) -> Json {
        let check = |output: &Output| output.value.scalus_compatibility();
        json!({
            "outputs": self.body.outputs.iter().map(check).collect::<Vec<_>>(),
            "collateralReturn": self.body.collateral_return.as_ref().map(check),
        })
    }
}
/// Decode a fixture envelope and retain its original-body ID alongside the serializable observation.
pub fn decode_original_transaction(original_hex: &str) -> Result<WireObservation> {
    let raw = original(original_hex)?;
    let mut c = Cursor::new(&raw);
    let (body, witnesses, tag) = c.tuple(4, |c| {
        let body = body(c)?;
        let wit = witnesses(c, &body)?;
        let tag = if c.simple(&[20, 21])? == 21 {
            "normal-tag"
        } else {
            "invalid-tag"
        };
        c.simple(&[22])?;
        Ok((body, wit, tag))
    })?;
    c.finish()?;
    let span = &body.body;
    let tx_id = hex::encode(Blake2b::<U32>::digest(
        &raw[span.offset..span.offset + span.length],
    ));
    Ok(WireObservation {
        schema: "castalia.kettle-current-wire.v1",
        envelope: c.span(0),
        body,
        witnesses,
        tag,
        tx_id,
    })
}

fn head_width(n: u64) -> usize {
    match n {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}
impl OutputValue {
    fn scalus_compatibility(&self) -> Json {
        if self.shape == "indefinite-pair" {
            return json!({"error":"scalus-value-shape"});
        }
        if self.coin > i64::MAX as u64 {
            return json!({"error":"scalus-value-quantity"});
        }
        let mut size = head_width(self.coin);
        let mut counts = std::collections::BTreeMap::new();
        for a in &self.assets {
            if a.quantity > i128::from(i64::MAX) {
                return json!({"error":"scalus-value-quantity"});
            }
            let len = a.asset_name.len() / 2;
            size += head_width(len as u64) + len + head_width(a.quantity as u64);
            *counts.entry(&a.policy_id).or_insert(0u64) += 1;
        }
        if !counts.is_empty() {
            size += 1 + head_width(counts.len() as u64);
            for n in counts.values() {
                size += head_width(28) + 28 + head_width(*n);
            }
        }
        if size > 5_000 {
            json!({"error":"scalus-value-size","normalizedBytes":size})
        } else {
            json!({"normalizedBytes":size})
        }
    }
}

#[cfg(test)]
mod tests;
