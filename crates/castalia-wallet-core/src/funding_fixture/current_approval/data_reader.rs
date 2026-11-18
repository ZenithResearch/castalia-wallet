//! Decode a bounded Plutus Data span for semantic comparisons. Original ledger hashes use the wire span.
use super::super::cbor::{Node, Value};
use super::{FixtureError, FixtureResult, ensure};

pub(super) fn read(raw: &[u8]) -> FixtureResult<Node> {
    ensure(
        !raw.is_empty() && raw.len() <= 16384,
        "current Data span size",
    )?;
    let mut r = Reader {
        rest: raw,
        length: raw.len(),
        nodes: 0,
    };
    let parsed = r.item(0)?;
    ensure(r.rest.is_empty(), "trailing current Data")?;
    Ok(parsed)
}

struct Reader<'a> {
    rest: &'a [u8],
    length: usize,
    nodes: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> FixtureResult<&'a [u8]> {
        let (prefix, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(FixtureError("truncated current Data"))?;
        self.rest = tail;
        Ok(prefix)
    }
    fn head(&mut self) -> FixtureResult<(u8, Option<u64>)> {
        let first = self.take(1)?[0];
        let extra = first & 31;
        let arg = match extra {
            0..=23 => Some(u64::from(extra)),
            24..=27 => {
                let mut word = [0; 8];
                let len = 1usize << (extra - 24);
                word[8 - len..].copy_from_slice(self.take(len)?);
                Some(u64::from_be_bytes(word))
            }
            31 => None,
            _ => return Err(FixtureError("current Data header")),
        };
        Ok((first >> 5, arg))
    }
    fn rows(
        &mut self,
        count: Option<u64>,
        mut row: impl FnMut(&mut Self) -> FixtureResult<()>,
    ) -> FixtureResult<()> {
        ensure(
            count.is_none_or(|n| n <= 256),
            "current Data collection bound",
        )?;
        for i in 0..=256 {
            if count == Some(i) {
                return Ok(());
            }
            if count.is_none() && self.rest.first() == Some(&0xff) {
                self.take(1)?;
                return Ok(());
            }
            ensure(i < 256, "current Data collection bound")?;
            row(self)?;
        }
        Err(FixtureError("current Data collection bound"))
    }
    fn piece(&mut self, len: Option<u64>) -> FixtureResult<&'a [u8]> {
        let n = len
            .filter(|l| *l <= 64)
            .ok_or(FixtureError("current Data byte chunk"))?;
        self.take(n as usize)
    }
    fn bytes(&mut self, len: Option<u64>) -> FixtureResult<Vec<u8>> {
        if len.is_some() {
            return Ok(self.piece(len)?.to_vec());
        }
        let mut out = Vec::new();
        while self.rest.first() != Some(&0xff) {
            let (major, size) = self.head()?;
            ensure(major == 2, "current Data byte chunk type")?;
            out.extend_from_slice(self.piece(size)?);
        }
        self.take(1)?;
        Ok(out)
    }
    fn item(&mut self, depth: usize) -> FixtureResult<Node> {
        ensure(
            depth <= 32 && self.nodes < 8192,
            "current Data structural bound",
        )?;
        self.nodes += 1;
        let start = self.length - self.rest.len();
        let (major, arg) = self.head()?;
        let value = match (major, arg) {
            (0, Some(n)) => Value::Int(i128::from(n)),
            (1, Some(n)) => Value::Int(-1 - i128::from(n)),
            (2, n) => Value::Bytes(self.bytes(n)?),
            (4, n) => {
                let mut rows = Vec::new();
                self.rows(n, |r| {
                    rows.push(r.item(depth + 1)?);
                    Ok(())
                })?;
                Value::Array(rows)
            }
            (5, n) => {
                let mut rows = Vec::new();
                self.rows(n, |r| {
                    let key = r.item(depth + 1)?;
                    ensure(
                        !rows.iter().any(|(k, _)| k == &key),
                        "duplicate current Data map key",
                    )?;
                    rows.push((key, r.item(depth + 1)?));
                    Ok(())
                })?;
                Value::Map(rows)
            }
            (6, Some(tag @ (2 | 3))) => {
                let (major, n) = self.head()?;
                ensure(major == 2, "current Data bignum bytes")?;
                let magnitude = self.bytes(n)?.into_iter().try_fold(0u64, |a, b| {
                    a.checked_mul(256)
                        .and_then(|n| n.checked_add(u64::from(b)))
                        .ok_or(FixtureError("current Data integer range"))
                })?;
                let n = i128::from(magnitude);
                Value::Int(if tag == 2 { n } else { -1 - n })
            }
            (6, Some(102)) => {
                let (outer, n) = self.head()?;
                ensure(
                    outer == 4 && n.is_none_or(|n| n == 2),
                    "current Data constructor pair",
                )?;
                let (major, index) = self.head()?;
                ensure(major == 0, "current Data constructor index")?;
                let tag = match index {
                    Some(i @ 0..=6) => 121 + i,
                    Some(i @ 7..=127) => 1280 + i - 7,
                    _ => return Err(FixtureError("current approval constructor range")),
                };
                let fields = self.item(depth + 1)?;
                fields.array()?;
                if n.is_none() {
                    ensure(self.take(1)? == [0xff], "current Data constructor arity")?;
                }
                Value::Tag(tag, Box::new(fields))
            }
            (6, Some(tag @ (121..=127 | 1280..=1400))) => {
                let fields = self.item(depth + 1)?;
                fields.array()?;
                Value::Tag(tag, Box::new(fields))
            }
            _ => return Err(FixtureError("unsupported current Data")),
        };
        Ok(Node {
            start,
            end: self.length - self.rest.len(),
            value,
        })
    }
}
