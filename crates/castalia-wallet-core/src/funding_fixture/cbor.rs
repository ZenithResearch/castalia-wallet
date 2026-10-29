use super::{FixtureError, FixtureResult};

#[derive(Clone, Debug)]
pub(super) struct Node {
    pub start: usize,
    pub end: usize,
    pub value: Value,
}
impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl Eq for Node {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Value {
    Int(i128),
    Bytes(Vec<u8>),
    Array(Vec<Node>),
    Map(Vec<(Node, Node)>),
    Tag(u64, Box<Node>),
    Bool(bool),
    Null,
}
impl Node {
    pub fn int(&self) -> FixtureResult<i128> {
        if let Value::Int(n) = self.value {
            Ok(n)
        } else {
            Err(FixtureError("expected integer"))
        }
    }
    pub fn bytes(&self) -> FixtureResult<&[u8]> {
        if let Value::Bytes(ref b) = self.value {
            Ok(b)
        } else {
            Err(FixtureError("expected bytes"))
        }
    }
    pub fn array(&self) -> FixtureResult<&[Node]> {
        if let Value::Array(ref a) = self.value {
            Ok(a)
        } else {
            Err(FixtureError("expected array"))
        }
    }
    pub fn set(&self) -> FixtureResult<&[Node]> {
        match &self.value {
            Value::Tag(258, n) => n.array(),
            _ => self.array(),
        }
    }
    pub fn map(&self) -> FixtureResult<&[(Node, Node)]> {
        if let Value::Map(ref m) = self.value {
            Ok(m)
        } else {
            Err(FixtureError("expected map"))
        }
    }
    pub fn field(&self, key: i128) -> FixtureResult<Option<&Node>> {
        Ok(self
            .map()?
            .iter()
            .find(|(k, _)| k.value == Value::Int(key))
            .map(|(_, v)| v))
    }
    pub fn required(&self, key: i128) -> FixtureResult<&Node> {
        self.field(key)?
            .ok_or(FixtureError("missing transaction field"))
    }
    pub fn closed_map(&self, keys: &[i128]) -> FixtureResult<()> {
        for (key, _) in self.map()? {
            if !keys.contains(&key.int()?) {
                return Err(FixtureError("unsupported map field"));
            }
        }
        Ok(())
    }
    pub fn constructor(&self) -> FixtureResult<(u64, &[Node])> {
        match &self.value {
            Value::Tag(tag, n) if (121..=127).contains(tag) => Ok((tag - 121, n.array()?)),
            Value::Tag(tag, n) if (1280..=1400).contains(tag) => Ok((tag - 1280 + 7, n.array()?)),
            _ => Err(FixtureError("unsupported Data constructor")),
        }
    }
}
pub(super) fn parse(raw: &[u8]) -> FixtureResult<Node> {
    let mut parser = Parser {
        raw,
        pos: 0,
        nodes: 0,
    };
    let node = parser.item(0)?;
    if parser.pos != raw.len() {
        return Err(FixtureError("trailing CBOR bytes"));
    }
    Ok(node)
}
struct Parser<'a> {
    raw: &'a [u8],
    pos: usize,
    nodes: usize,
}
impl Parser<'_> {
    fn byte(&mut self) -> FixtureResult<u8> {
        let n = *self
            .raw
            .get(self.pos)
            .ok_or(FixtureError("truncated CBOR"))?;
        self.pos += 1;
        Ok(n)
    }
    fn uint(&mut self, a: u8) -> FixtureResult<Option<u64>> {
        let count = match a {
            0..=23 => return Ok(Some(u64::from(a))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 => return Ok(None),
            _ => return Err(FixtureError("invalid CBOR length")),
        };
        let mut value = 0;
        for _ in 0..count {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(Some(value))
    }
    fn length(&self, n: u64) -> FixtureResult<usize> {
        let n = usize::try_from(n).map_err(|_| FixtureError("CBOR length overflow"))?;
        if n > 65536 {
            Err(FixtureError("CBOR collection too large"))
        } else {
            Ok(n)
        }
    }
    fn item(&mut self, depth: usize) -> FixtureResult<Node> {
        if depth > 32 || self.nodes >= 8192 {
            return Err(FixtureError("CBOR structural limit"));
        }
        self.nodes += 1;
        let start = self.pos;
        let b = self.byte()?;
        let major = b >> 5;
        let a = b & 31;
        let n = self.uint(a)?;
        let value = match (major, n) {
            (0, Some(n)) => Value::Int(i128::from(n)),
            (1, Some(n)) => Value::Int(-1 - i128::from(n)),
            (2, Some(n)) => {
                let count = self.length(n)?;
                let end = self
                    .pos
                    .checked_add(count)
                    .ok_or(FixtureError("CBOR length overflow"))?;
                let b = self
                    .raw
                    .get(self.pos..end)
                    .ok_or(FixtureError("truncated CBOR bytes"))?
                    .to_vec();
                self.pos = end;
                Value::Bytes(b)
            }
            (2, None) => {
                let mut bytes = Vec::new();
                while self.raw.get(self.pos) != Some(&255) {
                    let next = *self
                        .raw
                        .get(self.pos)
                        .ok_or(FixtureError("truncated CBOR bytes"))?;
                    if next >> 5 != 2 || next & 31 == 31 {
                        return Err(FixtureError("invalid indefinite byte chunk"));
                    }
                    let part = self.item(depth + 1)?;
                    bytes.extend_from_slice(part.bytes()?);
                    if bytes.len() > 65536 {
                        return Err(FixtureError("CBOR bytes too large"));
                    }
                }
                self.pos += 1;
                Value::Bytes(bytes)
            }
            (4, n) => {
                let count = n.map(|n| self.length(n)).transpose()?;
                let mut items = Vec::new();
                while if let Some(n) = count {
                    items.len() < n
                } else {
                    self.raw.get(self.pos) != Some(&255)
                } {
                    items.push(self.item(depth + 1)?);
                }
                if count.is_none() {
                    self.pos += 1;
                }
                Value::Array(items)
            }
            (5, n) => {
                let count = n.map(|n| self.length(n)).transpose()?;
                let mut items: Vec<(Node, Node)> = Vec::new();
                while if let Some(n) = count {
                    items.len() < n
                } else {
                    self.raw.get(self.pos) != Some(&255)
                } {
                    if items.len() >= 128 {
                        return Err(FixtureError("CBOR map limit"));
                    }
                    let key = self.item(depth + 1)?;
                    if items.iter().any(|(k, _)| k == &key) {
                        return Err(FixtureError("duplicate CBOR map key"));
                    }
                    let value = self.item(depth + 1)?;
                    items.push((key, value));
                }
                if count.is_none() {
                    self.pos += 1;
                }
                Value::Map(items)
            }
            (6, Some(24)) => {
                let child = self.item(depth + 1)?;
                child.bytes()?;
                Value::Tag(24, Box::new(child))
            }
            (6, Some(n)) if n == 258 || (121..=127).contains(&n) || (1280..=1400).contains(&n) => {
                Value::Tag(n, Box::new(self.item(depth + 1)?))
            }
            (7, Some(20)) if a == 20 => Value::Bool(false),
            (7, Some(21)) if a == 21 => Value::Bool(true),
            (7, Some(22)) if a == 22 => Value::Null,
            _ => return Err(FixtureError("unsupported CBOR type")),
        };
        Ok(Node {
            start,
            end: self.pos,
            value,
        })
    }
}
