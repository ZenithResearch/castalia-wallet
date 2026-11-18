//! Frozen A3 public codec and A4 trust paths. Opt-in synthetic qualification only.
//! No key import, generic signing, ledger resolution, or production consent API.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub type Result<T> = std::result::Result<T, &'static str>;
pub const MAX_JSON_BYTES: usize = 65536;
pub fn parse(raw: &str) -> Result<Value> {
    if raw.len() > MAX_JSON_BYTES {
        return Err("Marsh input too large");
    }
    crate::portable::parse_unique(raw)
}
fn exact(v: &Value, keys: &[&str]) -> Result<()> {
    let obj = v.as_object().ok_or("expected object")?;
    if obj.len() != keys.len() || keys.iter().any(|k| !obj.contains_key(*k)) {
        return Err("unsupported fields");
    }
    Ok(())
}
fn eq(v: &Value, s: &str) -> Result<()> {
    if v.as_str() == Some(s) {
        Ok(())
    } else {
        Err("unsupported value")
    }
}
fn raw(v: &Value, max: usize, size: Option<usize>) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or("expected hex")?;
    if s.len() > max * 2
        || s.len() % 2 != 0
        || size.is_some_and(|n| s.len() != n * 2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid hex");
    }
    hex::decode(s).map_err(|_| "invalid hex")
}
fn id(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or("invalid identifier")?;
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if s.is_empty()
        || s.len() > 64
        || !alnum(s.as_bytes()[0])
        || !alnum(*s.as_bytes().last().unwrap())
        || !s.bytes().all(|b| alnum(b) || b == b'.' || b == b'-')
    {
        return Err("invalid identifier");
    }
    Ok(s)
}
fn u32le(v: &Value) -> Result<[u8; 4]> {
    Ok(u32::try_from(v.as_u64().ok_or("invalid u32")?)
        .map_err(|_| "invalid u32")?
        .to_le_bytes())
}
fn u64le(v: &Value) -> Result<[u8; 8]> {
    let s = v.as_str().ok_or("invalid u64")?;
    if s.is_empty()
        || s.len() > 20
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid u64");
    }
    Ok(s.parse::<u64>().map_err(|_| "invalid u64")?.to_le_bytes())
}
fn frame(out: &mut Vec<u8>, b: &[u8]) {
    out.extend((b.len() as u32).to_le_bytes());
    out.extend(b);
}
pub(crate) fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn sig(v: &Value) -> Result<[u8; 64]> {
    let s = v.as_str().ok_or("invalid signature")?;
    if s.len() != 86 {
        return Err("invalid signature");
    }
    let b = B64.decode(s).map_err(|_| "invalid signature")?;
    if B64.encode(&b) != s {
        return Err("noncanonical signature");
    }
    b.try_into().map_err(|_| "invalid signature")
}
fn key(b: &[u8]) -> Result<VerifyingKey> {
    let mut y: [u8; 32] = b.try_into().map_err(|_| "invalid key")?;
    y[31] &= 127;
    let mut p = [255u8; 32];
    p[0] = 237;
    p[31] = 127;
    if y.iter().rev().cmp(p.iter().rev()) != std::cmp::Ordering::Less {
        return Err("noncanonical point");
    }
    let vk = VerifyingKey::from_bytes(b.try_into().map_err(|_| "invalid key")?)
        .map_err(|_| "invalid point")?;
    if vk.is_weak() {
        return Err("weak point");
    }
    Ok(vk)
}
fn verify(key_bytes: &[u8], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    key(&signature[..32])?;
    key(key_bytes)?
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| "invalid signature")
}
pub fn issuer_transcript(c: &Value) -> Result<Vec<u8>> {
    exact(
        c,
        &[
            "schema",
            "version",
            "membershipId",
            "ownerPublicKey",
            "status",
            "issuerId",
            "issuerKeyId",
            "signatureSuite",
            "issuerSignature",
        ],
    )?;
    eq(&c["schema"], "castalia.zenith-membership-credential.v3")?;
    if c["version"].as_u64() != Some(3) {
        return Err("unsupported version");
    }
    eq(&c["status"], "active")?;
    eq(&c["signatureSuite"], "Ed25519")?;
    let owner = raw(&c["ownerPublicKey"], 32, Some(32))?;
    let membership = raw(&c["membershipId"], 32, Some(32))?;
    let mut identity = b"castalia/zenith-membership-id/v3\0".to_vec();
    identity.extend(&owner);
    if hash(&identity).as_slice() != membership {
        return Err("membership identity mismatch");
    }
    sig(&c["issuerSignature"])?;
    let mut b = b"castalia/zenith-membership-credential/v3\0".to_vec();
    b.extend(3u64.to_le_bytes());
    b.extend(membership);
    b.extend(owner);
    for s in [
        "active",
        id(&c["issuerId"])?,
        id(&c["issuerKeyId"])?,
        "ed25519",
    ] {
        frame(&mut b, s.as_bytes());
    }
    Ok(b)
}
pub fn credential_commitment(c: &Value) -> Result<[u8; 32]> {
    let mut b = b"castalia/marsh-creation-credential/v1\0".to_vec();
    frame(&mut b, &issuer_transcript(c)?);
    b.extend(sig(&c["issuerSignature"])?);
    Ok(hash(&b))
}
pub(crate) fn deployment(d: &Value) -> Result<Vec<u8>> {
    exact(d, &["network", "discriminator"])?;
    let n = &d["network"];
    exact(n, &["family", "id", "genesisKind", "genesisDigest"])?;
    exact(&n["id"], &["kind", "magic"])?;
    eq(&n["family"], "Cardano")?;
    eq(&n["id"]["kind"], "testnet")?;
    eq(&n["genesisKind"], "shelley-genesis-raw-json-blake2b256")?;
    let mut b = vec![1];
    b.extend(u32le(&n["id"]["magic"])?);
    b.push(1);
    b.extend(raw(&n["genesisDigest"], 32, Some(32))?);
    b.extend(raw(&d["discriminator"], 32, Some(32))?);
    Ok(b)
}
fn credential(v: &Value) -> Result<Vec<u8>> {
    exact(v, &["kind", "hash"])?;
    let mut b = vec![match v["kind"].as_str() {
        Some("key") => 0,
        Some("script") => 1,
        _ => return Err("invalid address credential"),
    }];
    b.extend(raw(&v["hash"], 28, Some(28))?);
    Ok(b)
}
fn address(v: &Value) -> Result<Vec<u8>> {
    exact(v, &["payment", "stake"])?;
    let mut b = credential(&v["payment"])?;
    let s = &v["stake"];
    match s["kind"].as_str() {
        Some("none") => {
            exact(s, &["kind"])?;
            b.push(0);
        }
        Some("inline") => {
            exact(s, &["kind", "credential"])?;
            b.push(1);
            b.extend(credential(&s["credential"])?);
        }
        Some("pointer") => {
            exact(s, &["kind", "slot", "transactionIndex", "certificateIndex"])?;
            b.push(2);
            for k in ["slot", "transactionIndex", "certificateIndex"] {
                b.extend(u64le(&s[k])?);
            }
        }
        _ => return Err("invalid stake"),
    }
    Ok(b)
}
fn items(v: &Value) -> Result<&Vec<Value>> {
    let a = v.as_array().ok_or("expected array")?;
    if a.len() > 64 {
        return Err("too many Data children");
    }
    Ok(a)
}
fn data(v: &Value, depth: usize, nodes: &mut usize, b: &mut Vec<u8>) -> Result<()> {
    *nodes += 1;
    if depth > 16 || *nodes > 128 {
        return Err("Data structure bound");
    }
    match v["kind"].as_str() {
        Some("int") => {
            exact(v, &["kind", "value"])?;
            let s = v["value"].as_str().ok_or("invalid Data integer")?;
            let negative = s.starts_with('-');
            let n = if negative { &s[1..] } else { s };
            if s.len() > 79
                || n.is_empty()
                || !n.bytes().all(|x| x.is_ascii_digit())
                || (n.starts_with('0') && (n.len() > 1 || negative))
            {
                return Err("invalid Data integer");
            }
            let mut mag = vec![];
            for digit in n.bytes() {
                let mut carry = (digit - b'0') as u16;
                for byte in mag.iter_mut().rev() {
                    let x = (*byte as u16) * 10 + carry;
                    *byte = x as u8;
                    carry = x >> 8;
                }
                if carry > 0 {
                    mag.insert(0, carry as u8);
                }
                if mag.len() > 32 {
                    return Err("integer bound");
                }
            }
            b.extend([0, negative as u8, mag.len() as u8]);
            b.extend(mag);
        }
        Some("bytes") => {
            exact(v, &["kind", "hex"])?;
            let bytes = raw(&v["hex"], 2048, None)?;
            b.push(1);
            b.extend((bytes.len() as u16).to_le_bytes());
            b.extend(bytes);
        }
        Some("list") => {
            exact(v, &["kind", "items"])?;
            let a = items(&v["items"])?;
            b.push(2);
            b.extend((a.len() as u16).to_le_bytes());
            for x in a {
                data(x, depth + 1, nodes, b)?;
            }
        }
        Some("map") => {
            exact(v, &["kind", "entries"])?;
            let a = items(&v["entries"])?;
            b.push(3);
            b.extend((a.len() as u16).to_le_bytes());
            let mut keys = BTreeSet::new();
            for x in a {
                let pair = x
                    .as_array()
                    .filter(|x| x.len() == 2)
                    .ok_or("invalid Data pair")?;
                let start = b.len();
                data(&pair[0], depth + 1, nodes, b)?;
                if !keys.insert(b[start..].to_vec()) {
                    return Err("duplicate Data key");
                }
                data(&pair[1], depth + 1, nodes, b)?;
            }
        }
        Some("constructor") => {
            exact(v, &["kind", "index", "fields"])?;
            let a = items(&v["fields"])?;
            b.push(4);
            b.extend(u64le(&v["index"])?);
            b.extend((a.len() as u16).to_le_bytes());
            for x in a {
                data(x, depth + 1, nodes, b)?;
            }
        }
        _ => return Err("unsupported Data"),
    }
    if b.len() > 2048 {
        return Err("Data byte bound");
    }
    Ok(())
}
pub fn holder_transcript(c: &Value, proof: &Value) -> Result<Vec<u8>> {
    exact(
        c,
        &[
            "interface",
            "deployment",
            "seed",
            "initialController",
            "initialSecondary",
            "initialReceiver",
            "fixedKettle",
        ],
    )?;
    eq(&c["interface"], "castalia.marsh-creation-authority.v1")?;
    let mut b = b"castalia/marsh-creation-holder/v1\0".to_vec();
    b.extend(credential_commitment(proof)?);
    b.extend(deployment(&c["deployment"])?);
    exact(&c["seed"], &["transactionId", "outputIndex"])?;
    b.extend(raw(&c["seed"]["transactionId"], 32, Some(32))?);
    b.extend(u32le(&c["seed"]["outputIndex"])?);
    let controller = raw(&c["initialController"], 28, Some(28))?;
    b.extend(&controller);
    let s = &c["initialSecondary"];
    match s["kind"].as_str() {
        Some("absent") => {
            exact(s, &["kind"])?;
            b.push(0);
        }
        Some("present") => {
            exact(s, &["kind", "paymentKeyHash"])?;
            let k = raw(&s["paymentKeyHash"], 28, Some(28))?;
            if k == controller {
                return Err("secondary equals controller");
            }
            b.push(1);
            b.extend(k);
        }
        _ => return Err("invalid secondary"),
    }
    let r = &c["initialReceiver"];
    exact(r, &["address", "datum"])?;
    b.extend(address(&r["address"])?);
    let d = &r["datum"];
    match d["kind"].as_str() {
        Some("none") => {
            exact(d, &["kind"])?;
            b.push(0);
        }
        Some("hash") => {
            exact(d, &["kind", "hash"])?;
            b.push(1);
            b.extend(raw(&d["hash"], 32, Some(32))?);
        }
        Some("inline") => {
            exact(d, &["kind", "value"])?;
            let mut encoded = vec![];
            data(&d["value"], 1, &mut 0, &mut encoded)?;
            b.push(2);
            b.extend((encoded.len() as u16).to_le_bytes());
            b.extend(encoded);
        }
        _ => return Err("invalid datum"),
    }
    let k = &c["fixedKettle"];
    exact(k, &["stateToken", "stateAddress"])?;
    exact(&k["stateToken"], &["policyId", "assetName"])?;
    b.extend(raw(&k["stateToken"]["policyId"], 28, Some(28))?);
    let name = raw(&k["stateToken"]["assetName"], 32, None)?;
    b.push(name.len() as u8);
    b.extend(name);
    b.extend(address(&k["stateAddress"])?);
    if b.len() > 2459 {
        return Err("holder byte bound");
    }
    Ok(b)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustCommitment {
    pub count: u8,
    pub commitment: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TrustPath {
    pub index: u8,
    pub candidate_key: String,
    pub siblings: Vec<String>,
}
fn leaf(index: u8, issuer: &str, kid: &str, key: &[u8]) -> [u8; 32] {
    let mut b = b"castalia/marsh-membership-root-leaf/v1\0".to_vec();
    b.push(index);
    frame(&mut b, issuer.as_bytes());
    frame(&mut b, kid.as_bytes());
    b.extend(key);
    hash(&b)
}
fn branch(height: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut b = b"castalia/marsh-membership-root-branch/v1\0".to_vec();
    b.push(height);
    b.extend(left);
    b.extend(right);
    hash(&b)
}
fn commit(count: u8, root: &[u8; 32]) -> TrustCommitment {
    let mut b = b"castalia/marsh-membership-roots/v1\0".to_vec();
    b.push(count);
    b.extend(root);
    TrustCommitment {
        count,
        commitment: hex::encode(hash(&b)),
    }
}
fn roots(policy: &Value) -> Result<Vec<&Value>> {
    exact(policy, &["schema", "version", "roots"])?;
    eq(
        &policy["schema"],
        "castalia.zenith-membership-trust-policy.v1",
    )?;
    if policy["version"].as_u64() != Some(1) {
        return Err("invalid trust version");
    }
    let mut roots: Vec<_> = policy["roots"]
        .as_array()
        .ok_or("invalid roots")?
        .iter()
        .collect();
    if roots.is_empty() || roots.len() > 128 {
        return Err("trust count bound");
    }
    let mut seen = BTreeSet::new();
    for r in &roots {
        exact(r, &["issuerId", "keyId", "signatureSuite", "publicKey"])?;
        let tuple = (id(&r["issuerId"])?, id(&r["keyId"])?);
        if !seen.insert(tuple) {
            return Err("duplicate trust tuple");
        }
        eq(&r["signatureSuite"], "Ed25519")?;
        key(&raw(&r["publicKey"], 32, Some(32))?)?;
    }
    roots.sort_by(|a, b| {
        (a["issuerId"].as_str(), a["keyId"].as_str())
            .cmp(&(b["issuerId"].as_str(), b["keyId"].as_str()))
    });
    Ok(roots)
}
pub fn trust_path(policy: &Value, issuer: &str, kid: &str) -> Result<(TrustCommitment, TrustPath)> {
    let roots = roots(policy)?;
    let index = roots
        .iter()
        .position(|r| r["issuerId"] == issuer && r["keyId"] == kid)
        .ok_or("untrusted issuer")?;
    let mut level = Vec::with_capacity(128);
    for i in 0..128 {
        level.push(if let Some(r) = roots.get(i) {
            leaf(
                i as u8,
                id(&r["issuerId"])?,
                id(&r["keyId"])?,
                &raw(&r["publicKey"], 32, Some(32))?,
            )
        } else {
            let mut b = b"castalia/marsh-membership-root-empty/v1\0".to_vec();
            b.push(i as u8);
            hash(&b)
        });
    }
    let mut current = index;
    let mut siblings = vec![];
    for height in 1..=7 {
        siblings.push(hex::encode(level[current ^ 1]));
        level = level
            .chunks_exact(2)
            .map(|p| branch(height, &p[0], &p[1]))
            .collect();
        current >>= 1;
    }
    Ok((
        commit(roots.len() as u8, &level[0]),
        TrustPath {
            index: index as u8,
            candidate_key: roots[index]["publicKey"].as_str().unwrap().into(),
            siblings,
        },
    ))
}
pub fn trust_commitment(policy: &Value) -> Result<TrustCommitment> {
    let r = roots(policy)?;
    Ok(trust_path(policy, id(&r[0]["issuerId"])?, id(&r[0]["keyId"])?)?.0)
}
pub fn verify_trust_path(c: &Value, p: &TrustPath, admitted: &TrustCommitment) -> Result<()> {
    if admitted.count == 0
        || admitted.count > 128
        || p.index >= admitted.count
        || p.siblings.len() != 7
    {
        return Err("invalid trust path");
    }
    let candidate = raw(&Value::String(p.candidate_key.clone()), 32, Some(32))?;
    key(&candidate)?;
    let mut h = leaf(
        p.index,
        id(&c["issuerId"])?,
        id(&c["issuerKeyId"])?,
        &candidate,
    );
    let mut index = p.index;
    for (i, s) in p.siblings.iter().enumerate() {
        let sibling: [u8; 32] = raw(&Value::String(s.clone()), 32, Some(32))?
            .try_into()
            .unwrap();
        h = if index & 1 == 0 {
            branch((i + 1) as u8, &h, &sibling)
        } else {
            branch((i + 1) as u8, &sibling, &h)
        };
        index >>= 1;
    }
    if commit(admitted.count, &h) != *admitted {
        return Err("trust commitment mismatch");
    }
    Ok(())
}
pub fn verify_creation(context: &Value, proof: &Value, admission: &Value) -> Result<()> {
    exact(admission, &["deployment", "membershipTrustPolicy"])?;
    exact(proof, &["schema", "credential", "holderSignature"])?;
    eq(&proof["schema"], "castalia.marsh-creation-proof.v1")?;
    if deployment(&context["deployment"])? != deployment(&admission["deployment"])? {
        return Err("deployment mismatch");
    }
    let c = &proof["credential"];
    let message = holder_transcript(context, c)?;
    let (_, path) = trust_path(
        &admission["membershipTrustPolicy"],
        id(&c["issuerId"])?,
        id(&c["issuerKeyId"])?,
    )?;
    verify(
        &raw(&Value::String(path.candidate_key), 32, Some(32))?,
        &issuer_transcript(c)?,
        &sig(&c["issuerSignature"])?,
    )?;
    verify(
        &raw(&c["ownerPublicKey"], 32, Some(32))?,
        &message,
        &sig(&proof["holderSignature"])?,
    )
}
