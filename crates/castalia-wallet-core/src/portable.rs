//! Portable data contract, ported from the checksum-pinned public Web contracts.
//! Trust is supplied separately. Files can never add trusted issuers or authority.
use crate::OpenedWallet;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;
pub type Result<T> = std::result::Result<T, &'static str>;
const MAX: usize = 1_048_576;
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub v3: Option<Value>,
    pub v4: Option<Value>,
}

pub fn parse_unique(raw: &str) -> Result<Value> {
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON without duplicate fields")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(json!(v)))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut v = vec![];
                    while let Some(Unique(x)) = a.next_element()? {
                        v.push(x)
                    }
                    Ok(Unique(Value::Array(v)))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut m = serde_json::Map::new();
                    while let Some((k, Unique(v))) = a.next_entry::<String, Unique>()? {
                        if m.insert(k, v).is_some() {
                            return Err(serde::de::Error::custom("duplicate_field"));
                        }
                    }
                    Ok(Unique(Value::Object(m)))
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    if raw.len() > MAX * 3 {
        return Err("file_too_large");
    }
    serde_json::from_str::<Unique>(raw)
        .map(|v| v.0)
        .map_err(|_| "invalid_json")
}
fn exact(v: &Value, keys: &[&str]) -> Result<()> {
    let m = v.as_object().ok_or("invalid_contents")?;
    if m.len() != keys.len() || keys.iter().any(|k| !m.contains_key(*k)) {
        return Err("unsupported_fields");
    }
    Ok(())
}
fn eq(v: &Value, s: &str) -> Result<()> {
    if v.as_str() == Some(s) {
        Ok(())
    } else {
        Err("invalid_contents")
    }
}
fn text(v: &Value, max: usize) -> Result<&str> {
    v.as_str()
        .filter(|s| s.encode_utf16().count() <= max)
        .ok_or("invalid_contents")
}
fn number(v: &Value) -> Result<u64> {
    v.as_u64()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or("invalid_contents")
}
fn version(v: &Value, n: u64) -> Result<()> {
    if number(v)? == n {
        Ok(())
    } else {
        Err("unsupported_version")
    }
}
fn hex32(v: &Value) -> Result<[u8; 32]> {
    let s = text(v, 64)?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_identity");
    }
    hex::decode(s)
        .map_err(|_| "invalid_identity")?
        .try_into()
        .map_err(|_| "invalid_identity")
}
fn id(v: &Value) -> Result<&str> {
    let s = text(v, 64)?;
    if s.is_empty()
        || !s.as_bytes()[0].is_ascii_alphanumeric()
        || !s.as_bytes()[s.len() - 1].is_ascii_alphanumeric()
        || !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err("invalid_identifier");
    }
    Ok(s)
}
fn array(v: &Value, max: usize) -> Result<&Vec<Value>> {
    v.as_array()
        .filter(|a| a.len() <= max)
        .ok_or("invalid_contents")
}
fn disclosure(v: &Value) -> Result<()> {
    if matches!(v.as_str(), Some("private" | "selected")) {
        Ok(())
    } else {
        Err("invalid_disclosure")
    }
}
fn https(v: &Value) -> Result<()> {
    let s = text(v, 320)?;
    if s.is_empty() {
        return Ok(());
    }
    let u = url::Url::parse(s).map_err(|_| "invalid_url")?;
    if u.scheme() != "https" {
        return Err("invalid_url");
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn ordered(v: &Value, keys: &[&str]) -> Result<String> {
    let parts = keys
        .iter()
        .map(|k| {
            Ok(format!(
                "{}:{}",
                serde_json::to_string(k).map_err(|_| "encoding_failed")?,
                serde_json::to_string(&v[*k]).map_err(|_| "encoding_failed")?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(format!("{{{}}}", parts.join(",")))
}
fn genesis_scope(g: &Value) -> Result<String> {
    exact(g, &["schema", "version", "scopeType", "alias", "nonce"])?;
    eq(&g["schema"], "castalia.community-genesis.v1")?;
    version(&g["version"], 1)?;
    eq(&g["scopeType"], "community")?;
    id(&g["alias"])?;
    hex32(&g["nonce"])?;
    Ok(digest(
        format!(
            "castalia/community-id/v1\0{}",
            ordered(g, &["schema", "version", "scopeType", "alias", "nonce"])?
        )
        .as_bytes(),
    ))
}
fn roots(policy: &Value) -> Result<()> {
    let roots = array(&policy["roots"], 128)?;
    if roots.is_empty() {
        return Err("trust_setup_required");
    }
    let mut seen = BTreeSet::new();
    for r in roots {
        exact(r, &["issuerId", "keyId", "signatureSuite", "publicKey"])?;
        let issuer = id(&r["issuerId"])?;
        let key = id(&r["keyId"])?;
        eq(&r["signatureSuite"], "Ed25519")?;
        hex32(&r["publicKey"])?;
        if !seen.insert((issuer, key)) {
            return Err("duplicate_trust");
        }
    }
    Ok(())
}
impl Trust {
    pub fn validate(&self) -> Result<()> {
        if let Some(p) = &self.v3 {
            exact(p, &["schema", "version", "roots"])?;
            eq(&p["schema"], "castalia.zenith-membership-trust-policy.v1")?;
            version(&p["version"], 1)?;
            roots(p)?;
        }
        if let Some(p) = &self.v4 {
            exact(p, &["schema", "version", "roots", "scopes"])?;
            eq(&p["schema"], "castalia.scoped-membership-trust-policy.v1")?;
            version(&p["version"], 1)?;
            roots(p)?;
            let scopes = array(&p["scopes"], 128)?;
            if scopes.is_empty() {
                return Err("trust_setup_required");
            }
            let mut seen = BTreeSet::new();
            for s in scopes {
                exact(s, &["scopeId", "genesis", "issuerIds"])?;
                hex32(&s["scopeId"])?;
                eq(&s["scopeId"], &genesis_scope(&s["genesis"])?)?;
                if !seen.insert(text(&s["scopeId"], 64)?) {
                    return Err("duplicate_trust");
                }
                let issuers = array(&s["issuerIds"], 128)?;
                if issuers.is_empty() {
                    return Err("trust_setup_required");
                }
                let mut unique = BTreeSet::new();
                for i in issuers {
                    if !unique.insert(id(i)?) {
                        return Err("duplicate_trust");
                    }
                }
            }
        }
        Ok(())
    }
}
pub fn verify_proof(proof: &Value, owner: &str, trust: &Trust, scoped: bool) -> Result<()> {
    trust.validate()?;
    let mut keys = vec![
        "schema",
        "version",
        "membershipId",
        "ownerPublicKey",
        "status",
        "issuerId",
        "issuerKeyId",
        "signatureSuite",
        "issuerSignature",
    ];
    if scoped {
        keys.extend(["scopeType", "scopeId"])
    }
    exact(proof, &keys)?;
    eq(
        &proof["schema"],
        if scoped {
            "castalia.scoped-membership-credential.v4"
        } else {
            "castalia.zenith-membership-credential.v3"
        },
    )?;
    version(&proof["version"], if scoped { 4 } else { 3 })?;
    eq(&proof["ownerPublicKey"], owner)?;
    let owner_bytes = hex32(&proof["ownerPublicKey"])?;
    hex32(&proof["membershipId"])?;
    eq(&proof["status"], "active")?;
    eq(&proof["signatureSuite"], "Ed25519")?;
    let issuer = id(&proof["issuerId"])?;
    let key = id(&proof["issuerKeyId"])?;
    let policy = if scoped {
        trust.v4.as_ref()
    } else {
        trust.v3.as_ref()
    }
    .ok_or("trust_setup_required")?;
    let mut id_bytes = if scoped {
        b"castalia/scoped-membership-id/v4\0".to_vec()
    } else {
        b"castalia/zenith-membership-id/v3\0".to_vec()
    };
    id_bytes.extend(owner_bytes);
    if scoped {
        eq(&proof["scopeType"], "community")?;
        id_bytes.extend(hex32(&proof["scopeId"])?);
        let s = array(&policy["scopes"], 128)?
            .iter()
            .find(|s| s["scopeId"] == proof["scopeId"])
            .ok_or("trust_setup_required")?;
        if !array(&s["issuerIds"], 128)?
            .iter()
            .any(|v| v.as_str() == Some(issuer))
        {
            return Err("untrusted_issuer");
        }
    }
    eq(&proof["membershipId"], &digest(&id_bytes))?;
    let root = array(&policy["roots"], 128)?
        .iter()
        .find(|r| r["issuerId"] == proof["issuerId"] && r["keyId"] == proof["issuerKeyId"])
        .ok_or("untrusted_issuer")?;
    let transcript = if scoped {
        format!(
            "castalia/scoped-membership-credential/v4\0{}",
            ordered(
                proof,
                &[
                    "schema",
                    "version",
                    "scopeType",
                    "scopeId",
                    "membershipId",
                    "ownerPublicKey",
                    "status",
                    "issuerId",
                    "issuerKeyId",
                    "signatureSuite"
                ]
            )?
        )
        .into_bytes()
    } else {
        let mut bytes = b"castalia/zenith-membership-credential/v3\0".to_vec();
        bytes.extend(3u64.to_le_bytes());
        bytes.extend(hex32(&proof["membershipId"])?);
        bytes.extend(owner_bytes);
        for s in ["active", issuer, key, "ed25519"] {
            bytes.extend((s.len() as u32).to_le_bytes());
            bytes.extend(s.as_bytes())
        }
        bytes
    };
    let signature = crate::decode_exact::<64>(text(&proof["issuerSignature"], 86)?)
        .map_err(|_| "invalid_signature")?;
    VerifyingKey::from_bytes(&hex32(&root["publicKey"])?)
        .map_err(|_| "invalid_signature")?
        .verify_strict(&transcript, &Signature::from_bytes(&signature))
        .map_err(|_| "invalid_signature")
}
fn identity(v: &Value, owner: &str) -> Result<()> {
    exact(v, &["schema", "version", "subject", "updatedAt"])?;
    eq(&v["schema"], "zenith.identity-section.v1")?;
    version(&v["version"], 1)?;
    number(&v["updatedAt"])?;
    let s = &v["subject"];
    exact(
        s,
        &[
            "type",
            "memberKey",
            "fields",
            "roles",
            "affiliations",
            "journals",
        ],
    )?;
    eq(&s["type"], "Person")?;
    eq(&s["memberKey"], owner)?;
    let fields = &s["fields"];
    let names = [
        "displayName",
        "givenName",
        "familyName",
        "headline",
        "biography",
        "website",
        "orcid",
    ];
    exact(fields, &names)?;
    for name in names {
        let claim = &fields[name];
        exact(claim, &["value", "disclosure"])?;
        text(
            &claim["value"],
            if name == "biography" { 4000 } else { 320 },
        )?;
        disclosure(&claim["disclosure"])?;
    }
    https(&fields["website"]["value"])?;
    let orcid = text(&fields["orcid"]["value"], 320)?;
    if !orcid.is_empty()
        && (orcid.len() != 19
            || !orcid.bytes().enumerate().all(|(i, b)| {
                if [4, 9, 14].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (i == 18 && b == b'X')
                }
            }))
    {
        return Err("invalid_orcid");
    }
    let mut roles = BTreeSet::new();
    for role in array(&s["roles"], 12)? {
        exact(role, &["role", "disclosure"])?;
        let r = text(&role["role"], 80)?;
        if r.is_empty()
            || r.trim() != r
            || r.nfc().collect::<String>() != r
            || r.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
            || !roles.insert(r.to_lowercase())
        {
            return Err("invalid_role");
        }
        disclosure(&role["disclosure"])?;
    }
    for a in array(&s["affiliations"], 12)? {
        exact(
            a,
            &[
                "type",
                "name",
                "department",
                "position",
                "identifier",
                "website",
                "disclosure",
            ],
        )?;
        eq(&a["type"], "AcademicInstitution")?;
        for f in ["name", "department", "position", "identifier"] {
            text(&a[f], 240)?;
        }
        https(&a["website"])?;
        disclosure(&a["disclosure"])?;
    }
    for j in array(&s["journals"], 24)? {
        exact(
            j,
            &[
                "type",
                "name",
                "relationship",
                "identifier",
                "website",
                "disclosure",
            ],
        )?;
        eq(&j["type"], "Journal")?;
        if !matches!(
            j["relationship"].as_str(),
            Some("Author" | "Editor" | "Reviewer" | "Contributor")
        ) {
            return Err("invalid_relationship");
        }
        text(&j["name"], 240)?;
        text(&j["identifier"], 240)?;
        https(&j["website"])?;
        disclosure(&j["disclosure"])?;
    }
    Ok(())
}
pub fn validate(wallet: &OpenedWallet, contents: &Value, trust: &Trust) -> Result<()> {
    validate_contents(wallet, contents, Some(trust))
}
/// Public data allowlist only. This never establishes issuer trust or membership.
pub fn validate_descriptors(wallet: &OpenedWallet, contents: &Value) -> Result<()> {
    validate_contents(wallet, contents, None)
}
fn validate_contents(wallet: &OpenedWallet, contents: &Value, trust: Option<&Trust>) -> Result<()> {
    if serde_json::to_vec(contents)
        .map_err(|_| "invalid_contents")?
        .len()
        > MAX
    {
        return Err("file_too_large");
    }
    exact(contents, &["schema", "version", "sections"])?;
    let v2 = contents_version(contents)? == 2;
    let sections = &contents["sections"];
    let mut keys = vec!["identity"];
    for k in ["memberships", "scopedMemberships", "chainAccounts"] {
        if sections.get(k).is_some() {
            keys.push(k)
        }
    }
    if v2 {
        keys.push("walletIdentities");
        crate::wallet_identities::validate(
            &sections["walletIdentities"],
            &wallet.public_key_hex(),
        )?;
    }
    exact(sections, &keys)?;
    identity(&sections["identity"], &wallet.public_key_hex())?;
    if let Some(accounts) = sections.get("chainAccounts") {
        // Derived descriptors are the authority-free allowlist; any extra key or
        // changed address/key/derivation fails exact equality against the core.
        let derived: Value =
            serde_json::from_str(&wallet.chain_accounts().map_err(|_| "invalid_accounts")?)
                .map_err(|_| "invalid_accounts")?;
        exact(
            accounts,
            &[
                "schema",
                "version",
                "ownerMemberKey",
                "authority",
                "recovery",
                "accounts",
            ],
        )?;
        for field in [
            "schema",
            "version",
            "ownerMemberKey",
            "authority",
            "recovery",
        ] {
            if accounts[field] != derived[field] {
                return Err("invalid_accounts");
            }
        }
        let mut seen = BTreeSet::new();
        for a in array(&accounts["accounts"], 8)? {
            if !array(&derived["accounts"], 8)?.contains(a)
                || !seen.insert(text(&a["accountId"], 64)?)
            {
                return Err("invalid_accounts");
            }
        }
    }
    for (field, scoped) in [("memberships", false), ("scopedMemberships", true)] {
        if let Some(proofs) = sections.get(field) {
            let mut ids = BTreeSet::new();
            let mut scopes = BTreeSet::new();
            for p in array(proofs, 16)? {
                if let Some(trust) = trust {
                    verify_proof(p, &wallet.public_key_hex(), trust, scoped)?;
                } else {
                    validate_proof_descriptor(p, &wallet.public_key_hex(), scoped)?;
                }
                if !ids.insert(text(&p["membershipId"], 64)?)
                    || (scoped && !scopes.insert(text(&p["scopeId"], 64)?))
                {
                    return Err("duplicate_proofs");
                }
            }
        }
    }
    Ok(())
}
pub fn empty_contents(wallet: &OpenedWallet, now: u64) -> Result<Value> {
    let mut fields = serde_json::Map::new();
    for k in [
        "displayName",
        "givenName",
        "familyName",
        "headline",
        "biography",
        "website",
        "orcid",
    ] {
        fields.insert(k.into(), json!({"value":"","disclosure":"private"}));
    }
    let accounts: Value =
        serde_json::from_str(&wallet.chain_accounts().map_err(|_| "invalid_accounts")?)
            .map_err(|_| "invalid_accounts")?;
    let c = json!({"schema":"castalia.castaway-contents.v1","version":1,"sections":{"identity":{"schema":"zenith.identity-section.v1","version":1,"subject":{"type":"Person","memberKey":wallet.public_key_hex(),"fields":fields,"roles":[],"affiliations":[],"journals":[]},"updatedAt":now},"chainAccounts":accounts}});
    validate(wallet, &c, &Trust::default())?;
    Ok(c)
}
pub fn import(wallet: &OpenedWallet, raw: &str, password: &str, trust: &Trust) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX {
        return Err("file_too_large");
    }
    let v = parse_unique(raw)?;
    exact(
        &v,
        &[
            "schema",
            "contentsSchema",
            "ownerPublicKey",
            "exportedAt",
            "kdf",
            "aead",
            "ciphertext",
        ],
    )?;
    let file_version = envelope_version(&v)?;
    eq(&v["ownerPublicKey"], &wallet.public_key_hex())?;
    number(&v["exportedAt"])?;
    exact(
        &v["kdf"],
        &[
            "name",
            "version",
            "salt",
            "memoryKiB",
            "iterations",
            "parallelism",
            "derivedKeyBytes",
        ],
    )?;
    for (k, n) in [
        ("version", 19),
        ("memoryKiB", 65536),
        ("iterations", 3),
        ("parallelism", 1),
        ("derivedKeyBytes", 32),
    ] {
        version(&v["kdf"][k], n)?;
    }
    eq(&v["kdf"]["name"], "Argon2id")?;
    exact(&v["aead"], &["name", "nonce", "tagBits"])?;
    eq(&v["aead"]["name"], "AES-256-GCM")?;
    version(&v["aead"]["tagBits"], 128)?;
    let salt =
        crate::decode_exact::<16>(text(&v["kdf"]["salt"], 22)?).map_err(|_| "invalid_file")?;
    let nonce =
        crate::decode_exact::<12>(text(&v["aead"]["nonce"], 16)?).map_err(|_| "invalid_file")?;
    let ciphertext = B64
        .decode(text(&v["ciphertext"], MAX)?)
        .map_err(|_| "invalid_file")?;
    let mut header = v.clone();
    header
        .as_object_mut()
        .ok_or("invalid_file")?
        .remove("ciphertext");
    let aad = serde_jcs::to_vec(&header).map_err(|_| "invalid_file")?;
    let key = crate::derive_key(password, &salt).map_err(|_| "invalid_file")?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| "invalid_file")?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "data_file_invalid")?,
    );
    let contents = parse_unique(std::str::from_utf8(&plain).map_err(|_| "invalid_file")?)?;
    validate(wallet, &contents, trust)?;
    if contents_version(&contents)? != file_version {
        return Err("contents_version_mismatch");
    }
    Ok(contents)
}
pub fn export(
    wallet: &OpenedWallet,
    contents: &Value,
    password: &str,
    now: u64,
    trust: &Trust,
) -> Result<Zeroizing<String>> {
    validate(wallet, contents, trust)?;
    if password.chars().count() < 12 {
        return Err("password_minimum_12");
    }
    let mut salt = [0; 16];
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut v = json!({"schema":"castalia.castaway.v1","contentsSchema":"castalia.castaway-contents.v1","ownerPublicKey":wallet.public_key_hex(),"exportedAt":now,"kdf":{"name":"Argon2id","version":19,"salt":B64.encode(salt),"memoryKiB":65536,"iterations":3,"parallelism":1,"derivedKeyBytes":32},"aead":{"name":"AES-256-GCM","nonce":B64.encode(nonce),"tagBits":128}});
    if contents_version(contents)? == 2 {
        v["schema"] = json!("castalia.castaway.v2");
        v["contentsSchema"] = json!("castalia.castaway-contents.v2");
    }
    number(&v["exportedAt"])?;
    let aad = serde_jcs::to_vec(&v).map_err(|_| "encoding_failed")?;
    let plain = Zeroizing::new(serde_jcs::to_vec(contents).map_err(|_| "encoding_failed")?);
    let key = crate::derive_key(password, &salt).map_err(|_| "export_failed")?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| "export_failed")?;
    v["ciphertext"] = json!(
        B64.encode(
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &plain,
                        aad: &aad
                    }
                )
                .map_err(|_| "export_failed")?
        )
    );
    let result = serde_jcs::to_string(&v).map_err(|_| "encoding_failed")?;
    if result.len() > MAX {
        return Err("file_too_large");
    }
    Ok(Zeroizing::new(result))
}

/// Frozen v1 remains strict. V2 is the public-descriptor extension.
pub fn contents_version(value: &Value) -> Result<u64> {
    match (value["schema"].as_str(), value["version"].as_u64()) {
        (Some("castalia.castaway-contents.v1"), Some(1)) => Ok(1),
        (Some("castalia.castaway-contents.v2"), Some(2)) => Ok(2),
        _ => Err("unsupported_version"),
    }
}
pub fn envelope_version(value: &Value) -> Result<u64> {
    match (value["schema"].as_str(), value["contentsSchema"].as_str()) {
        (Some("castalia.castaway.v1"), Some("castalia.castaway-contents.v1")) => Ok(1),
        (Some("castalia.castaway.v2"), Some("castalia.castaway-contents.v2")) => Ok(2),
        _ => Err("unsupported_version"),
    }
}
pub fn with_wallet_identities(contents: &Value, identities: &Value, owner: &str) -> Result<Value> {
    let mut next = contents.clone();
    next["sections"]["walletIdentities"] = crate::wallet_identities::validate(identities, owner)?;
    next["schema"] = json!("castalia.castaway-contents.v2");
    next["version"] = json!(2);
    Ok(next)
}

fn validate_proof_descriptor(proof: &Value, owner: &str, scoped: bool) -> Result<()> {
    let mut fields = vec![
        "schema",
        "version",
        "membershipId",
        "ownerPublicKey",
        "status",
        "issuerId",
        "issuerKeyId",
        "signatureSuite",
        "issuerSignature",
    ];
    if scoped {
        fields.extend(["scopeType", "scopeId"]);
    }
    exact(proof, &fields)?;
    eq(
        &proof["schema"],
        if scoped {
            "castalia.scoped-membership-credential.v4"
        } else {
            "castalia.zenith-membership-credential.v3"
        },
    )?;
    version(&proof["version"], if scoped { 4 } else { 3 })?;
    eq(&proof["ownerPublicKey"], owner)?;
    eq(&proof["status"], "active")?;
    eq(&proof["signatureSuite"], "Ed25519")?;
    id(&proof["issuerId"])?;
    id(&proof["issuerKeyId"])?;
    let mut bytes = if scoped {
        b"castalia/scoped-membership-id/v4\0".to_vec()
    } else {
        b"castalia/zenith-membership-id/v3\0".to_vec()
    };
    bytes.extend(hex32(&proof["ownerPublicKey"])?);
    if scoped {
        eq(&proof["scopeType"], "community")?;
        bytes.extend(hex32(&proof["scopeId"])?);
    }
    eq(&proof["membershipId"], &digest(&bytes))?;
    crate::decode_exact::<64>(text(&proof["issuerSignature"], 86)?)
        .map_err(|_| "invalid_signature")?;
    Ok(())
}
