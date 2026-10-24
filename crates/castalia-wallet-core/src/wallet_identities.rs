//! Portable, descriptor-only account associations. No login, key or control proof.
use serde_json::{Value, json};
use std::collections::BTreeSet;

type Result<T> = std::result::Result<T, &'static str>;
pub const SCHEMA: &str = "castalia.wallet-identities.v1";

pub fn empty(owner: &str) -> Value {
    json!({"schema":SCHEMA,"version":1,"ownerMemberKey":owner,"authority":"descriptor-only","accounts":[]})
}
fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("invalid_wallet_identities")?;
    if object.len() != fields.len() || fields.iter().any(|f| !object.contains_key(*f)) {
        return Err("unsupported_identity_fields");
    }
    Ok(())
}
fn text(value: &Value, max: usize, allow_empty: bool) -> Result<&str> {
    value.as_str().filter(|s| s.len() <= max && (allow_empty || !s.is_empty()) &&
        !s.chars().any(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')))
        .ok_or("invalid_identity_text")
}
fn hex_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn endpoint(value: &str, scheme: &str, origin: bool) -> bool {
    let Some((prefix, rest)) = value.split_once("://") else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(scheme)
        || value.contains('\\')
        || rest
            .split('/')
            .next()
            .is_some_and(|authority| authority.contains('@'))
    {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == scheme
        && url.port() != Some(0)
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && (!origin || url.path() == "/")
}
fn matrix_identifier(value: &str) -> bool {
    let Some((local, server)) = value.strip_prefix('@').and_then(|s| s.split_once(':')) else {
        return false;
    };
    if local.is_empty()
        || local
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, ':' | '@' | '/'))
    {
        return false;
    }
    let (host, port) = server
        .split_once(':')
        .map_or((server, None), |(h, p)| (h, Some(p)));
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && port.is_none_or(|p| {
            !p.is_empty()
                && p.len() <= 5
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n > 0)
        })
}

/// Validates the closed public allowlist and returns a deterministic account order.
pub fn validate(value: &Value, owner: &str) -> Result<Value> {
    if serde_json::to_vec(value)
        .map_err(|_| "invalid_wallet_identities")?
        .len()
        > 1_048_576
    {
        return Err("identities_too_large");
    }
    exact(
        value,
        &[
            "schema",
            "version",
            "ownerMemberKey",
            "authority",
            "accounts",
        ],
    )?;
    if !hex_key(owner)
        || value["schema"] != SCHEMA
        || value["version"] != 1
        || value["ownerMemberKey"] != owner
        || value["authority"] != "descriptor-only"
    {
        return Err("invalid_wallet_identities");
    }
    let mut accounts = value["accounts"]
        .as_array()
        .filter(|a| a.len() <= 100)
        .ok_or("identity_limit")?
        .clone();
    let mut ids = BTreeSet::new();
    let mut subjects = BTreeSet::new();
    for account in &accounts {
        exact(
            account,
            &["accountId", "kind", "label", "identifier", "server"],
        )?;
        let id = text(&account["accountId"], 36, false)?;
        let kind = text(&account["kind"], 16, false)?;
        text(&account["label"], 100, false)?;
        let identifier = text(&account["identifier"], 320, false)?;
        let server = text(&account["server"], 500, true)?;
        if !uuid(id) || !ids.insert(id) || !subjects.insert((kind, identifier)) {
            return Err("duplicate_or_invalid_identity");
        }
        let valid = match kind {
            "matrix" => matrix_identifier(identifier) && endpoint(server, "https", true),
            "nostr" => hex_key(identifier) && (server.is_empty() || endpoint(server, "wss", false)),
            "github" | "x" => {
                server.is_empty()
                    && identifier.len() <= 40
                    && !identifier.starts_with('0')
                    && identifier.bytes().all(|b| b.is_ascii_digit())
            }
            _ => false,
        };
        if !valid {
            return Err("invalid_provider_identity");
        }
    }
    accounts.sort_by(|a, b| a["accountId"].as_str().cmp(&b["accountId"].as_str()));
    let mut result = value.clone();
    result["accounts"] = json!(accounts);
    Ok(result)
}

/// Import is additive and idempotent. Conflicting IDs or associations need review.
pub fn merge(current: &Value, incoming: &Value, owner: &str) -> Result<Value> {
    let mut result = validate(current, owner)?;
    let incoming = validate(incoming, owner)?;
    let accounts = result["accounts"]
        .as_array_mut()
        .ok_or("invalid_wallet_identities")?;
    for record in incoming["accounts"]
        .as_array()
        .ok_or("invalid_wallet_identities")?
    {
        if let Some(old) = accounts
            .iter()
            .find(|a| a["accountId"] == record["accountId"])
        {
            if old != record {
                return Err("identity_conflict");
            }
        } else {
            if accounts
                .iter()
                .any(|a| a["kind"] == record["kind"] && a["identifier"] == record["identifier"])
            {
                return Err("identity_conflict");
            }
            accounts.push(record.clone());
        }
    }
    validate(&result, owner)
}
