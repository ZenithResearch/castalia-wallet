//! Closed, inert feed configuration. Validation grants no fetch or disclosure authority.
//! DNS resolution, public-address checks and activation remain accepting-host work.
use serde_json::Value;
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, &'static str>;
pub const SCHEMA: &str = "castalia.feeds-section.v1";
pub const MAX_SECTION_BYTES: usize = 256 * 1024;

fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("invalid_feeds")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("unsupported_feed_fields");
    }
    Ok(())
}

fn text(value: &Value, maximum: usize) -> Result<&str> {
    value
        .as_str()
        .filter(|text| text.len() <= maximum && !text.chars().any(char::is_control))
        .ok_or("invalid_feed_text")
}

fn uuid(value: &Value) -> Result<&str> {
    let id = text(value, 36)?;
    if id.len() != 36
        || !id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
        || !(b'1'..=b'8').contains(&id.as_bytes()[14])
        || !b"89ab".contains(&id.as_bytes()[19])
    {
        return Err("invalid_feed_id");
    }
    Ok(id)
}

fn array(value: &Value, maximum: usize) -> Result<&Vec<Value>> {
    value
        .as_array()
        .filter(|items| items.len() <= maximum)
        .ok_or("feed_limit")
}

fn endpoint(value: &Value) -> Result<()> {
    let raw = text(value, 2048)?;
    if !raw.starts_with("https://")
        || raw.chars().any(char::is_whitespace)
        || raw.contains('\\')
        || raw.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b'%'
                && !raw
                    .as_bytes()
                    .get(index + 1..index + 3)
                    .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
        })
    {
        return Err("invalid_feed_url");
    }
    let url = url::Url::parse(raw).map_err(|_| "invalid_feed_url")?;
    let Some(url::Host::Domain(host)) = url.host() else {
        return Err("invalid_feed_url");
    };
    let forbidden = [
        "localhost",
        "local",
        "internal",
        "home",
        "lan",
        "corp",
        "test",
        "invalid",
        "example",
        "onion",
        "arpa",
    ];
    if url.as_str() != raw
        || url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || raw
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .is_some_and(|authority| authority.contains('@'))
        || url.query().is_some()
        || url.fragment().is_some()
        || !host.contains('.')
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        || forbidden
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err("invalid_feed_url");
    }
    Ok(())
}

/// Parse raw bounded JSON before it can lose duplicate properties or invalid Unicode.
pub fn parse(raw: &str) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX_SECTION_BYTES {
        return Err("feeds_too_large");
    }
    let value = crate::portable::parse_unique(raw).map_err(|_| "invalid_feeds_json")?;
    validate(&value)
}

/// Validate the public-data allowlist without sorting, normalizing or dropping values.
pub fn validate(value: &Value) -> Result<Value> {
    if serde_json::to_vec(value)
        .map_err(|_| "invalid_feeds")?
        .len()
        > MAX_SECTION_BYTES
    {
        return Err("feeds_too_large");
    }
    exact(
        value,
        &[
            "schema",
            "version",
            "subscriptions",
            "collections",
            "preferences",
        ],
    )?;
    if value["schema"] != SCHEMA || value["version"].as_u64() != Some(1) {
        return Err("invalid_feeds");
    }
    exact(&value["preferences"], &["order"])?;
    if value["preferences"]["order"] != "newest-first" {
        return Err("invalid_feed_preferences");
    }
    let mut collection_ids = BTreeSet::new();
    for collection in array(&value["collections"], 64)? {
        exact(collection, &["id", "title"])?;
        if !collection_ids.insert(uuid(&collection["id"])?) {
            return Err("duplicate_feed_collection");
        }
        text(&collection["title"], 512)?;
    }
    let mut subscription_ids = BTreeSet::new();
    for subscription in array(&value["subscriptions"], 256)? {
        exact(
            subscription,
            &[
                "id",
                "url",
                "format",
                "title",
                "enabled",
                "collectionIds",
                "disclosure",
            ],
        )?;
        if !subscription_ids.insert(uuid(&subscription["id"])?) {
            return Err("duplicate_feed_subscription");
        }
        endpoint(&subscription["url"])?;
        text(&subscription["title"], 512)?;
        if !matches!(
            subscription["format"].as_str(),
            Some("auto" | "rss" | "atom")
        ) || !matches!(
            subscription["disclosure"].as_str(),
            Some("private" | "selected")
        ) || !subscription["enabled"].is_boolean()
        {
            return Err("invalid_feed_subscription");
        }
        let mut references = BTreeSet::new();
        for reference in array(&subscription["collectionIds"], 16)? {
            let id = uuid(reference)?;
            if !collection_ids.contains(id) || !references.insert(id) {
                return Err("invalid_feed_collection_reference");
            }
        }
    }
    Ok(value.clone())
}
