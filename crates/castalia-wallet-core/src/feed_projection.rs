//! Pure selected feed configuration; no consent, authority, persistence or transport.
//!
//! The caller supplies an independently trusted destination. Syntax validation is
//! not origin approval. Hosts must additionally bind their live requester, consent,
//! custody epoch, source revision, expiry and cancellation before any delivery.
//! The output remains the existing inert `castalia.feeds-section.v1` section.
use crate::feeds::{self, Result};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SELECTION_SCHEMA: &str = "castalia.feed-projection-selection.v1";
pub const MAX_SELECTION_BYTES: usize = feeds::MAX_SECTION_BYTES;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Selection {
    schema: String,
    subscription_ids: Vec<String>,
    collection_ids: Vec<String>,
    memberships: Vec<MembershipSelection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MembershipSelection {
    subscription_id: String,
    collection_ids: Vec<String>,
}

fn unique_ids(values: &[String], maximum: usize) -> Result<BTreeSet<&str>> {
    if values.len() > maximum {
        return Err("feed_selection_limit");
    }
    let mut ids = BTreeSet::new();
    for value in values {
        if !ids.insert(value.as_str()) {
            return Err("duplicate_feed_selection");
        }
    }
    Ok(ids)
}

fn destination_origin(raw: &str) -> Result<()> {
    if raw.is_empty() || raw.len() > 2048 {
        return Err("invalid_feed_projection_origin");
    }
    let url = url::Url::parse(raw).map_err(|_| "invalid_feed_projection_origin")?;
    // Match the established Wallet browser host scheme/loopback syntax. Individual
    // adapters retain their own approval allowlists and may be more restrictive.
    let supported = url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")));
    if !supported
        || url.origin().ascii_serialization() != raw
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid_feed_projection_origin");
    }
    Ok(())
}

/// An opaque, locally prepared projection. Deliberately neither cloneable nor
/// serializable/deserializable: a selected section is data, never an approval token.
/// The exact original source digest stays private and is never part of the preview.
pub struct PreparedFeedProjectionV1 {
    source_fingerprint: [u8; 32],
    destination_origin: String,
    selected_section: Value,
}

impl PreparedFeedProjectionV1 {
    /// Validate original raw JSON before duplicate fields can be lost. Every
    /// selected source needs an explicit membership choice, including an empty one.
    /// Selecting a label does not select membership; orphan labels are pruned.
    pub fn prepare(
        source_json: &str,
        selection_json: &str,
        trusted_destination_origin: &str,
    ) -> Result<Self> {
        destination_origin(trusted_destination_origin)?;
        let mut selected_section = feeds::parse(source_json)?;
        if selection_json.is_empty() || selection_json.len() > MAX_SELECTION_BYTES {
            return Err("feed_selection_limit");
        }
        let raw = crate::portable::parse_unique(selection_json)
            .map_err(|_| "invalid_feed_selection_json")?;
        let selection: Selection =
            serde_json::from_value(raw).map_err(|_| "invalid_feed_selection")?;
        if selection.schema != SELECTION_SCHEMA {
            return Err("unsupported_feed_selection");
        }
        let subscriptions = unique_ids(&selection.subscription_ids, 256)?;
        let collections = unique_ids(&selection.collection_ids, 64)?;
        if selection.memberships.len() != subscriptions.len() {
            return Err("missing_feed_membership_selection");
        }
        let mut memberships = BTreeMap::new();
        for membership in &selection.memberships {
            if !subscriptions.contains(membership.subscription_id.as_str()) {
                return Err("unselected_feed_membership");
            }
            let references = unique_ids(&membership.collection_ids, 16)?;
            if !references.iter().all(|id| collections.contains(id)) {
                return Err("unselected_feed_collection");
            }
            if memberships
                .insert(membership.subscription_id.as_str(), references)
                .is_some()
            {
                return Err("duplicate_feed_membership_selection");
            }
        }
        let source_subscriptions = selected_section["subscriptions"]
            .as_array()
            .expect("validated feed subscriptions");
        for id in &subscriptions {
            let source = source_subscriptions
                .iter()
                .find(|source| source["id"].as_str() == Some(id))
                .ok_or("unknown_feed_selection")?;
            if source["disclosure"] != "selected" {
                return Err("private_feed_selection");
            }
            let references = memberships
                .get(id)
                .ok_or("missing_feed_membership_selection")?;
            let original = source["collectionIds"]
                .as_array()
                .expect("validated collection references");
            if !references
                .iter()
                .all(|id| original.iter().any(|value| value.as_str() == Some(id)))
            {
                return Err("unknown_feed_membership");
            }
        }
        let source_collections = selected_section["collections"]
            .as_array()
            .expect("validated feed collections");
        if !collections.iter().all(|id| {
            source_collections
                .iter()
                .any(|collection| collection["id"].as_str() == Some(id))
        }) {
            return Err("unknown_feed_collection");
        }

        let sources = selected_section["subscriptions"]
            .as_array_mut()
            .expect("validated feed subscriptions");
        sources.retain(|source| {
            subscriptions.contains(source["id"].as_str().expect("validated feed id"))
        });
        for source in sources.iter_mut() {
            let references = &memberships[source["id"].as_str().expect("validated feed id")];
            source["collectionIds"]
                .as_array_mut()
                .expect("validated collection references")
                .retain(|id| references.contains(id.as_str().expect("validated collection id")));
        }
        let referenced: BTreeSet<String> = sources
            .iter()
            .flat_map(|source| {
                source["collectionIds"]
                    .as_array()
                    .expect("validated collection references")
                    .iter()
                    .map(|id| id.as_str().expect("validated collection id").to_owned())
            })
            .collect();
        selected_section["collections"]
            .as_array_mut()
            .expect("validated feed collections")
            .retain(|collection| {
                referenced.contains(collection["id"].as_str().expect("validated collection id"))
            });
        // Keep the original section validator authoritative for produced data too.
        feeds::validate(&selected_section)?;
        Ok(Self {
            source_fingerprint: Sha256::digest(source_json.as_bytes()).into(),
            destination_origin: trusted_destination_origin.to_owned(),
            selected_section,
        })
    }

    /// The exact caller-supplied destination for trusted host review UI.
    pub fn destination_origin(&self) -> &str {
        &self.destination_origin
    }

    /// Only the selected existing section. Contains no source digest, origin,
    /// unselected data, identity or approval. JSON whitespace/key order may differ.
    pub fn preview_json(&self) -> String {
        self.selected_section.to_string()
    }

    /// Consume this local preparation after checking the exact original source
    /// bytes and exact trusted destination again. Even whitespace-only source
    /// changes invalidate it. This does not persist, transmit, sign or authorize.
    pub fn confirm(
        self,
        current_source_json: &str,
        trusted_destination_origin: &str,
    ) -> Result<Value> {
        if trusted_destination_origin != self.destination_origin
            || current_source_json.len() > feeds::MAX_SECTION_BYTES
            || <[u8; 32]>::from(Sha256::digest(current_source_json.as_bytes()))
                != self.source_fingerprint
        {
            return Err("stale_feed_projection");
        }
        Ok(self.selected_section)
    }
}
