//! Rolling updates (`docs/contracts/u02.md` section 6): may one member take a candidate while the others stay as they are?
//!
//! The answer never contains an action on another member. A candidate that the rest of the group could not talk to is refused and the group
//! is preserved; nobody is upgraded or migrated to make a new sender acceptable. A member that is disconnected counts through the image it
//! last reported, and the answer says so; a member nobody has ever heard from, connected or not, cannot be assessed, so the admission is
//! refused. The member that takes the candidate must exist: an index that names nobody is refused as `invalid_target`.

use crate::policy::{Installed, settings_readable};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: String,
    /// The image the member last reported, if it ever did.
    pub image: Option<Installed>,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub admit: bool,
    /// `ok`, `wire_incompatible`, `unknown_member_state` or `invalid_target`.
    pub code: &'static str,
    /// Members the candidate cannot talk to (or, for `unknown_member_state`, every member that could not be assessed), sorted. Empty for `invalid_target`.
    pub conflicts: Vec<String>,
    /// Disconnected members that were judged by their last known image, sorted.
    pub assumed: Vec<String>,
}

/// Each image emits exactly its `wire_schema` and reads `wire_read_min..=wire_read_max`. Two images can talk only if EACH can read what the OTHER
/// emits: there is no negotiation and no fallback to an older version, so a newer emitter beyond a peer's upper bound is as incompatible as an
/// older one below its lower bound.
#[must_use]
pub fn wire_compatible(a: &Installed, b: &Installed) -> bool {
    let reads = |reader: &Installed, emitted: u16| {
        (reader.wire_read_min..=reader.wire_read_max).contains(&emitted)
    };
    reads(a, b.wire_schema) && reads(b, a.wire_schema)
}

/// May member `index` take `candidate`, with every other member left exactly as it is?
///
/// `index` must name a member. An empty group, or an `index` at or past `members.len()`, has nobody to upgrade: it is refused as `invalid_target`
/// before any member is assessed. Without that check every real member would count as "somebody else", and a group with nobody in it, or with
/// the wrong index, could be answered `ok` for a member that does not exist.
#[must_use]
pub fn group_decision(members: &[Member], index: usize, candidate: &Installed) -> Decision {
    if index >= members.len() {
        return Decision {
            admit: false,
            code: "invalid_target",
            conflicts: Vec::new(),
            assumed: Vec::new(),
        };
    }
    let mut unknown: Vec<String> = members
        .iter()
        .enumerate()
        .filter(|(position, other)| *position != index && other.image.is_none())
        .map(|(_, other)| other.id.clone())
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        return Decision {
            admit: false,
            code: "unknown_member_state",
            conflicts: unknown,
            assumed: Vec::new(),
        };
    }
    let mut assumed: Vec<String> = Vec::new();
    let mut conflicts: Vec<String> = Vec::new();
    for (position, other) in members.iter().enumerate() {
        if position == index {
            continue;
        }
        if !other.connected {
            assumed.push(other.id.clone());
        }
        if let Some(image) = &other.image
            && !wire_compatible(candidate, image)
        {
            conflicts.push(other.id.clone());
        }
    }
    conflicts.sort();
    assumed.sort();
    if conflicts.is_empty() {
        Decision {
            admit: true,
            code: "ok",
            conflicts,
            assumed,
        }
    } else {
        Decision {
            admit: false,
            code: "wire_incompatible",
            conflicts,
            assumed,
        }
    }
}

/// After a settings migration, may the member go back to `target`? Only if `target` reads what is stored, or a preserved copy of an older
/// schema. Returns `allow` or `refuse:settings_incompatible`.
#[must_use]
pub fn rollback_decision(
    stored_settings_schema: u16,
    backup: Option<u16>,
    target: &Installed,
) -> &'static str {
    if settings_readable(
        target.settings_read_min,
        target.settings_schema,
        stored_settings_schema,
        backup,
    ) {
        "allow"
    } else {
        "refuse:settings_incompatible"
    }
}
