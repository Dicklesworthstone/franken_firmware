//! Shared test support: the vector document, hex helpers, and the constructors that turn a vector's context into the crate's own types.

#![allow(dead_code)]

use franken_journal::{Journal, Limits, MemStorage, Namespace, Op};
use franken_update::engine::{
    Engine, KEY_FAILED, KEY_INSTALLED, MARK_FLOOR, MemStaging, pack_failed,
};
use franken_update::manifest::Isa;
use franken_update::policy::{AbReceipt, Board, Dynamic, Installed, Policy, TrustStore};
use serde_json::Value;

pub const VECTORS: &str = include_str!("../vectors/u02_vectors.json");

pub type Eng = Engine<MemStorage, MemStaging>;

pub fn doc() -> Value {
    serde_json::from_str(VECTORS).expect("the U02 vectors parse")
}

pub fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("a hex string")).expect("valid hex")
}

pub fn arr32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().expect("32 bytes")
}

pub fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("`{key}` is text"))
}

pub fn num(v: &Value, key: &str) -> u64 {
    v[key]
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` is a number"))
}

pub fn flag(v: &Value, key: &str) -> bool {
    v[key]
        .as_bool()
        .unwrap_or_else(|| panic!("`{key}` is a boolean"))
}

pub fn index(v: &Value, key: &str) -> usize {
    usize::try_from(num(v, key)).expect("fits")
}

pub fn small(v: &Value, key: &str) -> u16 {
    u16::try_from(num(v, key)).expect("fits u16")
}

pub fn wide(v: &Value, key: &str) -> u32 {
    u32::try_from(num(v, key)).expect("fits u32")
}

pub fn limits() -> Limits {
    Limits::standard()
}

pub fn board(d: &Value, name: &str) -> Board {
    let b = &d["boards"][name];
    Board {
        profile_id: text(b, "profile_id").to_string(),
        hw_rev: text(b, "hw_rev").to_string(),
        isa: Isa::from_code(u8::try_from(num(b, "isa")).expect("fits u8")).expect("an ISA code"),
        kernel_profile: text(b, "kernel_profile").to_string(),
        synthetic: flag(b, "synthetic"),
        attested: flag(b, "attested"),
    }
}

pub fn installed(spec: &Value) -> Option<Installed> {
    let i = &spec["installed"];
    if i.is_null() {
        return None;
    }
    Some(Installed {
        version: wide(i, "version"),
        security_version: wide(i, "security_version"),
        settings_schema: small(i, "settings_schema"),
        settings_read_min: small(i, "settings_read_min"),
        calibration_schema: small(i, "calibration_schema"),
        wire_schema: small(i, "wire_schema"),
        wire_read_min: small(i, "wire_read_min"),
        wire_read_max: small(i, "wire_read_max"),
        features: small(i, "features"),
        sha: arr32(&i["sha"]),
    })
}

pub fn policy(d: &Value, spec: &Value) -> Policy {
    let keys: Vec<([u8; 32], bool)> = spec["trust"]
        .as_array()
        .expect("a trust list")
        .iter()
        .map(|t| {
            (
                arr32(&d["keys"][text(t, "key")]["public"]),
                flag(t, "revoked"),
            )
        })
        .collect();
    let receipt = &spec["ab_receipt"];
    Policy {
        trust: TrustStore::new(&keys).expect("the vector's trust store is admissible"),
        board: board(d, text(spec, "board")),
        production: flag(spec, "production"),
        evidence: spec["evidence"].as_str().map(|_| arr32(&spec["evidence"])),
        required: small(spec, "required"),
        allow_downgrade: flag(spec, "allow_downgrade"),
        settings_backup: spec["settings_backup"]
            .as_u64()
            .map(|n| u16::try_from(n).expect("fits u16")),
        staging_bytes: wide(spec, "staging_bytes"),
        reserve: wide(spec, "reserve"),
        recovery_path: flag(spec, "recovery_path"),
        ab_receipt: if receipt.is_null() {
            None
        } else {
            Some(AbReceipt {
                slot_bytes: wide(receipt, "slot_bytes"),
                digest: arr32(&receipt["digest"]),
                synthetic: flag(receipt, "synthetic"),
            })
        },
    }
}

pub fn dynamic(spec: &Value) -> Dynamic {
    Dynamic {
        installed: installed(spec),
        floor: num(spec, "floor"),
        failed: spec["failed"].as_str().map(|_| arr32(&spec["failed"])),
    }
}

/// A journal on `storage` holding the context's installed image, floor and failed candidate, and an engine over it with an empty staging
/// medium of the context's capacity.
pub fn fresh_engine(d: &Value, spec: &Value, storage: MemStorage) -> Eng {
    let (mut journal, _) = Journal::open(storage, limits()).expect("a blank medium opens");
    let mut ops = Vec::new();
    if let Some(image) = installed(spec) {
        ops.push(Op::Put {
            ns: Namespace::Records,
            key: KEY_INSTALLED.to_vec(),
            value: image.pack(),
        });
    }
    ops.push(Op::Raise {
        key: MARK_FLOOR.to_vec(),
        value: num(spec, "floor"),
    });
    if let Some(sha) = dynamic(spec).failed {
        ops.push(Op::Put {
            ns: Namespace::Records,
            key: KEY_FAILED.to_vec(),
            value: pack_failed(sha),
        });
    }
    journal.commit(&ops).expect("the context is stored");
    Engine::open(
        journal,
        MemStaging::new(wide(spec, "staging_bytes")),
        policy(d, spec),
    )
    .expect("an engine over a clean journal")
}

/// A restart: the process is gone, the durable bytes of the journal and the staging medium remain.
pub fn restart(engine: Eng) -> Eng {
    let (journal, staging, policy) = engine.into_parts();
    let image = journal.storage().durable().to_vec();
    let storage = MemStorage::from_image(limits().segment_bytes, &image);
    let (journal, _) = Journal::open(storage, limits()).expect("the durable image opens");
    Engine::open(journal, staging, policy).expect("the engine resumes")
}

/// A restart under a policy that has changed since the stage began: the script's context with `change` laid over it (the same non-cumulative
/// merge the Python generator uses), a floor raised first if `change` carries one, then the durable bytes reopened under the merged policy.
pub fn restart_with(engine: Eng, d: &Value, base: &Value, change: &Value) -> Eng {
    let (mut journal, staging, _) = engine.into_parts();
    let mut merged = base.clone();
    for (key, value) in change.as_object().expect("a context change") {
        merged[key.as_str()] = value.clone();
    }
    if let Some(floor) = change.get("floor") {
        journal
            .commit(&[Op::Raise {
                key: MARK_FLOOR.to_vec(),
                value: floor.as_u64().expect("a floor"),
            }])
            .expect("the floor is raised");
    }
    let image = journal.storage().durable().to_vec();
    let storage = MemStorage::from_image(limits().segment_bytes, &image);
    let (journal, _) = Journal::open(storage, limits()).expect("the durable image opens");
    Engine::open(journal, staging, policy(d, &merged)).expect("the engine reopens")
}
