# N02 custody capacity and restart regression

Baseline `ce11c39`; production code above `cfg(test)` is unchanged. Five new tests exercise sixteen identities plus a revision mark, refusal of the seventeenth before writes, revocation/re-admission across restarts, pairing reset preserving tombstones, a foreign credential consuming a shared slot, and all-or-nothing refusal when journal identities exceed directory capacity. Every refusal is paired with permitted behavior.

Strict remote RCH: all19 custody tests passed, zero failed/ignored; all-target strict Clippy passed. Each1,258-file capture matched the local source before further edits; terminal ACK, absent wrapper/owner and all five release flags were verified. Commands and exact content roots are in `qualification.json`; outputs are in the adjacent logs. Rustfmt, Python tests and diff checks passed.

The current cap counts lifetime identities, including tombstones. These tests preserve the existing nonresurrection policy; they do not qualify that limitation as an ideal user pairing policy. Secure pairing-generation reclamation remains a design issue. Durable relative-command deduplication and its effect/ledger publication boundary remain open work. No flash or full N02 acceptance is claimed.
