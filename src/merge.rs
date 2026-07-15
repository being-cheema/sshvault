//! Field-level last-writer-wins merge.
//!
//! Merged state is a join on a lattice: per-field max clock, max tombstone
//! clock, max informational metadata. Joins are commutative, associative and
//! idempotent by construction, so **any** delivery order of any subset of
//! entries converges — proven by the property tests in `tests/merge_props.rs`.

use crate::record::{Kind, Record};
use std::collections::HashMap;
use uuid::Uuid;

/// Merge two snapshots of the *same* record id (panics in debug if ids differ —
/// callers group by id first).
pub fn merge(a: &Record, b: &Record) -> Record {
    debug_assert_eq!(a.id, b.id, "merge requires matching record ids");
    let mut fields = a.fields.clone();
    for (name, fb) in &b.fields {
        match fields.get(name) {
            Some(fa) if fa.clock >= fb.clock => {}
            _ => {
                fields.insert(name.clone(), fb.clone());
            }
        }
    }
    // Tombstones carry no kind of their own; the live kind survives. `Kind` orders
    // Tombstone first, so max() keeps the live kind in the only legit conflict.
    let kind = a.kind.max(b.kind);
    let (newer, older) = if a.clock >= b.clock { (a, b) } else { (b, a) };
    Record {
        id: a.id,
        kind,
        fields,
        deleted_at: a.deleted_at.max(b.deleted_at),
        clock: newer.clock,
        device_id: newer.device_id,
        modified_at: newer.modified_at.max(older.modified_at),
    }
}

/// Fold any number of record snapshots (any order, duplicates fine) into
/// current state per record id. Deleted records are retained in the map —
/// filter with [`Record::is_deleted`] at read time; the tombstone must keep
/// existing so later merges can't resurrect the record.
pub fn merge_all<'a>(records: impl IntoIterator<Item = &'a Record>) -> HashMap<Uuid, Record> {
    let mut state: HashMap<Uuid, Record> = HashMap::new();
    for rec in records {
        state
            .entry(rec.id)
            .and_modify(|cur| *cur = merge(cur, rec))
            .or_insert_with(|| rec.clone());
    }
    state
}

/// True if `kind` marks a live (non-tombstone) record.
pub fn live(rec: &Record) -> bool {
    !rec.is_deleted() && rec.kind != Kind::Tombstone
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{fields_from_payload, Clock, Field, Snippet};
    use std::collections::BTreeMap;

    fn clock(n: u64, d: u8) -> Clock {
        Clock {
            lamport: n,
            device: Uuid::from_bytes([d; 16]),
        }
    }

    fn snap(id: Uuid, name: &str, cmd: &str, c: Clock) -> Record {
        Record {
            id,
            kind: Kind::Snippet,
            fields: fields_from_payload(
                &Snippet {
                    name: name.into(),
                    command: cmd.into(),
                    ..Default::default()
                },
                c,
            ),
            deleted_at: None,
            clock: c,
            device_id: c.device,
            modified_at: c.lamport,
        }
    }

    fn tombstone(id: Uuid, c: Clock) -> Record {
        Record {
            id,
            kind: Kind::Tombstone,
            fields: BTreeMap::new(),
            deleted_at: Some(c),
            clock: c,
            device_id: c.device,
            modified_at: c.lamport,
        }
    }

    #[test]
    fn field_level_lww_takes_newest_field_wise() {
        let id = Uuid::new_v4();
        // device A renames at t=2; device B edits command at t=3
        let mut a = snap(id, "old", "ls", clock(1, 0));
        a.fields.insert(
            "name".into(),
            Field {
                value: "new".into(),
                clock: clock(2, 0),
            },
        );
        let mut b = snap(id, "old", "ls", clock(1, 0));
        b.fields.insert(
            "command".into(),
            Field {
                value: "ls -la".into(),
                clock: clock(3, 1),
            },
        );

        for m in [merge(&a, &b), merge(&b, &a)] {
            let s: Snippet = m.payload().unwrap();
            assert_eq!(s.name, "new", "A's newer name wins");
            assert_eq!(s.command, "ls -la", "B's newer command wins");
        }
    }

    #[test]
    fn tombstone_wins_only_when_later() {
        let id = Uuid::new_v4();
        let edit = snap(id, "s", "ls", clock(5, 0));
        assert!(merge(&edit, &tombstone(id, clock(6, 1))).is_deleted());
        assert!(!merge(&edit, &tombstone(id, clock(4, 1))).is_deleted());
    }

    #[test]
    fn merge_all_is_order_insensitive() {
        let id = Uuid::new_v4();
        let entries = vec![
            snap(id, "a", "1", clock(1, 0)),
            snap(id, "b", "2", clock(2, 1)),
            tombstone(id, clock(3, 0)),
        ];
        let forward = merge_all(&entries);
        let reversed = merge_all(entries.iter().rev());
        assert_eq!(forward[&id], reversed[&id]);
        assert!(forward[&id].is_deleted());
    }
}
