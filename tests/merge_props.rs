//! Phase 2 gate: the merge is a semilattice join, so it must be commutative,
//! idempotent and associative, and folding any permutation of a fixed entry
//! set must converge to identical state — including that a causally-latest
//! tombstone can never be resurrected by reordering.
//!
//! Generator invariants that make the laws honest (they mirror reality: a
//! `Clock` uniquely names one write):
//! - a field's value is a pure function of its clock, so equal clocks always
//!   carry equal values (no order-dependent value tie-break)
//! - `device_id == clock.device`, so the header "winner" is a function of the
//!   max clock alone

use proptest::prelude::*;
use sshvault::merge::{merge, merge_all};
use sshvault::record::{Clock, Field, Kind, Record};
use std::collections::BTreeMap;
use uuid::Uuid;

const ID: Uuid = Uuid::from_bytes([7; 16]);

fn dev(b: u8) -> Uuid {
    Uuid::from_bytes([b; 16])
}

/// Small clock space (few lamports × few devices) to force collisions and
/// interleavings — that is where merge bugs hide.
fn any_clock() -> impl Strategy<Value = Clock> {
    (0u64..8, 0u8..4).prop_map(|(lamport, d)| Clock {
        lamport,
        device: dev(d),
    })
}

/// Value is derived from the clock so two writes with the same clock agree.
fn val_from(c: &Clock) -> serde_json::Value {
    serde_json::Value::String(format!("{}:{}", c.lamport, c.device.as_bytes()[0]))
}

fn any_kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Tombstone),
        Just(Kind::Host),
        Just(Kind::Snippet),
        Just(Kind::PortForward),
        Just(Kind::KeyMeta),
    ]
}

fn field_name() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["name", "command", "description", "tags"]).prop_map(String::from)
}

fn any_record() -> impl Strategy<Value = Record> {
    (
        prop::collection::hash_map(field_name(), any_clock(), 0..4),
        prop::option::of(any_clock()),
        any_clock(),
        any_kind(),
    )
        .prop_map(|(field_clocks, deleted_at, hclock, kind)| {
            let fields: BTreeMap<String, Field> = field_clocks
                .into_iter()
                .map(|(name, c)| {
                    (
                        name,
                        Field {
                            value: val_from(&c),
                            clock: c,
                        },
                    )
                })
                .collect();
            Record {
                id: ID,
                kind,
                fields,
                deleted_at,
                clock: hclock,
                device_id: hclock.device,
                modified_at: hclock.lamport,
                share_id: uuid::Uuid::nil(),
            }
        })
}

fn entries() -> impl Strategy<Value = Vec<Record>> {
    prop::collection::vec(any_record(), 1..8)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn commutative(a in any_record(), b in any_record()) {
        prop_assert_eq!(merge(&a, &b), merge(&b, &a));
    }

    #[test]
    fn idempotent(a in any_record()) {
        prop_assert_eq!(merge(&a, &a), a);
    }

    #[test]
    fn absorptive(a in any_record(), b in any_record()) {
        let ab = merge(&a, &b);
        prop_assert_eq!(merge(&ab, &b), ab.clone());
        prop_assert_eq!(merge(&ab, &a), ab);
    }

    #[test]
    fn associative(a in any_record(), b in any_record(), c in any_record()) {
        let left = merge(&merge(&a, &b), &c);
        let right = merge(&a, &merge(&b, &c));
        prop_assert_eq!(left, right);
    }

    /// Any permutation of a fixed entry set folds to identical state.
    #[test]
    fn convergent(mut es in entries()) {
        let canonical = merge_all(&es);
        let perm = es.clone();
        es.reverse();
        prop_assert_eq!(&merge_all(&es), &canonical);
        prop_assert_eq!(&merge_all(perm.iter().rev()), &canonical);
    }

    /// A tombstone that is the causally-latest event (clock strictly above every
    /// field clock in the set) stays deleted under every ordering — no reorder
    /// resurrects it.
    #[test]
    fn no_resurrection(es in entries(), tdev in 0u8..4) {
        let max_lamport = es
            .iter()
            .flat_map(|r| r.fields.values().map(|f| f.clock.lamport))
            .chain(es.iter().map(|r| r.clock.lamport))
            .max()
            .unwrap_or(0);
        let tclock = Clock { lamport: max_lamport + 1, device: dev(tdev) };
        let tomb = Record {
            id: ID,
            kind: Kind::Tombstone,
            fields: BTreeMap::new(),
            deleted_at: Some(tclock),
            clock: tclock,
            device_id: tclock.device,
            modified_at: tclock.lamport,
            share_id: uuid::Uuid::nil(),
        };
        let mut all = es;
        all.push(tomb);

        let forward = merge_all(&all);
        prop_assert!(forward[&ID].is_deleted(), "tombstone must win going forward");

        let mut rev = all.clone();
        rev.reverse();
        prop_assert!(merge_all(&rev)[&ID].is_deleted(), "and in reverse");
        // convergence already proves all orderings equal; these two anchor it.
        prop_assert_eq!(&merge_all(&rev), &forward);
    }
}
