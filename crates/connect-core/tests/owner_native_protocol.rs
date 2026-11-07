use connect_core::owner::native::{Call, NativeSession, Unchanged};
use serde_json::{Value, json};

fn reply(call: &Call, outcome: Value) -> Value {
    json!({"schema": 1, "session": call.session, "sequence": call.sequence, "reply": outcome})
}

#[test]
fn native_reservation_is_single_use_and_replies_are_exactly_correlated() {
    let mut session = NativeSession::new();
    let call = session.prepare(&json!({"op":"open"})).unwrap();
    assert!(session.prepare(&json!({"op":"open"})).is_err());
    assert_eq!(
        session
            .accept(&call, reply(&call, json!({"ok":true})))
            .unwrap(),
        true
    );
    let next = session.prepare(&json!({"op":"space_list"})).unwrap();
    assert_eq!(next.sequence, call.sequence + 1);
    assert!(
        session
            .accept(&next, reply(&call, json!({"ok":[]})))
            .is_err()
    );
    assert!(session.prepare(&json!({"op":"space_list"})).is_err());
}

#[test]
fn malformed_foreign_oversized_or_uncertain_replies_cannot_be_reused() {
    for change in [
        "session",
        "sequence",
        "schema",
        "extra",
        "outcome",
        "error",
        "oversized",
    ] {
        let mut session = NativeSession::new();
        let call = session.prepare(&json!({"op":"open"})).unwrap();
        let mut value = reply(&call, json!({"ok":true}));
        match change {
            "session" => value["session"] = json!("foreign"),
            "sequence" => value["sequence"] = json!(call.sequence + 1),
            "schema" => value["schema"] = json!(2),
            "extra" => value["extra"] = json!(true),
            "outcome" => value["reply"] = json!({"ok":true,"error":"ambiguous"}),
            "error" => value["reply"] = json!({"error":"Uncertain native result"}),
            _ => value["reply"] = json!({"ok":"x".repeat(512 * 1024)}),
        }
        assert!(session.accept(&call, value).is_err(), "{change}");
        assert!(session.prepare(&json!({"op":"open"})).is_err(), "{change}");
    }
}

#[test]
fn requests_are_bounded_and_timeouts_poison_without_replay() {
    let mut session = NativeSession::new();
    assert!(
        session
            .prepare(&json!({"op":"create","name":"x".repeat(16 * 1024)}))
            .is_err()
    );
    let call = session
        .prepare(&json!({"op":"create","name":"Home"}))
        .unwrap();
    assert_eq!(call.budget_ms, 180_000);
    session.poison();
    assert!(
        session
            .accept(&call, reply(&call, json!({"ok":true})))
            .is_err()
    );
    assert!(
        session
            .prepare(&json!({"op":"create","name":"Home"}))
            .is_err()
    );
}

#[test]
fn a_refusal_that_changed_nothing_keeps_the_session_and_an_unconfirmed_one_does_not() {
    let mut session = NativeSession::new();
    let call = session.prepare(&json!({"op":"recovery_export"})).unwrap();
    let refused = session
        .accept(&call, reply(&call, json!({"unchanged":"Nothing changed"})))
        .unwrap_err();
    assert!(refused.downcast_ref::<Unchanged>().is_some());
    let next = session.prepare(&json!({"op":"space_list"})).unwrap();
    assert!(
        session
            .accept(&next, reply(&next, json!({"error":"Unconfirmed"})))
            .is_err()
    );
    assert!(session.prepare(&json!({"op":"space_list"})).is_err());
}
