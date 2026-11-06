use base64::{Engine as _, engine::general_purpose::STANDARD};
use connect_core::{
    authority::TrustPin,
    owner::inspection::{InspectionStatus, MembershipInspection},
};
use serde_json::{Value, json};

fn observation() -> Value {
    json!({"schema":1,"observed_at":"2026-11-06T12:00:00+00:00",
        "status":"matching_recorded_outcome","reason":"signed_exact_outcome_reference",
        "binding":{"instance":"00000000-0000-4000-8000-000000000001","network_name":"Home",
            "root_public_key":STANDARD.encode([1;32]),"authority_public_key":STANDARD.encode([2;32]),
            "operator_public_key":STANDARD.encode([3;32]),"member_public_key":STANDARD.encode([4;32]),
            "certificate_id":"00000000-0000-4000-8000-000000000002",
            "previous_certificate_id":"00000000-0000-4000-8000-000000000002",
            "operation":"00000000-0000-4000-8000-000000000003","intent_sha256":"a".repeat(64)},
        "outcome":{"certificate_id":"00000000-0000-4000-8000-000000000004","certificate_sha256":"b".repeat(64),
            "issued_at":"2026-11-06T10:00:00+00:00","expires_at":"2026-11-07T10:00:00+00:00","expired":false}})
}

#[test]
fn observations_are_strictly_bound_to_the_saved_network_member_and_update() {
    let value = MembershipInspection::parse(observation()).unwrap();
    let binding = value.binding.as_ref().unwrap();
    let pin = TrustPin {
        root_public_key: binding.root_public_key.clone(),
        network_name: "Home".into(),
    };
    assert_eq!(value.status, InspectionStatus::MatchingRecordedOutcome);
    value
        .require_binding(
            &pin,
            &binding.member_public_key,
            &binding.instance,
            &binding.operation,
            &binding.intent_sha256,
        )
        .unwrap();
    assert!(
        value
            .require_binding(
                &pin,
                &STANDARD.encode([8; 32]),
                &binding.instance,
                &binding.operation,
                &binding.intent_sha256
            )
            .is_err()
    );
    assert!(
        value
            .require_binding(
                &pin,
                &binding.member_public_key,
                &binding.instance,
                "foreign-operation",
                &binding.intent_sha256
            )
            .is_err()
    );
    assert!(
        value
            .require_binding(
                &pin,
                &binding.member_public_key,
                &binding.instance,
                &binding.operation,
                &"c".repeat(64)
            )
            .is_err()
    );
    let other = TrustPin {
        network_name: "Other".into(),
        ..pin
    };
    assert!(
        value
            .require_binding(
                &other,
                &binding.member_public_key,
                &binding.instance,
                &binding.operation,
                &binding.intent_sha256
            )
            .is_err()
    );
}

#[test]
fn ambiguity_empty_and_expired_observations_cannot_masquerade_as_confirmations() {
    for field in [
        "status",
        "reason",
        "unknown",
        "key",
        "uuid",
        "hash",
        "time",
        "future",
        "previous",
        "unrelated",
    ] {
        let mut value = observation();
        match field {
            "status" => value["status"] = json!("ambiguous_or_invalid_evidence"),
            "reason" => value["reason"] = json!("no_new_certificate_in_snapshot"),
            "unknown" => value["retry_allowed"] = json!(true),
            "key" => value["binding"]["root_public_key"] = json!("unverified"),
            "uuid" => value["binding"]["operation"] = json!("foreign"),
            "hash" => value["binding"]["intent_sha256"] = json!("a"),
            "future" => value["outcome"]["issued_at"] = json!("2026-11-06T13:00:00+00:00"),
            "previous" => {
                value["outcome"]["certificate_id"] =
                    value["binding"]["previous_certificate_id"].clone()
            }
            "unrelated" => {
                value["binding"]["certificate_id"] = value["binding"]["operation"].clone()
            }
            _ => value["outcome"]["expired"] = json!(true),
        }
        assert!(MembershipInspection::parse(value).is_err(), "{field}");
    }
    let mut empty = observation();
    empty["status"] = json!("no_recorded_issuance_observed");
    empty["reason"] = json!("no_new_certificate_in_snapshot");
    empty["outcome"] = Value::Null;
    assert!(MembershipInspection::parse(empty).is_ok());
    let mut expired = observation();
    expired["observed_at"] = json!("2026-11-08T12:00:00+00:00");
    expired["outcome"]["expired"] = json!(true);
    assert!(MembershipInspection::parse(expired).is_ok());
}

#[test]
fn malformed_or_oversized_reports_are_refused() {
    let mut oversized = observation();
    oversized["padding"] = json!("x".repeat(4096));
    assert!(MembershipInspection::parse(oversized).is_err());
    let mut unbound = observation();
    unbound["binding"] = Value::Null;
    assert!(MembershipInspection::parse(unbound).is_err());
    let invalid = json!({"schema":1,"observed_at":"2026-11-06T12:00:00+00:00",
        "status":"ambiguous_or_invalid_evidence","reason":"snapshot_unavailable","binding":null,"outcome":null});
    assert!(MembershipInspection::parse(invalid).is_ok());
}
