use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use connect_core::operations::{
    AccessCommitInput, Approval, OperationClass, OperationId, OperationRequest, Retry, registry,
};
use serde_json::json;

fn review() -> serde_json::Value {
    json!({"operation":"connect.access.update.v1","input":{"collection":uuid::Uuid::new_v4().to_string(),"settings":{
        "version":1,"recipients":[STANDARD.encode([1;32])],"expires_at":null,"max_bytes":4096,"max_seconds":300,"extra_gates":[]}}})
}
#[test]
fn registry_keeps_read_write_actor_approval_and_retry_contracts_distinct() -> Result<()> {
    let specs = registry();
    assert_eq!(specs.len(), 2);
    let read = specs
        .iter()
        .find(|s| s.id == OperationId::InspectAccess)
        .unwrap();
    let write = specs
        .iter()
        .find(|s| s.id == OperationId::UpdateAccess)
        .unwrap();
    assert_eq!(read.class, OperationClass::Read);
    assert_eq!(read.approval, Approval::None);
    assert_eq!(read.retry, Retry::FreshRead);
    assert_eq!(write.class, OperationClass::Write);
    assert_eq!(write.approval, Approval::ExactIntentConfirmation);
    assert_eq!(write.retry, Retry::ReconcileNeverAutomaticallyResend);
    for spec in specs {
        assert_eq!(spec.actor, "authenticated_resource_host");
        assert!(!spec.assisted);
        assert!(spec.manual);
    }
    let request = OperationRequest::parse(&review().to_string())?;
    assert_eq!(
        request.id().as_str(),
        connect_core::access_workflow::OPERATION
    );
    Ok(())
}

#[test]
fn closed_inputs_reject_arbitrary_dispatch_context_and_duplicate_json() -> Result<()> {
    let value = review();
    OperationRequest::parse(&value.to_string())?;
    for field in ["route", "url", "command", "key_path", "context", "actor"] {
        let mut changed = value.clone();
        changed["input"][field] = json!("untrusted");
        assert!(
            OperationRequest::parse(&changed.to_string()).is_err(),
            "{field}"
        );
    }
    let mut changed = value.clone();
    changed["operation"] = json!("core.admin.execute");
    assert!(OperationRequest::parse(&changed.to_string()).is_err());
    changed = value.clone();
    changed["input"]["settings"]["route"] = json!("/admin/revoke");
    assert!(OperationRequest::parse(&changed.to_string()).is_err());
    changed = value.clone();
    changed["input"]["collection"] = json!("../outside");
    assert!(OperationRequest::parse(&changed.to_string()).is_err());
    assert!(OperationRequest::parse(r#"{"operation":"connect.access.inspect.v1","operation":"connect.access.update.v1","input":{}}"#).is_err());
    assert!(OperationRequest::parse(&" ".repeat(24 * 1024 + 1)).is_err());
    Ok(())
}

#[test]
fn structural_decode_does_not_replace_runtime_semantic_checks() -> Result<()> {
    for (field, value) in [
        ("max_bytes", json!(0)),
        ("max_bytes", json!(9007199254740992u64)),
        ("max_seconds", json!(3601)),
        ("version", json!(0)),
        ("recipients", json!([])),
        ("expires_at", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut changed = review();
        changed["input"]["settings"][field] = value;
        assert!(
            OperationRequest::parse(&changed.to_string()).is_err(),
            "{field}"
        );
    }
    let mut changed = review();
    changed["input"]["settings"]["extra_gates"] = json!([{"gate_id":"peer"}]);
    assert!(OperationRequest::parse(&changed.to_string()).is_err());
    let input = AccessCommitInput {
        id: uuid::Uuid::new_v4().to_string(),
        digest: "a".repeat(64),
    };
    input.validate()?;
    assert!(
        AccessCommitInput {
            digest: "arbitrary payload".into(),
            ..input
        }
        .validate()
        .is_err()
    );
    Ok(())
}

#[test]
#[cfg(feature = "operation-schemas")]
fn generated_contract_matches_actual_types_and_every_operation_has_value_schemas() -> Result<()> {
    use connect_core::operations::schemas;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/connect-operations.json");
    assert_eq!(
        std::fs::read_to_string(path)?,
        schemas::document()?,
        "Explicitly regenerate after reviewing type changes"
    );
    let contract = schemas::contract();
    for op in contract["operations"].as_array().unwrap() {
        for name in [
            "input_schema",
            "review_schema",
            "commit_schema",
            "output_schema",
        ] {
            if let Some(reference) = op[name].as_str() {
                assert!(
                    contract
                        .pointer(reference.strip_prefix('#').unwrap())
                        .is_some()
                );
            }
        }
    }
    let schema = &contract["schemas"]["access_policy"];
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["max_bytes"]["maximum"],
        9007199254740991u64
    );
    assert_eq!(schema["properties"]["recipients"]["maxItems"], 31);
    assert_eq!(
        contract["schemas"]["access_commit_input"]["properties"]["digest"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    Ok(())
}
