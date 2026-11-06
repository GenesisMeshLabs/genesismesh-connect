//! Correlation for a native-only Android qualification bridge, not a wire protocol.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const MAX_REQUEST: usize = 16 * 1024;
pub const MAX_REPLY: usize = 512 * 1024;
pub const MAX_SEQUENCE: u64 = (1 << 53) - 1;

#[derive(Clone, Serialize)]
pub struct Call {
    pub schema: u8,
    pub session: String,
    pub sequence: u64,
    pub budget_ms: u32,
    pub request: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub schema: u8,
    pub session: String,
    pub sequence: u64,
    pub reply: Value,
}

pub struct NativeSession {
    id: String,
    next: u64,
    pending: Option<u64>,
    poisoned: bool,
}

impl Default for NativeSession {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeSession {
    pub fn new() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            next: 1,
            pending: None,
            poisoned: false,
        }
    }

    /// The session identifier is random native state, never frontend input.
    pub fn control(&self) -> Value {
        json!({"schema": 1, "session": self.id})
    }

    pub fn prepare(&mut self, request: &Value) -> Result<Call> {
        ensure!(
            !self.poisoned && self.pending.is_none(),
            "Native owner session needs restart"
        );
        let request = serde_json::to_string(request)?;
        ensure!(
            request.len() <= MAX_REQUEST,
            "Native owner request is too large"
        );
        ensure!(self.next <= MAX_SEQUENCE, "Native owner session is full");
        // Operations that wait for the root key's authentication prompt.
        let budget_ms = match serde_json::from_str::<Value>(&request)?["op"].as_str() {
            Some("create" | "recovery_export" | "recovery_import") => 180_000,
            _ => 30_000,
        };
        let sequence = self.next;
        self.next += 1;
        self.pending = Some(sequence); // Reserve before any platform dispatch.
        Ok(Call {
            schema: 1,
            session: self.id.clone(),
            sequence,
            budget_ms,
            request,
        })
    }

    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    pub fn accept(&mut self, call: &Call, value: Value) -> Result<Value> {
        let result = self.check(call, value);
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.pending = None;
        }
        result
    }

    fn check(&self, call: &Call, value: Value) -> Result<Value> {
        ensure!(
            !self.poisoned && self.pending == Some(call.sequence),
            "Stale native owner reply"
        );
        ensure!(
            serde_json::to_vec(&value)?.len() <= MAX_REPLY,
            "Native owner reply is too large"
        );
        let reply: Reply = serde_json::from_value(value)?;
        ensure!(
            reply.schema == 1
                && reply.session == self.id
                && reply.session == call.session
                && reply.sequence == call.sequence,
            "Native owner reply belongs to another operation"
        );
        let fields = reply
            .reply
            .as_object()
            .filter(|fields| fields.len() == 1)
            .ok_or_else(|| anyhow::anyhow!("Invalid native owner outcome"))?;
        if let Some(error) = fields.get("error") {
            ensure!(
                error.as_str().is_some_and(|s| s.len() <= 256),
                "Invalid native owner refusal"
            );
            anyhow::bail!(
                "The local authority operation was not confirmed. Existing state was preserved."
            );
        }
        fields
            .get("ok")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Invalid native owner outcome"))
    }
}
