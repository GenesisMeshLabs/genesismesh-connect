use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewRequest {
  pub path: Option<String>,
  #[serde(default)]
  pub share: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewResponse {
  pub value: Option<String>,
}
