//! The desktop authority uses its inherited process pipe to ask the Rust host
//! for native secret storage. Only opaque purpose-bound references reach disk.
use super::vault::{credential::Store, platform_store};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PREFIX: &[u8] = b"GenesisMesh.Connect.Owner.Native.v1\0";
const PURPOSE: &str = "org.genesismesh.connect.owner.v1";
const MAX_SECRET: usize = 16 * 1024;

pub(crate) fn request(request: &Value) -> Result<Value> {
    let object = request
        .as_object()
        .context("Invalid native storage request")?;
    match request["op"].as_str() {
        Some("ready") => {
            ensure!(object.len() == 1, "Unsupported storage fields");
            let store = platform_store()?;
            let id = uuid::Uuid::new_v4().to_string();
            ensure!(
                store.get(&id)?.is_none(),
                "Credential store probe already exists"
            );
            store.set(&id, b"Genesis Mesh Connect storage availability probe")?;
            store.delete(&id)?;
            Ok(json!({"ready":true}))
        }
        Some("seal") => {
            ensure!(object.len() == 2, "Unsupported storage fields");
            let data = decode(request["data"].as_str().context("Missing owner secret")?)?;
            let store = platform_store()?;
            let id = uuid::Uuid::new_v4().to_string();
            ensure!(store.get(&id)?.is_none(), "Owner credential already exists");
            let record = Zeroizing::new(serde_json::to_vec(
                &json!({"purpose":PURPOSE,"id":id,"data":STANDARD.encode(&data)}),
            )?);
            store.set(&id, &record)?;
            let mut reference = PREFIX.to_vec();
            reference.extend_from_slice(id.as_bytes());
            Ok(json!({"data":STANDARD.encode(reference)}))
        }
        Some("open") => {
            ensure!(object.len() == 2, "Unsupported storage fields");
            let reference = decode(
                request["data"]
                    .as_str()
                    .context("Missing owner reference")?,
            )?;
            let id = std::str::from_utf8(
                reference
                    .strip_prefix(PREFIX)
                    .context("Wrong owner storage provider")?,
            )?;
            ensure!(
                uuid::Uuid::parse_str(id)?.to_string() == id,
                "Invalid owner storage reference"
            );
            let stored = platform_store()?.get(id)?.context("The saved owner key is missing from the system credential store. Existing network state was preserved.")?;
            ensure!(stored.len() <= 32 * 1024, "Owner credential too large");
            let record: Value = serde_json::from_slice(&stored)?;
            ensure!(
                record["purpose"] == PURPOSE && record["id"] == id,
                "Owner credential was substituted"
            );
            let data = decode(
                record["data"]
                    .as_str()
                    .context("Invalid owner credential")?,
            )?;
            Ok(json!({"data":STANDARD.encode(&data)}))
        }
        _ => anyhow::bail!("Unsupported native owner storage operation"),
    }
}

fn decode(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(text.len() <= 24 * 1024, "Owner storage request too large");
    let bytes = Zeroizing::new(STANDARD.decode(text)?);
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_SECRET,
        "Invalid owner secret size"
    );
    Ok(bytes)
}
