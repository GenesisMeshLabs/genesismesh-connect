//! Names are protected data: a separate authenticated ALPN, capability and
//! context domain authorize each bounded page before metadata enters the wire.
use super::*;
use crate::session::wire::{Protocol, Role, authenticate_for, read_frame, write_frame};
use iroh::endpoint::{Connection, RecvStream, SendStream};
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub request_id: String,
    pub after: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directory: Vec<String>,
    /// The Space to list; apps from before Spaces name none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub name: String,
    pub bytes: usize,
    pub sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilePage {
    pub collection_id: String,
    pub files: Vec<FileEntry>,
    pub next: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Response<T> {
    Allowed {
        intent: Value,
        decision: Value,
        attestation: Value,
        receipt: Value,
        page: T,
    },
    Denied,
}
const MAX_RESPONSE: usize = 512 * 1024;
async fn send_response<T: Serialize>(send: &mut SendStream, value: &Response<T>) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_RESPONSE, "File list too large");
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    Ok(())
}
async fn read_response<T: serde::de::DeserializeOwned>(
    recv: &mut RecvStream,
) -> Result<Response<T>> {
    let mut size = [0; 4];
    recv.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size > 0 && size <= MAX_RESPONSE, "Invalid file list size");
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected file list data"
    );
    Ok(serde_json::from_value(
        genesis_mesh_sdk::parse_strict_json(std::str::from_utf8(&bytes)?)?,
    )?)
}
impl Share {
    async fn list(
        &self,
        credentials: &Credentials,
        peer: &Value,
        request: &ListRequest,
        protocol: Protocol,
    ) -> Result<Response<Value>> {
        uuid::Uuid::parse_str(&request.request_id)?;
        storage::directory(&request.directory)?;
        ensure!(
            matches!(protocol, Protocol::Browse) || request.directory.is_empty(),
            "Legacy catalog is flat"
        );
        if let Some(after) = &request.after {
            storage::name(after)?;
        }
        {
            let nested = matches!(protocol, Protocol::Browse);
            let mut window = if nested {
                &self.browse_requests
            } else {
                &self.requests
            }
            .lock()
            .expect("List budget");
            if window.0.elapsed() >= Duration::from_secs(60) {
                *window = (std::time::Instant::now(), 0)
            }
            ensure!(
                window.1 < if nested { 120 } else { 16 },
                "Too many file operations; try again in a minute"
            );
            window.1 += 1;
        }
        let mut store = self.trust.lock().await;
        let trust = self.authority.refresh(&mut store).await?;
        drop(store);
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        trust.certificate(
            &credentials.identity.certificate,
            &credentials.identity.public_key(),
            Utc::now(),
        )?;
        let directory = self.directory.clone();
        let after = request.after.clone();
        let collection_id = self.config.collection_id.clone();
        let segments = request.directory.clone();
        let page = tokio::task::spawn_blocking(move || -> Result<Value> {
            match protocol {
                Protocol::List => {
                    let (files, next) = directory.list(after.as_deref())?;
                    Ok(serde_json::to_value(FilePage {
                        collection_id,
                        files,
                        next,
                    })?)
                }
                Protocol::Catalog => {
                    let (files, next) = directory.catalog(after.as_deref())?;
                    Ok(serde_json::to_value(super::catalog::Page {
                        collection_id,
                        files,
                        next,
                    })?)
                }
                Protocol::Browse => {
                    let (files, next) = directory.nested(&segments)?.browse(after.as_deref())?;
                    Ok(serde_json::to_value(super::browse::Page {
                        collection_id,
                        directory: segments,
                        files,
                        next,
                    })?)
                }
                _ => anyhow::bail!("Unsupported listing protocol"),
            }
        })
        .await??;
        let intent = json!({"domain":page_domain(protocol),"capability":"connect.collection.list","request":request,"host_node":credentials.identity.public_key(),"peer_node":credentials.expected_node,"host_nonce":uuid::Uuid::new_v4().to_string(),"page_digest":genesis_mesh_sdk::canonical_digest(&serde_json::to_value(&page)?)?,"policy_id":self.config.policy_id});
        let context = format!(
            "{}:{}",
            page_context(protocol),
            genesis_mesh_sdk::canonical_digest(&intent)?
        );
        let attestation_id = self.attestation_id();
        let attestation = self
            .authority
            .attestation(&credentials.identity, &trust, &attestation_id)
            .await?["attestation"]
            .clone();
        let mut parameters = json!({"collection_id":self.config.collection_id,"peer_node":credentials.expected_node,"size":0,"page_digest":intent["page_digest"]});
        if matches!(protocol, Protocol::Browse) {
            parameters["directory"] = json!(request.directory.join("/"));
        }
        let decision = self
            .authority
            .evaluate(
                &credentials.identity,
                &trust,
                &attestation_id,
                &context,
                parameters,
                "connect.collection.list",
            )
            .await?["decision"]
            .clone();
        trust.read_decision(
            &decision,
            &attestation,
            &context,
            &self.config.policy_id,
            &credentials.identity.public_key(),
        )?;
        let receipt = receipt(
            &credentials.identity,
            &intent,
            &decision,
            "prepared",
            Value::Null,
        )?;
        self.persist(&json!({"receipt":receipt,"intent":intent,"decision":decision,"attestation":attestation,"host_certificate":credentials.identity.certificate,"peer_certificate":peer}))?;
        trust.certificate(peer, &credentials.expected_node, Utc::now())?;
        ensure!(
            Utc::now() < crate::session::trust::timestamp(&decision, "decision_valid_until")?,
            "List decision expired"
        );
        Ok(Response::Allowed {
            intent,
            decision,
            attestation,
            receipt,
            page,
        })
    }
}
pub(in crate::session) async fn serve(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    shares: &Shares,
) -> Result<()> {
    serve_for(connection, local, credentials, shares, Protocol::List).await
}
pub(in crate::session) async fn serve_for(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    shares: &Shares,
    protocol: Protocol,
) -> Result<()> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let peer = authenticate_for(
        connection,
        local,
        Role::Server,
        credentials,
        &mut send,
        &mut recv,
        protocol,
    )
    .await?;
    let request: ListRequest = read_frame(&mut recv).await?;
    let selected = credentials.for_authenticated(&peer)?;
    let credentials = &selected;
    ensure!(
        recv.read_to_end(0).await?.is_empty(),
        "Unexpected list request data"
    );
    ensure!(
        matches!(protocol, Protocol::Browse) || request.collection_id.is_none(),
        "Only folder browsing names a shared folder"
    );
    // An unknown Space is refused like any other denial.
    let result = match shares.find(request.collection_id.as_deref(), &credentials.expected_node) {
        Some(share) => {
            let _permit = share
                .budget
                .try_acquire()
                .context("Another file operation is running")?;
            let result = share
                .list(credentials, &peer, &request, protocol)
                .await
                .unwrap_or(Response::Denied);
            if let Response::Allowed { page, .. } = &result {
                share.released_names.fetch_add(
                    page["files"].as_array().map_or(0, Vec::len) as u64,
                    Ordering::Relaxed,
                );
            }
            result
        }
        None => Response::Denied,
    };
    send_response(&mut send, &result).await?;
    connection.closed().await;
    Ok(())
}
pub(in crate::session) async fn receive(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &ListRequest,
) -> Result<FilePage> {
    let page: FilePage =
        receive_page(connection, local, credentials, request, Protocol::List).await?;
    validate_legacy_page(&page, request)?;
    Ok(page)
}

pub(in crate::session) async fn receive_catalog(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &ListRequest,
) -> Result<super::catalog::Page> {
    let page: super::catalog::Page =
        receive_page(connection, local, credentials, request, Protocol::Catalog).await?;
    ensure!(page.files.len() <= 32, "File list too long");
    storage::name(&page.collection_id)?;
    let mut previous = request.after.as_deref();
    for file in &page.files {
        storage::name(&file.name)?;
        ensure!(
            file.bytes <= super::download::MAX_FILE_BYTES
                && file.version.len() == 64
                && file.version.bytes().all(|b| b.is_ascii_hexdigit())
                && previous.is_none_or(|s| file.name.as_str() > s),
            "Invalid file entry"
        );
        previous = Some(&file.name);
    }
    ensure!(
        page.next
            .as_ref()
            .is_none_or(|next| page.files.last().is_some_and(|f| &f.name == next)),
        "Invalid next page"
    );
    Ok(page)
}

pub(in crate::session) async fn receive_browse(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &ListRequest,
) -> Result<super::browse::Page> {
    let page: super::browse::Page =
        receive_page(connection, local, credentials, request, Protocol::Browse).await?;
    super::browse::validate(&page, request)?;
    Ok(page)
}

fn page_domain(protocol: Protocol) -> &'static str {
    if matches!(protocol, Protocol::Browse) {
        "genesismesh-connect/browse/v1"
    } else if matches!(protocol, Protocol::Catalog) {
        "genesismesh-connect/catalog/v1"
    } else {
        "genesismesh-connect/list/v1"
    }
}
fn page_context(protocol: Protocol) -> &'static str {
    if matches!(protocol, Protocol::Browse) {
        "connect-browse"
    } else if matches!(protocol, Protocol::Catalog) {
        "connect-catalog"
    } else {
        "connect-list"
    }
}

async fn receive_page<T: Serialize + serde::de::DeserializeOwned>(
    connection: &Connection,
    local: iroh::EndpointId,
    credentials: &Credentials,
    request: &ListRequest,
    protocol: Protocol,
) -> Result<T> {
    let (mut send, mut recv) = connection.open_bi().await?;
    authenticate_for(
        connection,
        local,
        Role::Client,
        credentials,
        &mut send,
        &mut recv,
        protocol,
    )
    .await?;
    write_frame(&mut send, request).await?;
    send.finish()?;
    let Response::<T>::Allowed {
        intent,
        decision,
        attestation,
        receipt,
        page,
    } = read_response(&mut recv).await?
    else {
        anyhow::bail!("This folder is unavailable or access was not allowed")
    };
    ensure!(
        intent["domain"] == page_domain(protocol)
            && intent["capability"] == "connect.collection.list"
            && intent["request"] == serde_json::to_value(request)?
            && intent["host_node"] == credentials.expected_node
            && intent["peer_node"] == credentials.identity.public_key()
            && intent["page_digest"]
                == genesis_mesh_sdk::canonical_digest(&serde_json::to_value(&page)?)?,
        "Wrong file list response"
    );
    let context = format!(
        "{}:{}",
        page_context(protocol),
        genesis_mesh_sdk::canonical_digest(&intent)?
    );
    credentials.trust.read_decision(
        &decision,
        &attestation,
        &context,
        intent["policy_id"]
            .as_str()
            .context("Missing list policy")?,
        &credentials.expected_node,
    )?;
    verify_receipt(
        &receipt,
        &credentials.expected_node,
        &intent,
        &decision,
        "prepared",
    )?;
    Ok(page)
}

fn validate_legacy_page(page: &FilePage, request: &ListRequest) -> Result<()> {
    ensure!(page.files.len() <= 32, "File list too long");
    storage::name(&page.collection_id)?;
    let mut previous = request.after.as_deref();
    for file in &page.files {
        storage::name(&file.name)?;
        ensure!(
            file.bytes <= storage::MAX_FILE
                && file.sha256.len() == 64
                && file.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                && previous.is_none_or(|s| file.name.as_str() > s),
            "Invalid file entry"
        );
        previous = Some(&file.name);
    }
    ensure!(
        page.next
            .as_ref()
            .is_none_or(|next| page.files.last().is_some_and(|file| &file.name == next)),
        "Invalid next page"
    );
    Ok(())
}
