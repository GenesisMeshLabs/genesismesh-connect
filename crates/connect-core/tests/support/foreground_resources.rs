//! Disposable fixture orchestration. No product runtime, secret export or test discovery.
use super::pairing_support::{grant, joined, owner, request, ticket};
use super::support;
use anyhow::{Context, Result, ensure};
use connect_core::{
    device::DeviceController,
    owner::{OwnerCall, OwnerRequest, foreground::ForegroundNetwork},
    session::{
        bridge::SpaceView,
        sharing::{
            ShareConfig, SpaceKind,
            browse::{Entry, Kind},
            download::{MIN_WINDOW_BYTES, Request},
        },
    },
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
};
use tokio::sync::Mutex;
pub(crate) const DECISION: &str = "/node/boundary/evaluate";

pub(crate) async fn pair(
    owner: &mut ForegroundNetwork,
    path: &Path,
    lost: bool,
) -> Result<DeviceController> {
    let mut member = DeviceController::prepare_remote(path, owner.info.pin.clone())?;
    let (pair, card, mut client, target) = request(owner, &mut member, true).await?;
    owner.device.prepare_local_pairing(&target).await?;
    let completion = owner
        .device
        .issue_local_pairing(&mut owner.runtime, &target)?;
    let issued = grant(client.grant().await?)?;
    if lost {
        let mut flow = Box::pin(member.complete_approved_pairing(&mut client, &card, issued));
        let joined = tokio::select! {
            result=joined(completion)=>result?,
            result=&mut flow=>{result?;anyhow::bail!("Final reply observed before original host commit")}
        };
        drop(flow);
        owner.device.commit_local_pairing(&target, joined).await?;
    } else {
        let a = member.complete_approved_pairing(&mut client, &card, issued);
        let b = async {
            owner
                .device
                .commit_local_pairing(&target, joined(completion).await?)
                .await
        };
        let (a, b) = tokio::join!(a, b);
        a?;
        b?;
    }
    client.close().await;
    pair.close().await;
    if lost {
        let before = member.status()?;
        member.stop().await;
        drop(member);
        member = DeviceController::open(path)?;
        ensure!(
            member.status()?.node_public_key == before.node_public_key
                && member.status()?.certificate_id == before.certificate_id,
            "Enrollment changed after interrupted pairing"
        );
        ensure!(
            member.status()?.paired_device.is_none(),
            "Lost final reply was treated as complete"
        );
    }
    Ok(member)
}
pub(crate) struct Network {
    pub(crate) host: Arc<Mutex<ForegroundNetwork>>,
    pub(crate) worker: tokio::task::JoinHandle<()>,
    pub(crate) member: DeviceController,
}
impl Network {
    pub(crate) async fn new(root: &Path, lost: bool) -> Result<Self> {
        let (mut owner, _) = owner(root).await?;
        let member = pair(&mut owner, &root.join("candidate"), lost).await?;
        let mut network = Self::serve(owner, member);
        if lost {
            let before = network.member.status()?;
            let invites = support::calls(root, "invite");
            let joins = support::core_calls(root, "/join");
            network.member.inspect_pairing_completion().await?;
            assert!(network.member.status()?.paired_device.is_none());
            network.member.finish_pairing_completion().await?;
            assert_eq!(
                before.certificate_id,
                network.member.status()?.certificate_id
            );
            assert_eq!(support::calls(root, "invite"), invites);
            assert_eq!(support::core_calls(root, "/join"), joins);
            network.member.reconnect_saved().await?;
        }
        Ok(network)
    }
    /// A network with a second, independent member, both paired before the
    /// owner starts serving bridge requests.
    pub(crate) async fn with_second(root: &Path, path: &Path) -> Result<(Self, DeviceController)> {
        let (mut owner, _) = owner(root).await?;
        let member = pair(&mut owner, &root.join("candidate"), false).await?;
        let second = pair(&mut owner, path, false).await?;
        Ok((Self::serve(owner, member), second))
    }
    fn serve(mut owner: ForegroundNetwork, member: DeviceController) -> Self {
        let (send, mut receive) = tokio::sync::mpsc::channel::<OwnerRequest>(8);
        owner.device.serve_owner(send);
        let host = Arc::new(Mutex::new(owner));
        let state = host.clone();
        let worker = tokio::spawn(async move {
            while let Some(request) = receive.recv().await {
                let mut host = state.lock().await;
                let result = match request.call {
                    OwnerCall::PairingCompletion {
                        node,
                        certificate,
                        query,
                    } => host
                        .device
                        .answer_pairing_completion(&node, &certificate, query)
                        .await
                        .and_then(|a| Ok(serde_json::to_value(a)?)),
                    // The product's existing fixed adapter derives host identity
                    // from the authenticated bridge. This is not a generic proxy.
                    call => host.runtime.answer(call),
                };
                let _ = request.reply.send(result);
            }
        });
        Self {
            host,
            worker,
            member,
        }
    }
    pub(crate) async fn host_folder(&self, directory: &Path, name: &str) -> Result<ShareConfig> {
        let recipient = self.member.status()?.node_public_key;
        self.host_folder_for(directory, name, &recipient).await
    }
    /// Share a folder from the owner with exactly one recipient.
    pub(crate) async fn host_folder_for(
        &self,
        directory: &Path,
        name: &str,
        recipient: &str,
    ) -> Result<ShareConfig> {
        let mut host = self.host.lock().await;
        let node = host.device.status()?.node_public_key;
        let recipient = recipient.to_owned();
        let space = host.runtime.space_share(
            &node,
            &uuid::Uuid::new_v4().to_string(),
            name,
            &[recipient],
            None,
            SpaceKind::Folder,
        )?;
        let config = DeviceController::space_config(
            SpaceView::of(space, &node).context("Missing host grant")?,
            directory.into(),
        )?;
        host.device.set_space(config.clone()).await?;
        publish(&mut host)?;
        Ok(config)
    }
    pub(crate) async fn host_ticket(&self) -> Result<(String, String)> {
        let state = self.host.lock().await.device.status()?;
        Ok((
            state.node_public_key,
            ticket(state.ticket.context("Missing host session")?)?,
        ))
    }
    pub(crate) async fn close(mut self) {
        self.member.stop().await;
        self.host.lock().await.device.stop().await;
        self.worker.abort();
        assert!(self.worker.await.unwrap_err().is_cancelled());
    }
}
pub(crate) fn publish(host: &mut ForegroundNetwork) -> Result<()> {
    let spaces = host.runtime.space_list()?;
    host.device.publish_spaces(spaces.clone());
    let node = host.device.status()?.node_public_key;
    host.device.apply_spaces(
        spaces
            .into_iter()
            .filter_map(|s| SpaceView::of(s, &node))
            .collect(),
    )?;
    Ok(())
}
pub(crate) fn content(root: &Path, name: &str) -> Result<(std::path::PathBuf, Vec<u8>)> {
    let directory = root.join(name);
    std::fs::create_dir_all(directory.join("Projects/Photos"))?;
    let bytes: Vec<u8> = (0..MIN_WINDOW_BYTES as usize * 3 + 19)
        .map(|i| (i % 251) as u8)
        .collect();
    std::fs::write(directory.join("Projects/Photos/archive.bin"), &bytes)?;
    std::fs::write(directory.join("welcome.txt"), b"A real protected file")?;
    Ok((directory, bytes))
}
pub(crate) async fn entry(
    reader: &DeviceController,
    node: &str,
    address: &str,
    collection: &str,
) -> Result<Entry> {
    let root = reader
        .session()?
        .browse_from(node, address, None, vec![], Some(collection.into()))
        .await?;
    assert!(
        root.files
            .iter()
            .any(|e| e.name == "Projects" && e.kind == Kind::Folder)
    );
    let nested = reader
        .session()?
        .browse_from(
            node,
            address,
            None,
            vec!["Projects".into(), "Photos".into()],
            Some(collection.into()),
        )
        .await?;
    assert_eq!(nested.collection_id, collection);
    assert_eq!(nested.directory, ["Projects", "Photos"]);
    ensure!(nested.files.len() == 1, "Unexpected fixture files");
    Ok(nested.files[0].clone())
}
pub(crate) fn download(
    collection: &str,
    file: &Entry,
    token: Option<String>,
    offset: u64,
) -> Request {
    Request {
        request_id: uuid::Uuid::new_v4().to_string(),
        collection_id: collection.into(),
        file_name: file.name.clone(),
        directory: vec!["Projects".into(), "Photos".into()],
        version: file.version.clone(),
        size: file.bytes,
        token,
        offset,
        length: MIN_WINDOW_BYTES,
    }
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub(crate) fn bytes(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
pub(crate) async fn receive(
    reader: &DeviceController,
    node: &str,
    address: &str,
    collection: &str,
    file: &Entry,
    expected: &[u8],
) -> Result<()> {
    let mut output = tempfile::tempfile()?;
    let mut token = None;
    let mut offset = 0;
    loop {
        let window = reader
            .session()?
            .download_window_from(
                node,
                address,
                download(collection, file, token, offset),
                &mut output,
            )
            .await?;
        offset += window.bytes as u64;
        assert_eq!(output.metadata()?.len(), offset);
        assert_eq!(window.total, expected.len() as u64);
        if window.done {
            assert_eq!(offset, expected.len() as u64);
            assert_eq!(window.sha256, digest(expected));
            break;
        }
        token = Some(window.token);
    }
    assert_eq!(bytes(&mut output)?, expected);
    Ok(())
}
