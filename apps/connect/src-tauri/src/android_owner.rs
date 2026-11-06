//! Native-only bridge in an opt-in qualification package; no app activation.
use anyhow::{Result, ensure};
use connect_core::owner::{NativeOwnerTransport, OwnerRuntime, native::NativeSession};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tauri::{
    Manager, Runtime,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("connect-owner-qualification")
        // Tauri forwards unhandled mobile invokes to Java/Kotlin. Explicitly
        // consume/reject ALL frontend requests; native run_mobile_plugin bypasses IPC.
        .invoke_handler(|invoke| {
            invoke
                .resolver
                .reject("This owner bridge is native-only and disabled for frontend use.");
            true
        })
        .setup(|app, api| {
            if app.config().identifier != "org.genesismesh.connect.ownerqualification" {
                return Err(
                    "Embedded owner qualification requires its isolated application identifier"
                        .into(),
                );
            }
            let handle = api.register_android_plugin(
                "org.genesismesh.connect.authority",
                "OwnerQualificationPlugin",
            )?;
            app.manage(AndroidOwner(handle));
            Ok(())
        })
        .build()
}

struct AndroidOwner<R: Runtime>(PluginHandle<R>);

struct Transport<R: Runtime> {
    handle: PluginHandle<R>,
    session: NativeSession,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handshake {
    schema: u8,
    core_version: String,
    native_only: bool,
    production_create_enabled: bool,
}

/// Worker-thread native qualification entry only. It is deliberately not called
/// by workflow::setup/start or exposed as a Tauri command. It opens no network.
#[allow(dead_code)]
pub(crate) fn prepare<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<OwnerRuntime> {
    let state = app.state::<AndroidOwner<R>>();
    let mut transport = Transport {
        handle: state.0.clone(),
        session: NativeSession::new(),
    };
    let qualification = (|| -> Result<()> {
        let value = transport.call("begin", json!({"op":"status"}))?;
        let handshake: Handshake = serde_json::from_value(value)?;
        let expected = include_str!("../../authority/core-requirements.txt")
            .lines()
            .find_map(|line| line.trim().strip_prefix("genesis-mesh=="))
            .ok_or_else(|| anyhow::anyhow!("Missing authority release pin"))?;
        ensure!(
            handshake.schema == 1
                && handshake.core_version == expected
                && handshake.native_only
                && !handshake.production_create_enabled,
            "Unqualified native owner handshake"
        );
        Ok(())
    })();
    if let Err(error) = qualification {
        transport.close();
        return Err(error);
    }
    Ok(OwnerRuntime::from_native(Box::new(transport)))
}

impl<R: Runtime> Transport<R> {
    fn call(&mut self, method: &'static str, request: Value) -> Result<Value> {
        let call = self.session.prepare(&request)?;
        let response = tauri::async_runtime::block_on(async {
            tokio::time::timeout(
                Duration::from_millis(u64::from(call.budget_ms)),
                self.handle.run_mobile_plugin_async::<Value>(method, &call),
            )
            .await
        });
        match response {
            Ok(Ok(reply)) => self.session.accept(&call, reply),
            _ => {
                self.session.poison();
                anyhow::bail!(
                    "Native owner result is unconfirmed. Restart to review saved state; do not repeat it."
                )
            }
        }
    }
}

impl<R: Runtime> NativeOwnerTransport for Transport<R> {
    fn request(&mut self, request: Value) -> Result<Value> {
        self.call("exchange", request)
    }
    fn close(&mut self) {
        self.session.poison();
        let handle = self.handle.clone();
        let control = self.session.control();
        tauri::async_runtime::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                handle.run_mobile_plugin_async::<Value>("close", control),
            )
            .await;
        });
    }
}
