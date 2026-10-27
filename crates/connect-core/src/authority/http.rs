use anyhow::{Context, Result, ensure};
use genesis_mesh_sdk::parse_strict_json;
use reqwest::{Client, Method, Url, redirect};
use serde_json::Value;
use std::{net::IpAddr, time::Duration};

pub(super) const MAX_RESPONSE: usize = 256 * 1024;

/// Explicit loopback-only adapter for a native desktop authority. No DNS,
/// redirects, environment proxies or caller-selected paths are accepted.
#[derive(Clone)]
pub struct LocalAuthority {
    client: Client,
    base: Url,
}

impl LocalAuthority {
    pub(super) async fn exchange_public_attestation(&self, id: &str) -> Result<Value> {
        self.exchange(Method::GET, &format!("/attestations/{id}"), None)
            .await
    }
    pub fn new(base: &str) -> Result<Self> {
        let base = Url::parse(base).context("Invalid authority URL")?;
        let host = base.host_str().context("Missing authority host")?;
        let ip: IpAddr = host
            .trim_matches(['[', ']'])
            .parse()
            .context("Authority must use a numeric loopback address")?;
        ensure!(
            base.scheme() == "http"
                && ip.is_loopback()
                && base.port().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.path() == "/"
                && base.query().is_none()
                && base.fragment().is_none(),
            "Use an explicit http://loopback:port authority origin"
        );
        // Iroh enables reqwest's rustls-no-provider feature. Configure this
        // client explicitly rather than depending on an endpoint having first
        // installed a process-wide crypto provider. HTTPS is outside this adapter.
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self { client, base })
    }

    pub(super) async fn get(&self, path: &str) -> Result<Value> {
        ensure!(
            matches!(path, "/na/key-history" | "/crl"),
            "Unsupported authority read"
        );
        self.exchange(Method::GET, path, None).await
    }
    pub(super) async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        ensure!(
            matches!(path, "/join" | "/renew" | "/node/boundary/evaluate"),
            "Unsupported authority write"
        );
        self.exchange(Method::POST, path, Some(body)).await
    }

    async fn exchange(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let mut request = self.client.request(method, self.base.join(path)?);
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body)?;
            ensure!(bytes.len() <= 16 * 1024, "Authority request too large");
            request = request
                .header("Content-Type", "application/json")
                .body(bytes);
        }
        let mut response = request.send().await.context("Authority unavailable")?;
        // Do not include arbitrary response text: it may echo an invite or payload.
        ensure!(
            response.status().is_success(),
            "Authority refused request (HTTP {})",
            response.status().as_u16()
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|size| size <= MAX_RESPONSE as u64),
            "Authority response too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("Authority response incomplete")?
        {
            ensure!(
                chunk.len() <= MAX_RESPONSE - bytes.len(),
                "Authority response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        // Parser error text can contain received values; expose a stable refusal.
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| anyhow::anyhow!("Authority returned invalid UTF-8"))?;
        parse_strict_json(text)
            .map_err(|_| anyhow::anyhow!("Authority returned invalid or ambiguous JSON"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_an_explicit_numeric_loopback_origin_is_accepted() {
        for url in ["http://127.0.0.1:9443", "http://[::1]:9443"] {
            assert!(LocalAuthority::new(url).is_ok());
        }
        for url in [
            "https://example.org",
            "http://localhost:9443",
            "http://192.168.1.3:9443",
            "http://127.0.0.1",
            "http://user:secret@127.0.0.1:9443",
            "http://127.0.0.1:9443/admin",
            "http://127.0.0.1:9443/?url=x",
            "http://127.0.0.1:9443/#x",
        ] {
            assert!(LocalAuthority::new(url).is_err(), "{url}");
        }
    }
}
