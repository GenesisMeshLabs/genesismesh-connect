//! Explicit native stores only. No keyring default store, mock, plaintext file
//! fallback or automatic replacement when the OS credential service is locked.
//! A headless Linux node uses its sealed store instead of Secret Service; the
//! two use different references, so neither can open the other's records.
use super::credential;
use anyhow::{Context, Result};
use keyring_core::{Entry, api::CredentialStoreApi};
use zeroize::Zeroizing;
pub(in crate::device) struct Store {
    #[cfg(target_os = "linux")]
    inner: Backend,
    #[cfg(target_os = "android")]
    inner: std::sync::Arc<android_native_keyring_store::Store>,
}
#[cfg(target_os = "linux")]
enum Backend {
    SecretService(std::sync::Arc<zbus_secret_service_keyring_store::Store>),
    Sealed(Box<crate::device::sealed_store::Store>),
}
impl Store {
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        let inner = match crate::device::sealed_store::Store::configured()? {
            Some(sealed) => Backend::Sealed(Box::new(sealed)),
            None => Backend::SecretService(zbus_secret_service_keyring_store::Store::new().context("Connect needs an available, unlocked Secret Service credential store on this Linux account")?),
        };
        #[cfg(target_os = "android")]
        let inner = android_native_keyring_store::Store::new_with_configuration(
            &std::collections::HashMap::from([
                ("name", "genesismesh-connect-v1"),
                ("filename", "genesismesh-connect-keystore-v1"),
            ]),
        )
        .context("Android Keystore could not open the Connect credential store")?;
        Ok(Self { inner })
    }
    fn entry(&self, id: &str) -> Result<Entry> {
        #[cfg(target_os = "linux")]
        let Backend::SecretService(inner) = &self.inner else {
            anyhow::bail!("Not a Secret Service store");
        };
        #[cfg(target_os = "android")]
        let inner = &self.inner;
        Ok(inner.build("org.genesismesh.connect.device.v1", id, None)?)
    }
    #[cfg(target_os = "linux")]
    fn sealed(&self) -> Option<&crate::device::sealed_store::Store> {
        match &self.inner {
            Backend::Sealed(sealed) => Some(sealed),
            Backend::SecretService(_) => None,
        }
    }
}
impl credential::Store for Store {
    fn prefix(&self) -> &'static [u8] {
        #[cfg(target_os = "linux")]
        if let Some(sealed) = self.sealed() {
            return sealed.prefix();
        }
        #[cfg(target_os = "linux")]
        {
            b"GenesisMesh.Connect.SecretService.v1\0"
        }
        #[cfg(target_os = "android")]
        {
            b"GenesisMesh.Connect.AndroidKeystore.v1\0"
        }
    }
    fn get(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        #[cfg(target_os = "linux")]
        if let Some(sealed) = self.sealed() {
            return sealed.get(id);
        }
        match self.entry(id)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => {
                Err(error).context("The system credential store could not open the saved identity")
            }
        }
    }
    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(sealed) = self.sealed() {
            return sealed.set(id, secret);
        }
        self.entry(id)?
            .set_secret(secret)
            .context("The system credential store could not save the identity")
    }
    fn delete(&self, id: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(sealed) = self.sealed() {
            return sealed.delete(id);
        }
        self.entry(id)?
            .delete_credential()
            .context("Could not clean up the uncommitted identity")
    }
}
