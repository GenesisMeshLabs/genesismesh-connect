//! Native Apple Keychain. The iOS service and opaque reference format stay
//! compatible with existing device records; no identity migration or reset.
use super::credential;
use anyhow::{Context, Result};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use zeroize::Zeroizing;
pub(in crate::device) struct Store;
const SERVICE: &str = "org.genesismesh.connect.device.v1";
const ITEM_NOT_FOUND: i32 = -25300;
fn options(id: &str) -> PasswordOptions {
    let mut value = PasswordOptions::new_generic_password(SERVICE, id);
    value.set_access_synchronized(Some(false));
    value
}
impl credential::Store for Store {
    fn prefix(&self) -> &'static [u8] {
        b"GenesisMesh.Connect.Keychain.v1\0"
    }
    fn get(&self, id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match generic_password(options(id)) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(error) if error.code() == ITEM_NOT_FOUND => Ok(None),
            Err(error) => {
                Err(error).context("Unlock the system Keychain to open your saved Connect identity")
            }
        }
    }
    fn set(&self, id: &str, secret: &[u8]) -> Result<()> {
        let mut options = options(id);
        options.set_label("Genesis Mesh Connect device identity");
        #[cfg(target_os = "ios")]
        {
            use security_framework::access_control::{ProtectionMode, SecAccessControl};
            options.set_access_control(SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                0,
            )?);
        }
        set_generic_password_options(secret, options)
            .context("The system Keychain could not save the Connect identity")
    }
    fn delete(&self, id: &str) -> Result<()> {
        delete_generic_password_options(options(id))
            .context("Could not clean up the uncommitted Keychain identity")
    }
}
