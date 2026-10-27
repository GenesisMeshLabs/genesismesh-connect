//! The same verified collection operations work with a local authority or a
//! pinned Connect bridge. No administrative routes are exposed to peers.
use super::*;
use crate::session::bridge::BridgeAuthority;

#[derive(Clone)]
pub enum AuthorityAccess {
    Local(LocalAuthority),
    Remote(BridgeAuthority),
}
impl From<LocalAuthority> for AuthorityAccess {
    fn from(authority: LocalAuthority) -> Self {
        Self::Local(authority)
    }
}
impl AuthorityAccess {
    pub(crate) async fn refresh(&self, store: &mut TrustStore) -> Result<TrustSnapshot> {
        match self {
            Self::Local(authority) => authority.refresh(store).await,
            Self::Remote(authority) => authority.refresh(store).await,
        }
    }
    pub(crate) async fn attestation(
        &self,
        identity: &SessionIdentity,
        trust: &TrustSnapshot,
        id: &str,
    ) -> Result<Value> {
        match self {
            Self::Local(authority) => authority.read_attestation(id).await,
            Self::Remote(authority) => {
                authority
                    .attestation(identity.clone(), trust.clone(), id)
                    .await
            }
        }
    }
    pub(crate) async fn evaluate(
        &self,
        identity: &SessionIdentity,
        trust: &TrustSnapshot,
        attestation: &str,
        context: &str,
        parameters: Value,
        capability: &str,
    ) -> Result<Value> {
        match self {
            Self::Local(authority) => {
                authority
                    .evaluate_collection(
                        identity,
                        &trust.audience()?,
                        attestation,
                        context,
                        parameters,
                        capability,
                    )
                    .await
            }
            Self::Remote(authority) => {
                authority
                    .evaluate(
                        identity,
                        trust,
                        attestation,
                        context,
                        parameters,
                        capability,
                    )
                    .await
            }
        }
    }
}
