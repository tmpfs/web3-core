//! Common traits for signing and verification.
use async_trait::async_trait;
use std::error::Error;

use ethereum_types::Address;
use web3_signature::Signature;

/// Trait for types that can sign messages.
#[async_trait]
pub trait Sign {
    /// The error type for the implementation.
    type Error: Error + Send + Sync;

    /// Signs a raw message.
    async fn sign<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error>;

    /// Compute the address for the public
    /// key associated with this signer.
    fn address(&self) -> Address;

    /// Get the bytes for the signing key.
    fn to_bytes(&self) -> Vec<u8>;

    /// Create a signing implementation from raw bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Verify the signature for a message.
    fn verify<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
        signature: &Signature,
    ) -> Result<(), Self::Error>;
}
