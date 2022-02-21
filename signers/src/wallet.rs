//! Wallet for signing messages and transactions
//! using an underlying signer implementation.
use thiserror::Error;

use crate::traits::Sign;
use ethereum_types::{Address, H256, U64};
use web3_hash_utils::{hash_message, sha256};
use web3_signature::Signature;
use web3_transaction::TypedTransaction;

/// Error generated by the wallet implementation.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Error thrown when a transaction chain id does not match this wallet.
    #[error("transaction chain_id does not match the wallet signer")]
    InvalidChainId,

    /// Errors thrown by the bip32 crate.
    #[error(transparent)]
    Bip32(#[from] coins_bip32::Bip32Error),

    /// Errors thrown by the bip32 ECDSA module.
    #[error(transparent)]
    Bip32Ecdsa(#[from] coins_bip32::ecdsa::Error),

    /// Errors thrown by the bip39 mnemonic handling.
    #[error(transparent)]
    Bip39Mnemomic(#[from] coins_bip39::MnemonicError),

    /// Errors thrown creating a wallet from a deterministic mnemonic.
    #[error(transparent)]
    Mnemonic(#[from] crate::mnemonic::MnemonicError),

    /// Generic error handler, used for converting from signer errors.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Wallet for signing messages and transactions using a `Sign` implementation.
pub struct Wallet<S: Sign> {
    /// The signer managing the wallet's private key.
    signer: S,
    /// The wallet's address
    address: Address,
    /// The wallet's chain id (for EIP-155)
    chain_id: u64,
}

impl<S: Sign> Wallet<S> {
    /// Create a new wallet.
    pub fn new(signer: S, address: Address, chain_id: u64) -> Self {
        Self {
            signer,
            address,
            chain_id,
        }
    }

    /// Prepend the Ethereum prefix, hash the result and sign it.
    pub async fn sign_message<M: Send + Sync + AsRef<[u8]>>(
        &self,
        message: M,
    ) -> Result<Signature, WalletError> {
        let message = hash_message(message);
        Ok(self.sign_hash(message, false).await?)
    }

    /// Sign a transaction.
    pub async fn sign_transaction(
        &self,
        tx: &TypedTransaction,
    ) -> Result<Signature, WalletError> {
        let chain_id = tx.chain_id();
        match chain_id {
            Some(id) => {
                if U64::from(self.chain_id) != id {
                    return Err(WalletError::InvalidChainId);
                }
                Ok(self.sign_hash(tx.sighash(), true).await?)
            }
            None => {
                // in the case we don't have a chain_id,
                // let's use the signer chain id instead
                let mut tx_with_chain = tx.clone();
                tx_with_chain.set_chain_id(self.chain_id);
                Ok(self.sign_hash(tx_with_chain.sighash(), true).await?)
            }
        }
    }

    /// Returns the wallet's chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the wallet's chain id.
    #[must_use]
    pub fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
    }

    /// Signs the provided transaction hash and proceeds to
    /// normalize the `v` value of the signature with EIP-155
    /// if the flag is set to true otherwise the `v` value
    /// is converted to the Electrum format.
    pub async fn sign_hash(
        &self,
        hash: H256,
        eip155: bool,
    ) -> Result<Signature, WalletError> {
        let digest = sha256(hash);
        let signature = if eip155 {
            self.signer
                .sign(digest)
                .await
                .map_err(Box::from)?
                .into_eip155(self.chain_id)
        } else {
            self.signer
                .sign(digest)
                .await
                .map_err(Box::from)?
                .into_electrum()
        };
        Ok(signature)
    }

    /// Get the wallet's signer.
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Get the wallet's address.
    pub fn address(&self) -> &Address {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::single_party::SingleParty;
    use anyhow::Result;

    #[test]
    fn test_new_wallet() -> Result<()> {
        let mut rng = rand::thread_rng();
        let signer = SingleParty::random(&mut rng);
        let wallet = Wallet::<SingleParty> {
            address: signer.address(),
            signer,
            chain_id: 1337,
        };
        assert_eq!(1337, wallet.chain_id());
        Ok(())
    }
}
