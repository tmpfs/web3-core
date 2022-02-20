//! Wallet for signing messages and transactions
//! using an underlying signer implementation.
use thiserror::Error;

use crate::traits::Sign;
use ethereum_types::Address;
use web3_hash_utils::hash_message;
use web3_signature::Signature;

/// Errors generated by the wallet implementation.
#[derive(Debug, Error)]
pub enum WalletError {}

/// Wallet for signing messages and transactions using a signer.
pub struct Wallet<S: Sign> {
    /// The signer managing the wallet's private key.
    pub(crate) signer: S,
    /// The wallet's address
    pub(crate) address: Address,
    /// The wallet's chain id (for EIP-155)
    pub(crate) chain_id: u64,
}

impl<S: Sign> Wallet<S> {
    /// Prepend the Ethereum prefix, hash the result and sign it.
    async fn sign_message<M: Send + Sync + AsRef<[u8]>>(
        &self,
        message: M,
    ) -> Result<Signature, <S as Sign>::Error> {
        let message = hash_message(message);
        self.signer.sign(message).await
    }

    /*
    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        let chain_id = tx.chain_id();
        match chain_id {
            Some(id) => {
                if U64::from(self.chain_id) != id {
                    return Err(WalletError::InvalidTransactionError(
                        "transaction chain_id does not match the signer".to_string(),
                    ))
                }
                Ok(self.sign_transaction_sync(tx))
            }
            None => {
                // in the case we don't have a chain_id, let's use the signer chain id instead
                let mut tx_with_chain = tx.clone();
                tx_with_chain.set_chain_id(self.chain_id);
                Ok(self.sign_transaction_sync(&tx_with_chain))
            }
        }
    }
    */

    /// Returns the wallet's chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sets the signer's chain id.
    #[must_use]
    pub fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.chain_id = chain_id.into();
        self
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
