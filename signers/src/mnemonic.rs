//! Create a deterministic private key using a mnemonic
//! following BIP-39 specifications for a single party wallet.
use std::marker::PhantomData;
use std::str::FromStr;

use coins_bip32::path::DerivationPath;
use coins_bip39::{Mnemonic, Wordlist};
use k256::ecdsa::SigningKey;
use thiserror::Error;

use crate::single_party::SingleParty;
use crate::traits::Sign;
use crate::{Wallet, WalletError};

const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/60'/0'/0/";

/// Error produced by the mnemonic wallet builder.
#[derive(Error, Debug)]
pub enum MnemonicError {
    /// Error thrown when a phrase was expected but not found.
    #[error("expected phrase not found")]
    ExpectedPhraseNotFound,
}

/// Represents a structure that can resolve into a `Wallet<SingleParty>`.
#[derive(Clone, Debug, PartialEq)]
pub struct MnemonicBuilder<W: Wordlist> {
    /// The mnemonic phrase to use for the deterministic wallet.
    phrase: Option<String>,
    /// The derivation path at which the extended private
    /// key child will be derived at. By default
    /// the mnemonic builder uses the path: "m/44'/60'/0'/0/0".
    derivation_path: DerivationPath,
    /// Password for the mnemonic phrase.
    password: Option<String>,
    /// Optional chain id for the generated wallet.
    ///
    /// If no value is given the id for Ethereum mainnet is used (`1`).
    chain_id: Option<u64>,
    /// PhantomData
    _wordlist: PhantomData<W>,
}

impl<W: Wordlist> Default for MnemonicBuilder<W> {
    fn default() -> Self {
        Self {
            phrase: None,
            derivation_path: DerivationPath::from_str(&format!(
                "{}{}",
                DEFAULT_DERIVATION_PATH_PREFIX, 0
            ))
            .expect("should parse the default derivation path"),
            password: None,
            chain_id: None,
            _wordlist: PhantomData,
        }
    }
}

impl<W: Wordlist> MnemonicBuilder<W> {
    /// Sets the phrase in the mnemonic builder, the key will be generated
    /// deterministically by calling the `build` method.
    ///
    /// # Example
    ///
    /// ```
    /// use web3_signers::MnemonicBuilder;
    /// use coins_bip39::English;
    /// # async fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let wallet = MnemonicBuilder::<English>::default()
    ///     .phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    ///     .build()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn phrase<P: Into<String>>(mut self, phrase: P) -> Self {
        self.phrase = Some(phrase.into());
        self
    }

    /// Set the chain id for the generated wallet.
    #[must_use]
    pub fn chain_id<C: Into<u64>>(mut self, id: C) -> Self {
        self.chain_id = Some(id.into());
        self
    }

    /// Sets the derivation path of the child key to be derived.
    ///
    /// The derivation path is calculated using the default
    /// derivation path prefix used in Ethereum, i.e. "m/44'/60'/0'/0/{index}".
    pub fn index<U: Into<u32>>(
        mut self,
        index: U,
    ) -> Result<Self, WalletError> {
        self.derivation_path = DerivationPath::from_str(&format!(
            "{}{}",
            DEFAULT_DERIVATION_PATH_PREFIX,
            index.into()
        ))?;
        Ok(self)
    }

    /// Sets the derivation path of the child key to be derived.
    pub fn derivation_path(mut self, path: &str) -> Result<Self, WalletError> {
        self.derivation_path = DerivationPath::from_str(path)?;
        Ok(self)
    }

    /// Sets the password used to construct the seed from the mnemonic phrase.
    #[must_use]
    pub fn password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Builds a single party `Wallet` using the parameters set
    /// in mnemonic builder.
    ///
    /// This method expects the phrase field to be set.
    pub fn build(&self) -> Result<Wallet<SingleParty>, WalletError> {
        let mnemonic = match &self.phrase {
            Some(phrase) => Mnemonic::<W>::new_from_phrase(phrase)?,
            None => return Err(MnemonicError::ExpectedPhraseNotFound.into()),
        };

        let derived_priv_key = mnemonic
            .derive_key(&self.derivation_path, self.password.as_deref())?;
        let key: &coins_bip32::prelude::SigningKey = derived_priv_key.as_ref();
        let secret_key = SigningKey::from_bytes(&key.to_bytes())?;
        let signer = SingleParty::new(secret_key);
        let address = signer.address();
        Ok(Wallet::new(signer, address, self.chain_id.unwrap_or(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MnemonicPhrase;
    use anyhow::Result;
    use coins_bip39::English;
    use web3_hash_utils::to_checksum;

    #[test]
    fn mnemonic_deterministic() {
        // Testcases have been taken from MyCryptoWallet
        const TESTCASES: [(&str, u32, Option<&str>, &str); 4] = [
            (
                "work man father plunge mystery proud hollow address reunion sauce theory bonus",
                0u32,
                Some("TREZOR123"),
                "0x431a00DA1D54c281AeF638A73121B3D153e0b0F6",
            ),
            (
                "inject danger program federal spice bitter term garbage coyote breeze thought funny",
                1u32,
                Some("LEDGER321"),
                "0x231a3D0a05d13FAf93078C779FeeD3752ea1350C",
            ),
            (
                "fire evolve buddy tenant talent favorite ankle stem regret myth dream fresh",
                2u32,
                None,
                "0x1D86AD5eBb2380dAdEAF52f61f4F428C485460E9",
            ),
            (
                "thumb soda tape crunch maple fresh imitate cancel order blind denial giraffe",
                3u32,
                None,
                "0xFB78b25f69A8e941036fEE2A5EeAf349D81D4ccc",
            ),
        ];
        TESTCASES
            .iter()
            .for_each(|(phrase, index, password, expected_addr)| {
                let wallet = match password {
                    Some(psswd) => MnemonicBuilder::<English>::default()
                        .phrase(*phrase)
                        .index(*index)
                        .unwrap()
                        .password(psswd)
                        .build()
                        .unwrap(),
                    None => MnemonicBuilder::<English>::default()
                        .phrase(*phrase)
                        .index(*index)
                        .unwrap()
                        .build()
                        .unwrap(),
                };
                assert_eq!(&to_checksum(wallet.address(), None), expected_addr);
            })
    }

    #[test]
    fn mnemonic_recovery() -> Result<()> {
        let phrase = MnemonicPhrase::words(Default::default())?;

        // Generate a wallet
        let first_wallet = MnemonicBuilder::<English>::default()
            .phrase(&phrase)
            .build()?;
        let first_bytes = first_wallet.signer().to_bytes();

        // Recover the wallet from the recovery seed phrase
        let second_wallet = MnemonicBuilder::<English>::default()
            .phrase(&phrase)
            .build()?;
        let second_bytes = second_wallet.signer().to_bytes();

        assert_eq!(first_bytes, second_bytes);
        Ok(())
    }
}
