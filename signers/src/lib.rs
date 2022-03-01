//! Lightweight library for ECDSA signing compatible with the
//! Ethereum blockchain designed for Webassembly interoperability.
#![deny(missing_docs)]

//mod hash;
mod mnemonic;
mod phrase;
pub mod single_party;
mod traits;
mod wallet;

pub use bip39;
pub use coins_bip32;
pub use coins_bip39;

pub use mnemonic::MnemonicBuilder;
pub use phrase::{MnemonicPhrase, PhraseError, WordCount};
pub use traits::Sign;
pub use wallet::{Wallet, WalletError};
