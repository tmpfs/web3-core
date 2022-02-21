//! Lightweight library for ECDSA signing compatible with the
//! Ethereum blockchain designed for Webassembly interoperability.
#![deny(missing_docs)]

mod mnemonic;
pub mod single_party;
mod traits;
mod wallet;

pub use mnemonic::MnemonicBuilder;
pub use traits::Sign;
pub use wallet::{Wallet, WalletError};
