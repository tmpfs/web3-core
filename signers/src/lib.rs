//! Lightweight library for ECDSA signing compatible with the
//! Ethereum blockchain designed for Webassembly interoperability.
#![deny(missing_docs)]

pub mod single_party;
mod traits;
mod wallet;

//pub use ethereum_types as types;

pub use traits::Sign;
pub use wallet::Wallet;
