//! Address types to represent public keys on various blockchains.
//!
//! More types will be added in the future.
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
mod error;

#[cfg(feature = "ethereum")]
pub mod ethereum;

pub use error::Error;

/// Result type for the address library.
pub type Result<T> = std::result::Result<T, Error>;
