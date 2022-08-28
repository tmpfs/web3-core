//! Address types to represent public keys on various blockchains.
//!
//! Use the `ethereum` feature flag for ethereum style addresses. 
//!
//! More types will be added in the future.
#![deny(missing_docs)]
mod error;

#[cfg(feature = "ethereum")]
pub mod ethereum;

pub use error::Error;

/// Result type for the address library.
pub type Result<T> = std::result::Result<T, Error>;
