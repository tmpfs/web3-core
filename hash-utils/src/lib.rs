//! Utility functions for computing hashes.
use ethereum_types::H256;
use sha3::{Digest, Keccak256};

const PREFIX: &str = "\x19Ethereum Signed Message:\n";

/// Hash a message according to EIP-191.
///
/// The data is a UTF-8 encoded string and will enveloped as follows:
/// `"\x19Ethereum Signed Message:\n" + message.length + message` and hashed
/// using keccak256.
pub fn hash_message<S>(message: S) -> H256
where
    S: AsRef<[u8]>,
{
    let message = message.as_ref();
    let mut eth_message = format!("{}{}", PREFIX, message.len()).into_bytes();
    eth_message.extend_from_slice(message);
    keccak256(&eth_message).into()
}

/// Compute the Keccak-256 hash of input bytes.
///
/// Panics if the computed hash is not the expected length (32 bytes).
pub fn keccak256<S>(bytes: S) -> [u8; 32]
where
    S: AsRef<[u8]>,
{
    let hash = Keccak256::digest(bytes.as_ref());
    let hash: [u8; 32] = hash
        .as_slice()
        .try_into()
        .expect("hash is not the correct length");
    hash
}
