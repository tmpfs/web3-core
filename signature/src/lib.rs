//! Type to represent an ECDSA signature with a recovery identifier.
#![deny(missing_docs)]
use ethereum_types::U256;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

/// Errors thrown converting to and from signatures.
#[derive(Debug, Error)]
pub enum SignatureError {
    /// Invalid length, secp256k1 signatures are 65 bytes
    #[error("invalid signature length, got {0}, expected 65")]
    InvalidLength(usize),
    /// When parsing a signature from string to hex
    #[error(transparent)]
    DecodingError(#[from] hex::FromHexError),
}

/// An ECDSA signature with a recovery identifier.
///
/// The recovery identifier may be normalized, in Electrum notation
/// or have EIP155 chain replay protection applied.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub struct Signature {
    /// R value
    pub r: U256,
    /// S value
    pub s: U256,
    /// V value for the recovery identifier
    pub v: u64,
}

impl Signature {
    /// Create a signature with normalized recovery identifier.
    pub fn new_normalized(r: U256, s: U256, v: u64) -> Self {
        debug_assert!(v == 0 || v == 1);
        Self { r, s, v }
    }

    /// Create a signature with electrum recovery identifier.
    pub fn new_electrum(r: U256, s: U256, v: u64) -> Self {
        debug_assert!(v == 27 || v == 28);
        Self { r, s, v }
    }

    /// Create a signature with EIP155 chain replay protection.
    pub fn new_eip155(r: U256, s: U256, v: u64) -> Self {
        debug_assert!(v >= 35);
        Self { r, s, v }
    }

    /// Is the recovery identifier for this signature in
    /// the normalized form (`0` or `1`).
    pub fn is_normalized(&self) -> bool {
        self.v == 0 || self.v == 1
    }

    /// Is the recovery identifier for this signature in
    /// the electrum form (`27` or `28`).
    pub fn is_electrum(&self) -> bool {
        self.v == 27 || self.v == 28
    }

    /// Is the recovery identifier for this signature in
    /// the EIP155 form.
    pub fn is_eip155(&self) -> bool {
        self.v >= 35
    }

    /// Converts this signature into normalized form from an Electrum
    /// signature.
    ///
    /// Panics if this signature is not in Electrum format.
    pub fn normalize(self) -> Self {
        assert!(self.is_electrum());
        Self {
            r: self.r,
            s: self.s,
            v: self.v - 27,
        }
    }

    /// Converts this signature into normalized form from an EIP155
    /// signature.
    ///
    /// Panics if the signature could not be safely normalized for
    /// example if a `chain_id` was supplied that would cause the
    /// existing `v` value to become negative.
    pub fn normalize_eip155(self, chain_id: u64) -> Self {
        if self.v >= 35 + (chain_id * 2) {
            Self {
                r: self.r,
                s: self.s,
                v: self.v - chain_id * 2 - 35,
            }
        } else {
            panic!("cannot safely normalize signature recovery identifier")
        }
    }

    /// Converts this signature into Electrum form.
    ///
    /// Panics if this signature is not in it's normalized form.
    pub fn into_electrum(self) -> Self {
        assert!(self.is_normalized());
        Self {
            r: self.r,
            s: self.s,
            v: self.v + 27,
        }
    }

    /// Converts this signature applying
    /// [EIP155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
    /// chain replay protection.
    ///
    /// Panics if this signature is not in it's normalized form.
    pub fn into_eip155(self, chain_id: u64) -> Self {
        assert!(self.is_normalized());
        Self {
            r: self.r,
            s: self.s,
            v: self.v + 35 + chain_id * 2,
        }
    }

    /// Get the bytes for the r and s values.
    pub fn to_bytes(&self) -> [u8; 64] {
        //let mut out = Vec::with_capacity(64);
        let mut out = [0u8; 64];
        let mut r: [u8; 32] = [0u8; 32];
        let mut s: [u8; 32] = [0u8; 32];
        self.r.to_big_endian(&mut r);
        self.s.to_big_endian(&mut s);
        let (left, right) = out.split_at_mut(32);
        left.copy_from_slice(&r);
        right.copy_from_slice(&s);
        out
    }
}

/*
impl From<&Signature> for [u8; 65] {
    fn from(src: &Signature) -> [u8; 65] {
        let mut sig = [0u8; 65];
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        src.r.to_big_endian(&mut r_bytes);
        src.s.to_big_endian(&mut s_bytes);
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        // TODO: What if we try to serialize a signature where
        // the `v` is not normalized?
        sig[64] = src.v as u8;
        sig
    }
}
*/

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = SignatureError;

    /// Parses a raw signature which is expected to be 65 bytes long where
    /// the first 32 bytes is the `r` value, the second 32 bytes the `s` value
    /// and the final byte is the `v` value in 'Electrum' notation.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 65 {
            return Err(SignatureError::InvalidLength(bytes.len()));
        }

        let v = bytes[64];
        let r = U256::from_big_endian(&bytes[0..32]);
        let s = U256::from_big_endian(&bytes[32..64]);

        Ok(Signature { r, s, v: v.into() })
    }
}

impl FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)?;
        Signature::try_from(&bytes[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_into_electrum() {
        let sig = Signature {
            r: Default::default(),
            s: Default::default(),
            v: 1,
        };
        let electrum = sig.into_electrum();
        assert_eq!(28, electrum.v);
    }

    #[test]
    fn signature_from_electrum() {
        let electrum = Signature {
            r: Default::default(),
            s: Default::default(),
            v: 37,
        };
        let sig = electrum.normalize_eip155(1);
        assert_eq!(0, sig.v);
    }

    #[test]
    fn signature_into_eip155() {
        let sig = Signature {
            r: Default::default(),
            s: Default::default(),
            v: 1,
        };
        let eip155 = sig.into_eip155(1337u64);
        assert_eq!(2710, eip155.v);
    }
}
