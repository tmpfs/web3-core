//! Types to represent signatures with various recovery identifiers.
use serde::{Deserialize, Serialize};
use ethereum_types::U256;

/// An ECDSA signature with a normalized recovery identifier.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub struct Signature {
    /// R value
    pub r: U256,
    /// S Value
    pub s: U256,
    /// V value in normalized notation (either `0` or `1`).
    pub v: u64,
}

impl From<ElectrumSignature> for Signature {
    fn from(sig: ElectrumSignature) -> Self {
        Self {
            r: sig.r,
            s: sig.s,
            v: sig.v - 27,
        }
    }
}

impl Signature {
    /// Converts this signature applying
    /// [EIP155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
    /// chain replay protection.
    pub(crate) fn into_eip155(self, chain_id: u64) -> Eip155Signature {
        Eip155Signature {
            r: self.r,
            s: self.s,
            v: self.v + 35 + chain_id * 2,
        }
    }

    /// Get the bytes for the r and s values.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        let mut r: [u8; 32] = [0u8; 32];
        let mut s: [u8; 32] = [0u8; 32];
        self.r.to_big_endian(&mut r);
        self.s.to_big_endian(&mut s);
        out.extend_from_slice(&r);
        out.extend_from_slice(&s);
        out
    }
}

/// An ECDSA signature with Electrum style recovery id.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct ElectrumSignature {
    /// R value
    pub r: U256,
    /// S Value
    pub s: U256,
    /// V value in Electrum notation (either `27` or `28`).
    pub v: u64,
}

impl From<Signature> for ElectrumSignature {
    fn from(sig: Signature) -> Self {
        Self {
            r: sig.r,
            s: sig.s,
            v: sig.v + 27,
        }
    }
}

/// An ECDSA signature with
/// [EIP155](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md)
/// chain replay protection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub(crate) struct Eip155Signature {
    /// R value
    pub r: U256,
    /// S Value
    pub s: U256,
    /// V value with EIP155 chain replay protection.
    pub v: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_electrum() {
        let sig = Signature {
            r: Default::default(),
            s: Default::default(),
            v: 1,
        };
        let electrum: ElectrumSignature = sig.into();
        assert_eq!(28, electrum.v);
    }

    #[test]
    fn test_from_electrum() {
        let electrum = ElectrumSignature {
            r: Default::default(),
            s: Default::default(),
            v: 27,
        };
        let sig: Signature = electrum.into();
        assert_eq!(0, sig.v);
    }

    #[test]
    fn test_into_eip155() {
        let sig = Signature {
            r: Default::default(),
            s: Default::default(),
            v: 1,
        };
        let eip155 = sig.into_eip155(1337u64);
        assert_eq!(2710, eip155.v);
    }
}
