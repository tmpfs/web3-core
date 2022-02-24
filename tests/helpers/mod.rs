//! Helper functions for type conversions in order
//! to use the ethers JSON RPC provider.
use anyhow::Result;

use ethers_providers::{Http, Provider};
use std::convert::TryFrom;

use web3_transaction::types::{Address, Bytes, U256};

pub fn provider(url: &str) -> Result<Provider<Http>> {
    let provider = Provider::<Http>::try_from(url)?;
    Ok(provider)
}

pub fn into_bytes(bytes: Bytes) -> ethers_core::types::Bytes {
    ethers_core::types::Bytes(bytes.0)
}

pub fn into_provider_address(
    address: &Address,
) -> ethers_core::types::NameOrAddress {
    ethers_core::types::NameOrAddress::Address(
        ethers_core::types::Address::from_slice(address.as_ref()),
    )
}

pub fn into_address(address: ethers_core::types::H160) -> Address {
    let to_bytes: [u8; 20] = address.into();
    Address::from_slice(&to_bytes)
}

pub fn into_u256(value: ethers_core::types::U256) -> U256 {
    let nonce_bytes: [u8; 32] = value.into();
    U256::from_big_endian(&nonce_bytes)
}
