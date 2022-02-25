//! Helper functions for type conversions in order
//! to use the ethers JSON RPC provider.
use anyhow::Result;
use std::path::{Path, PathBuf};

use ethers_providers::{Http, Provider};
use std::convert::TryFrom;

use web3_hash_utils::keccak256;
use web3_transaction::types::{Address, Bytes, U256};

use curv::{
    arithmetic::Converter, elliptic::curves::secp256_k1::Secp256k1, BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    party_i::verify,
    state_machine::{
        keygen::LocalKey,
        sign::{OfflineStage, SignManual},
    },
};
use round_based::StateMachine;

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

pub fn load_key_shares<P: AsRef<Path>>(
    dir: P,
    parties: u16,
) -> Result<Vec<LocalKey<Secp256k1>>> {
    let base = PathBuf::from(dir.as_ref());
    let mut out = Vec::with_capacity(parties as usize);
    for i in 0..parties {
        let path = base.join(&format!("key-share-{}.json", i + 1));
        let contents = std::fs::read_to_string(path)?;
        let key_share: LocalKey<Secp256k1> = serde_json::from_str(&contents)?;
        out.push(key_share);
    }
    Ok(out)
}

/// Compute the address of an uncompressed public key (65 bytes).
pub fn mpc_address(bytes: Vec<u8>) -> Address {
    let public_key: [u8; 65] =
        bytes.try_into().expect("address bytes should be 65");
    // Remove the leading 0x04
    let bytes = &public_key[1..];
    let digest = keccak256(bytes);
    let final_bytes = &digest[12..];
    Address::from_slice(final_bytes)
}

pub fn mpc_signature<B>(
    message: B,
    ks1: LocalKey<Secp256k1>,
    ks2: LocalKey<Secp256k1>,
) -> Result<()>
where
    B: AsRef<[u8]>,
{
    // Start signing offline stage, assuming sl_i is key shares
    // with indices 1 and 2
    let mut s1 = OfflineStage::new(1, vec![1, 2], ks1)?;
    let mut s2 = OfflineStage::new(2, vec![1, 2], ks2)?;

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    let s1_r1: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r1.is_empty());

    let s2_r1: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r1.is_empty());

    debug_assert_eq!(1, s1.current_round());
    debug_assert_eq!(1, s2.current_round());

    // Feed incoming messages to signer 1 for round 1
    for m in s2_r1.iter() {
        s1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to signer 2 for round 1
    for m in s1_r1.iter() {
        s2.handle_incoming(m.clone())?;
    }

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    let s1_r2: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r2.is_empty());

    let s2_r2: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r2.is_empty());

    debug_assert_eq!(2, s1.current_round());
    debug_assert_eq!(2, s2.current_round());

    // Handle round 2 as p2p
    for m in s1_r2.iter().chain(s2_r2.iter()) {
        if let Some(receiver) = &m.receiver {
            match receiver {
                1 => s1.handle_incoming(m.clone())?,
                2 => s2.handle_incoming(m.clone())?,
                _ => panic!("unknown party index (sign)"),
            }
        }
    }

    let s1_r3: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r3.is_empty());

    let s2_r3: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r3.is_empty());

    debug_assert_eq!(3, s1.current_round());
    debug_assert_eq!(3, s2.current_round());

    // Feed incoming messages to signer 1 for round 3
    for m in s2_r3.iter() {
        s1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to signer 2 for round 3
    for m in s1_r3.iter() {
        s2.handle_incoming(m.clone())?;
    }

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    let s1_r4: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r4.is_empty());

    let s2_r4: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r4.is_empty());

    debug_assert_eq!(4, s1.current_round());
    debug_assert_eq!(4, s2.current_round());

    // Feed incoming messages to signer 1 for round 4
    for m in s2_r4.iter() {
        s1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to signer 2 for round 4
    for m in s1_r4.iter() {
        s2.handle_incoming(m.clone())?;
    }

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    let s1_r5: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r5.is_empty());

    let s2_r5: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r5.is_empty());

    debug_assert_eq!(5, s1.current_round());
    debug_assert_eq!(5, s2.current_round());

    // Feed incoming messages to signer 1 for round 5
    for m in s2_r5.iter() {
        s1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to signer 2 for round 5
    for m in s1_r5.iter() {
        s2.handle_incoming(m.clone())?;
    }

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    let s1_r6: Vec<_> = {
        s1.proceed()?;
        s1.message_queue().drain(..).collect()
    };
    debug_assert!(!s1_r6.is_empty());

    let s2_r6: Vec<_> = {
        s2.proceed()?;
        s2.message_queue().drain(..).collect()
    };
    debug_assert!(!s2_r6.is_empty());

    debug_assert_eq!(6, s1.current_round());
    debug_assert_eq!(6, s2.current_round());

    // Feed incoming messages to signer 1 for round 6
    for m in s2_r6.iter() {
        s1.handle_incoming(m.clone())?;
    }

    // Feed incoming messages to signer 2 for round 6
    for m in s1_r6.iter() {
        s2.handle_incoming(m.clone())?;
    }

    debug_assert!(s1.wants_to_proceed());
    debug_assert!(s2.wants_to_proceed());

    s1.proceed()?;
    s2.proceed()?;

    debug_assert!(s1.is_finished());
    debug_assert!(s2.is_finished());

    let s1_completed = s1.pick_output().unwrap()?;
    let s2_completed = s2.pick_output().unwrap()?;

    let s1_pk = s1_completed.public_key().clone();
    let s2_pk = s2_completed.public_key().clone();

    let data = BigInt::from_bytes(message.as_ref());

    // Sign the message
    let (sign1, partial1) = SignManual::new(data.clone(), s1_completed)?;
    let (sign2, partial2) = SignManual::new(data.clone(), s2_completed)?;

    // In the real world we need to broadcast and
    // wait for the partial signatures

    let sigs1 = vec![partial2];
    let sigs2 = vec![partial1];

    let signature1 = sign1.complete(&sigs1)?;
    let signature2 = sign2.complete(&sigs2)?;

    debug_assert!(verify(&signature1, &s1_pk, &data).is_ok());
    debug_assert!(verify(&signature2, &s2_pk, &data).is_ok());

    Ok(())
}
