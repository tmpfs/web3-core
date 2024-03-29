//! Helper functions for type conversions in order
//! to use the ethers JSON RPC provider.
use anyhow::Result;
use std::path::{Path, PathBuf};
use url::Url;

use ethers_providers::{Http, Middleware, Provider};

use web3_hash_utils::keccak256;
use web3_signers::{
    coins_bip39::English, single_party::SingleParty, MnemonicBuilder, Wallet,
};
use web3_transaction::{
    //eip1559::Eip1559TransactionRequest,
    types::{Address, Bytes, U256},
    TransactionRequest,
    TypedTransaction,
};

use curv::{
    arithmetic::Converter, elliptic::curves::secp256_k1::Secp256k1, BigInt,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    party_i::{verify, SignatureRecid},
    state_machine::{
        keygen::LocalKey,
        sign::{OfflineStage, SignManual},
    },
};
use round_based::StateMachine;

pub const ENDPOINT: &str = "http://localhost:8545";

const PARTIES: u16 = 3;
const MNEMONIC_PHRASE: &str = include_str!("mnemonic.txt");

pub fn provider(src: &str) -> Result<Provider<Http>> {
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()?;
    let url = Url::parse(src)?;
    let http = Http::new_with_client(url, client);
    let provider = Provider::<Http>::new(http);
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

pub fn load_default_key_shares() -> Result<(Address, Vec<LocalKey<Secp256k1>>)>
{
    let key_shares = load_key_shares("test-helpers/mpc-keys", PARTIES)?;
    let ks1 = key_shares.get(0).unwrap();
    let pk1 = ks1.public_key();
    let pk1_bytes = pk1.to_bytes(false).to_vec();
    let mpc_addr = mpc_address(pk1_bytes);
    Ok((mpc_addr, key_shares))
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

/// Generate a signature using the key shares for test MPC.
pub fn mpc_signature<B>(
    message: B,
    ks1: &LocalKey<Secp256k1>,
    ks2: &LocalKey<Secp256k1>,
) -> Result<Vec<SignatureRecid>>
where
    B: AsRef<[u8]>,
{
    // Start signing offline stage, assuming sl_i is key shares
    // with indices 1 and 2
    let mut s1 = OfflineStage::new(1, vec![1, 2], ks1.clone())?;
    let mut s2 = OfflineStage::new(2, vec![1, 2], ks2.clone())?;

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

    Ok(vec![signature1, signature2])
}

pub fn primary_wallet() -> Result<Wallet<SingleParty>> {
    // Now we need to ensure the MPC address has some funds
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(MNEMONIC_PHRASE.trim().to_string())
        .build()?
        .with_chain_id(1337u64);
    Ok(wallet)
}

pub async fn fund_account<'a>(to: Address, value: Option<u64>) -> Result<()> {
    let provider = provider(ENDPOINT)?;

    let from = primary_wallet()?;
    let addr = into_provider_address(from.address());

    let nonce = into_u256(
        provider
            .get_transaction_count(
                addr.clone(),
                Some(ethers_core::types::BlockNumber::Latest.into()),
            )
            .await?,
    );

    let value = value.unwrap_or(1_000_000_000_000_000_000u64);
    let tx: TypedTransaction = TransactionRequest::new()
        .from(from.address().clone())
        .to(to)
        .value(value)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    let signature = from.sign_transaction(&tx).await?;
    let bytes = tx.rlp_signed(&signature);
    let _ = provider.send_raw_transaction(into_bytes(bytes)).await?;
    Ok(())
}
