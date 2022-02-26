use anyhow::Result;

use ethers_providers::Middleware;

use web3_hash_utils::{keccak256, hash_message};
use web3_signature::Signature;
use web3_signers::{coins_bip39::English, MnemonicBuilder};
use web3_transaction::{
    types::{Address, U256},
    eip1559::Eip1559TransactionRequest,
    TransactionRequest, TypedTransaction,
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
    party_i::{SignatureRecid},
};

mod helpers;
use helpers::*;

const MNEMONIC_PHRASE: &str = include_str!("mnemonic.txt");
const PARTIES: u16 = 3;
const ENDPOINT: &str = "http://localhost:8545";

#[tokio::test]
async fn tx_multi_party_legacy() -> Result<()> {
    let provider = provider(ENDPOINT)?;
    let accounts = provider.get_accounts().await?;
    let to = into_address(accounts[1]);

    // Load the mock MPC key shares
    let key_shares = load_key_shares("tests/mpc-keys", PARTIES)?;
    let ks1 = key_shares.get(0).unwrap();
    let ks2 = key_shares.get(1).unwrap();
    let pk1 = ks1.public_key();
    let pk2 = ks2.public_key();
    assert_eq!(pk1, pk2);

    let pk1_bytes = pk1.to_bytes(false).to_vec();
    let mpc_addr = mpc_address(pk1_bytes);

    let balance_before = provider
        .get_balance(into_provider_address(&to), None)
        .await?;

    let balance_before_mpc = provider
        .get_balance(into_provider_address(&mpc_addr), None)
        .await?;

    println!("Got balance for MPC addr: {}", balance_before_mpc);

    // Ensure the MPC address has some funds to spend
    fund_mpc_account(mpc_addr).await?;

    let nonce = into_u256(
        provider
            .get_transaction_count(
                into_provider_address(&mpc_addr),
                Some(ethers_core::types::BlockNumber::Latest.into()),
            )
            .await?,
    );

    let value = 1_000u64;
    // NOTE: must use an Eip1559 transaction
    // NOTE: otherwise ganache/ethers fails to
    // NOTE: parse the correct chain id!
    let tx: TypedTransaction = Eip1559TransactionRequest::new()
        .from(mpc_addr.clone())
        .to(to)
        .value(value)
        .max_fee_per_gas(200_000u64)
        .max_priority_fee_per_gas(22_000_000u64)
        .gas(21_000u64)
        //.gas_price(22_000_000_000u64)
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    dbg!(&tx);

    let sighash = tx.sighash();

    let mut signatures = mpc_signature(&sighash, ks1, ks2)?;
    let signature = signatures.remove(0);

    //recover_secp256k1(sighash.as_ref(), &signature)?;

    let r = signature.r.to_bytes().as_ref().to_vec();
    let s = signature.s.to_bytes().as_ref().to_vec();
    let v = signature.recid as u64;

    println!("M {}", hex::encode(&sighash));
    println!("R {}", hex::encode(&r));
    println!("S {}", hex::encode(&s));
    println!("V {}", signature.recid);

    let signature = Signature {
        r: U256::from_big_endian(&r),
        s: U256::from_big_endian(&s),
        v,
    }
    .into_eip155(1337);
    //.into_electrum();

    /*
    println!("AFTER CONVERSION");
    let s_r: [u8; 32] = signature.r.into();
    let s_s: [u8; 32] = signature.s.into();
    println!("R {}", hex::encode(s_r));
    println!("S {}", hex::encode(s_s));
    println!("V {}", signature.v);
    */

    //println!("Got MPC signature {:#?}", signature);

    let bytes = tx.rlp_signed(&signature);

    println!("tx: 0x{}", hex::encode(&bytes.0));

    /*
    let expected_signed_rlp =
        rlp::Rlp::new(&bytes.0);
    let (decoded_tx, decoded_sig) =
        TransactionRequest::decode_signed_rlp(&expected_signed_rlp)
            .unwrap();

    println!("Decoded tx {:#?}", decoded_tx);
    println!("Decoded sig {:#?}", decoded_sig);
    */

    let tx_receipt = provider.send_raw_transaction(into_bytes(bytes)).await?;
    dbg!(tx_receipt);

    //let balance_after = provider.get_balance(into_provider_address(&mpc_addr), None).await?;

    //println!("Got address {:#?}", mpc_addr);
    //println!("Got balance {:#?}", balance_before);

    //println!("Key shares {:#?}", key_shares);

    Ok(())
}

/*
fn recover_secp256k1<B>(msg: B, signature: &SignatureRecid) -> Result<()> where B: AsRef<[u8]> {
    /// Get a secp256k1 Signature
    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = signature.r.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = signature.s.to_bytes().to_vec();
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let mut secp_sig = secp256k1::Signature::parse_slice(
        compact.as_slice()).unwrap();

    println!("before normalize s: {:#?}", secp_sig.s);
    secp_sig.normalize_s();
    println!("after normalize s: {:#?}", secp_sig.s);

    let rec_id = secp256k1::RecoveryId::parse(signature.recid)?;
    let msg = secp256k1::Message::parse_slice(msg.as_ref())?;
    let pk = secp256k1::recover(&msg, &secp_sig, &rec_id)?;

    let pk_bytes = pk.serialize();
    let hash = keccak256(&pk_bytes[1..]);
    let address = &hash[12..];

    println!("recovered: 0x{}", hex::encode(address));

    Ok(())
}
*/

async fn fund_mpc_account(mpc_addr: Address) -> Result<()> {
    let provider = provider(ENDPOINT)?;

    // Now we need to ensure the MPC address has some funds
    let from = MnemonicBuilder::<English>::default()
        .phrase(MNEMONIC_PHRASE.trim().to_string())
        .build()?
        .with_chain_id(1337u64);

    let addr = into_provider_address(from.address());
    let nonce = into_u256(
        provider
            .get_transaction_count(
                addr.clone(),
                Some(ethers_core::types::BlockNumber::Latest.into()),
            )
            .await?,
    );

    let value = 1_000u64;
    let tx: TypedTransaction = TransactionRequest::new()
        .from(from.address().clone())
        .to(mpc_addr)
        .value(value)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    let signature = from.sign_transaction(&tx).await?;
    let bytes = tx.rlp_signed(&signature);
    let tx_receipt = provider.send_raw_transaction(into_bytes(bytes)).await?;
    Ok(())
}
