use anyhow::Result;

use ethers_providers::Middleware;

use web3_signers::{coins_bip39::English, MnemonicBuilder};
use web3_transaction::{TransactionRequest, TypedTransaction, types::Address};

mod helpers;
use helpers::*;

const MNEMONIC_PHRASE: &str = include_str!("mnemonic.txt");
const PARTIES: u16 = 3;

#[tokio::test]
async fn tx_multi_party_legacy() -> Result<()> {
    let provider = provider("http://localhost:8545")?;
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

    // Ensure the MPC address has some funds to spend
    fund_mpc_account(mpc_addr).await?;

    let balance_before = provider.get_balance(into_provider_address(&to), None).await?;

    let nonce = into_u256(
        provider
            .get_transaction_count(
                into_provider_address(&mpc_addr),
                Some(ethers_core::types::BlockNumber::Latest.into()),
            )
            .await?,
    );

    let value = 1_000u64;
    let tx: TypedTransaction = TransactionRequest::new()
        .from(mpc_addr.clone())
        .to(to)
        .value(value)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    dbg!(&tx);

    //let balance_before = provider.get_balance(into_provider_address(&mpc_addr), None).await?;

    //println!("Got address {:#?}", mpc_addr);
    //println!("Got balance {:#?}", balance_before);

    //println!("Key shares {:#?}", key_shares);

    Ok(())
}

async fn fund_mpc_account(mpc_addr: Address) -> Result<()> {
    let provider = provider("http://localhost:8545")?;

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

    let value = 1_000_000u64;
    let tx: TypedTransaction = TransactionRequest::new()
        .from(from.address().clone())
        .to(mpc_addr)
        .value(value)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    //dbg!(&tx);

    let signature = from.sign_transaction(&tx).await?;
    //dbg!(&signature);

    let bytes = tx.rlp_signed(&signature);
    //dbg!(hex::encode(&bytes.0));

    let tx_receipt = provider.send_raw_transaction(into_bytes(bytes)).await?;
    //dbg!(tx_receipt);

    //let mpc_balance= provider.get_balance(into_provider_address(&mpc_addr), None).await?;

    Ok(())
}
