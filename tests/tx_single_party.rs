use anyhow::Result;

use ethers_providers::Middleware;

use web3_signers::{coins_bip39::English, MnemonicBuilder};
use web3_transaction::{TransactionRequest, TypedTransaction};

mod helpers;
use helpers::*;

const MNEMONIC_PHRASE: &str = include_str!("mnemonic.txt");

#[tokio::test]
async fn tx_sign_legacy() -> Result<()> {
    let provider = provider("http://localhost:8545")?;
    let accounts = provider.get_accounts().await?;
    let to = into_address(accounts[1]);

    let from = MnemonicBuilder::<English>::default()
        .phrase(MNEMONIC_PHRASE.trim().to_string())
        .build()?
        .with_chain_id(1337u64);

    let addr = into_provider_address(from.address());

    let balance_before = provider.get_balance(addr.clone(), None).await?;

    let nonce = into_u256(
        provider
            .get_transaction_count(
                addr.clone(),
                Some(ethers_core::types::BlockNumber::Latest.into()),
            )
            .await?,
    );

    let value = 1_000_000u64;
    //let data: Vec<u8> = vec![];
    let tx: TypedTransaction = TransactionRequest::new()
        .from(from.address().clone())
        .to(to)
        .value(value)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        //.max_fee_per_gas(300_000u64)
        //.max_priority_fee_per_gas(50_000u64)
        //.nonce(nonce1)
        //.data(data);
        .chain_id(1337u64)
        .nonce(nonce)
        .into();

    dbg!(&tx);

    let signature = from.sign_transaction(&tx).await?;
    dbg!(&signature);

    let bytes = tx.rlp_signed(&signature);
    dbg!(hex::encode(&bytes.0));

    let tx_receipt = provider.send_raw_transaction(into_bytes(bytes)).await?;
    dbg!(tx_receipt);

    let balance_after = provider.get_balance(addr.clone(), None).await?;
    assert!(balance_after < balance_before);

    Ok(())
}
