use anyhow::Result;

use ethers_core::types::Bytes;
use ethers_providers::{Http, Middleware, Provider};
use std::convert::TryFrom;

use web3_signers::{coins_bip39::English, MnemonicBuilder};

use web3_transaction::types::{Address, U256};
use web3_transaction::{TransactionRequest, TypedTransaction};

fn provider(url: &str) -> Result<Provider<Http>> {
    let provider = Provider::<Http>::try_from(url)?;
    Ok(provider)
}

fn into_provider_address(
    address: &Address,
) -> ethers_core::types::NameOrAddress {
    ethers_core::types::NameOrAddress::Address(
        ethers_core::types::Address::from_slice(address.as_ref()),
    )
}

fn into_address(address: ethers_core::types::H160) -> Address {
    let to_bytes: [u8; 20] = address.into();
    Address::from_slice(&to_bytes)
}

fn into_u256(value: ethers_core::types::U256) -> U256 {
    let nonce_bytes: [u8; 32] = value.into();
    U256::from_big_endian(&nonce_bytes)
}

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

    let tx_receipt = provider.send_raw_transaction(Bytes(bytes.0)).await?;
    dbg!(tx_receipt);

    let balance_after = provider.get_balance(addr.clone(), None).await?;
    assert!(balance_after < balance_before);

    Ok(())
}
