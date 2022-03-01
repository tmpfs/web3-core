use anyhow::Result;

use ethers_providers::Middleware;
use web3_signature::Signature;
use web3_transaction::{
    eip1559::Eip1559TransactionRequest, types::U256, TypedTransaction,
};

use web3_test_helpers::*;

#[tokio::test]
async fn tx_multi_party_eip1559() -> Result<()> {
    let provider = provider(ENDPOINT)?;
    let accounts = provider.get_accounts().await?;
    let to = into_address(accounts[1]);

    // Load the mock MPC key shares
    let (mpc_addr, key_shares) = load_default_key_shares()?;
    let ks1 = key_shares.get(0).unwrap();
    let ks2 = key_shares.get(1).unwrap();

    let balance_before = provider
        .get_balance(into_provider_address(&mpc_addr), None)
        .await?;

    dbg!(&balance_before);

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
        .max_fee_per_gas(800_000_000u64)
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

    let r = signature.r.to_bytes().as_ref().to_vec();
    let s = signature.s.to_bytes().as_ref().to_vec();
    let v = signature.recid as u64;

    dbg!(format!("M {}", hex::encode(&sighash)));
    dbg!(format!("R {}", hex::encode(&r)));
    dbg!(format!("S {}", hex::encode(&s)));
    dbg!(format!("V {}", signature.recid));

    let signature = Signature {
        r: U256::from_big_endian(&r),
        s: U256::from_big_endian(&s),
        v,
    }
    .into_eip155(1337);

    let bytes = tx.rlp_signed(&signature);

    dbg!(format!("0x{}", hex::encode(&bytes.0)));

    let tx_receipt = provider.send_raw_transaction(into_bytes(bytes)).await?;
    dbg!(tx_receipt);

    Ok(())
}
