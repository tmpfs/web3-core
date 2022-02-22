use anyhow::{anyhow, Result};

use ethers_providers::{Provider, Http, Middleware};
use ethers_core::types::Bytes;
use std::convert::TryFrom;

use web3_signers::{single_party::SingleParty, Sign, Wallet, MnemonicBuilder, coins_bip39::English};

use web3_hash_utils::to_checksum;
use web3_transaction::{TransactionRequest, eip1559::Eip1559TransactionRequest, TypedTransaction};
use web3_transaction::types::{U256, Address};

fn checksum(input: &Address) -> Address {
    let addr = to_checksum(input, None);
    let addr_bytes = hex::decode(addr.as_bytes()[2..].to_vec()).unwrap();
    Address::from_slice(&addr_bytes)
}

fn signer(index: usize) -> Result<Wallet<SingleParty>> {
    // Test signers from Ganache - well known.
    let signers = vec![
        (
            "0x140e8445989105F22803172f82140E9a92B5918B",
            "0xda3a15512c6e44882f6e19c17312f8e1cadb6b96e1b7021642d89c538a1af626"
        ),
        (
            "0xF6D6424b5d8033D5d1Fa386A3d5aCe4A2f5f344d",
            "0xa24c9c6095a80d1b3633a12fc7a7b51ed3f3370bc6ee6cd058b0f76883a035c4"
        ),
        (
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
        ),
        (
            "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
            "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
        ),
        (
            "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
            "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
        )
    ];

    let (address, private_key) = signers.get(index)
        .ok_or_else(|| anyhow!("signer index is out of bounds"))?;

    let private_key_bytes = hex::decode(&private_key[2..])?;
    let signer = SingleParty::from_bytes(&private_key_bytes)?;
    let signer_address = format!("{}", signer);
    let address = signer.address().clone();

    //println!("{}", address);
    //println!("{}", checksum(&signer.address()));
    //assert_eq!(address, checksum(&signer_address));

    let wallet = Wallet::new(signer, address, 1337);
    Ok(wallet)
}

fn provider() -> Result<Provider::<Http>> {
    let provider = Provider::<Http>::try_from(
        "http://localhost:8545"
    )?;
    Ok(provider)
}

#[tokio::test]
async fn tx_sign_legacy() -> Result<()> {
    let (from, to) = (signer(0)?, signer(1)?);

    let provider = provider()?;
    let accounts = provider.get_accounts().await?;
    let signer1 = accounts[0];
    let signer2 = accounts[1];


    let first_wallet = MnemonicBuilder::<English>::default()
        .phrase("comfort expect symptom success relax hockey position catalog grab fall resist guitar")
        .build()?;

    //signer1.foo();

    //println!("Accounts: {:#?}", accounts)
    //

    //let addr = ethers_core::types::NameOrAddress::Address(
        //ethers_core::types::Address::from_slice(from.address().as_ref()));

    //let balance_before = provider.get_balance(
        //addr, None).await?;

    //println!("Balance before {:#?}", signer1);
    //println!("Balance before {}", from);
    //println!("Balance before {:#?}", balance_before);

    //let from_addr = Address::from_slice(&hex::decode("dAa69C45671f3012e20Ac3240fefE55C20c9f5Ca")?);

    let value = 1_000_000u64;
    let data: Vec<u8> = vec![];
    let tx = TransactionRequest::new()
        .from(first_wallet.address().clone())
        .to(to.address().clone())
        .value(U256::from(value))
        .gas(21_000u64)
        .gas_price(22_000u64)
        //.max_fee_per_gas(300_000u64)
        //.max_priority_fee_per_gas(50_000u64)
        //.nonce(3)
        //.data(data);
        //.chain_id(1337)
        ;

    println!("Tx sign test {:#?}", tx);

    //let signature = from.sign_transaction(
        //&TypedTransaction::Eip1559(tx.clone())).await?;

    let signature = from.sign_transaction(
        &TypedTransaction::Legacy(tx.clone())).await?;
    //let signature = signature.normalize_eip155(1337).into_electrum();
    //println!("Got signature {:#?}", signature);

    let bytes = tx.rlp_signed(&signature);
    //let bytes = tx.rlp();
    //let raw_hex = hex::encode(&bytes);

    //println!("Tx sign test {:#?}", raw_hex);

    //let sig_1 = provider.sign(Bytes(bytes.0.clone()), &signer1).await?;
    //println!("Sig 1 {:#?}", sig_1);

    let tx_receipt = provider.send_raw_transaction(Bytes(bytes.0)).await?;

    println!("Pending transaction: {:#?}", tx_receipt);

    Ok(())
}
