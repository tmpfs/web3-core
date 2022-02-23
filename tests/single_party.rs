use anyhow::{anyhow, Result};

use ethers_providers::{Provider, Http, Middleware};
use ethers_core::types::Bytes;
use std::convert::TryFrom;

use web3_signers::{single_party::SingleParty, Sign, Wallet, MnemonicBuilder, coins_bip39::English};

use web3_hash_utils::to_checksum;
use web3_transaction::{TransactionRequest, eip1559::Eip1559TransactionRequest, TypedTransaction, types::BlockNumber};
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

    //println!("Ganache private key: {}", &private_key[2..]);

    let private_key_bytes = hex::decode(&private_key[2..])?;
    let signer = SingleParty::from_bytes(&private_key_bytes)?;
    let signer_address = format!("{}", signer);
    let address = signer.address().clone();

    //println!("Signer private key: {}", hex::encode(signer.to_bytes()));

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
    //let to = signer(0)?;

    let provider = provider()?;
    let accounts = provider.get_accounts().await?;
    let to = accounts[1];

    let to_bytes: [u8; 20] = to.into();
    let to = Address::from_slice(&to_bytes);

    let from = MnemonicBuilder::<English>::default()
        .phrase("comfort expect symptom success relax hockey position catalog grab fall resist guitar")
        .build()?
        .with_chain_id(1337u64);

    println!("From private key: {}", hex::encode(from.signer().to_bytes()));

    let addr = ethers_core::types::NameOrAddress::Address(
        ethers_core::types::Address::from_slice(from.address().as_ref()));

    let balance_before = provider.get_balance(
        addr.clone(), None).await?;

    //println!("Balance before {:#?}", signer1);
    //println!("Balance before {}", from);
    //println!("Balance before {:#?}", balance_before);

    //let from_addr = Address::from_slice(&hex::decode("dAa69C45671f3012e20Ac3240fefE55C20c9f5Ca")?);
    //
    let nonce1 = provider.get_transaction_count(
        addr.clone(), Some(ethers_core::types::BlockNumber::Latest.into())).await?;

    let nonce_bytes: [u8; 32] = nonce1.into();
    let nonce1 = U256::from_big_endian(&nonce_bytes);

    let value = 1_000u64;
    let data: Vec<u8> = vec![];
    let tx: TypedTransaction = TransactionRequest::new()
        .from(from.address().clone())
        .to(to)
        .value(1000)
        .gas(21_000u64)
        .gas_price(22_000_000_000u64)
        //.max_fee_per_gas(300_000u64)
        //.max_priority_fee_per_gas(50_000u64)
        //.nonce(nonce1)
        //.data(data);
        .chain_id(1337u64)
        .nonce(nonce1)
        .into()
        ;

    println!("Tx {:#?}", tx);

    //let signature = from.sign_transaction(
        //&TypedTransaction::Eip1559(tx.clone())).await?;

    let signature = from.sign_transaction(&tx).await?;
    println!("Signature {:#?}", signature);

    let signature = from.sign_transaction(&tx).await?;
    println!("Signature {:#?}", signature);

    //let signature = signature.normalize_eip155(1337).into_electrum();
    //println!("Got signature {:#?}", signature);

    let bytes = tx.rlp_signed(&signature);

    println!("Bytes {}", hex::encode(&bytes.0));

    // Bytes f8680985051f4d5c0082520894e2af91e419974999c22b1de7eaada5bf02c4e09f8203e880820a96a0cd0ebacd88f982e8062b735f9586802a7be2a5adc10beca2e97989ac6fee1b5ca030275fe46ed9b8b38a3cd618d5aa6e2be8793c3e7d0bcb4af694e3729da67f7e
    //
    // Bytes f8680a85051f4d5c0082520894140e8445989105f22803172f82140e9a92b5918b8203e880820a96a059f5970909140fd913cc859401bc8eac218f67ca11d63a4f2686a7439e6a835ba0617a84cff0c1241b0f1bde8123ef7582fa0760d15a8afd376109fa228e02421b

    //let bytes = tx.rlp();
    //let raw_hex = hex::encode(&bytes);

    //println!("Tx sign test {:#?}", raw_hex);

    //let sig_1 = provider.sign(Bytes(bytes.0.clone()), &signer1).await?;
    //println!("Sig 1 {:#?}", sig_1);

    //let tx_receipt = provider.send_raw_transaction(Bytes(bytes.0)).await?;

    let tx_receipt = provider
        .send_raw_transaction(Bytes(bytes.0))
        .await?;

    println!("Pending transaction: {:#?}", tx_receipt);

    Ok(())
}
