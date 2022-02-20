use anyhow::Result;
use web3_keystore::{decrypt, encrypt, new_random, KeyStore};

fn load_test_key(name: &str) -> Result<KeyStore> {
    let path = format!("./tests/test-keys/{}", name);
    let contents = std::fs::read_to_string(&path)?;
    let keystore: KeyStore = serde_json::from_str(&contents)?;
    Ok(keystore)
}

#[test]
fn test_new() -> Result<()> {
    let mut rng = rand::thread_rng();
    let (keystore, secret) = new_random(&mut rng, "thebestrandompassword")?;

    assert_eq!(decrypt(&keystore, "thebestrandompassword")?, secret);
    assert!(decrypt(&keystore, "notthebestrandompassword").is_err());
    Ok(())
}

#[test]
fn test_decrypt_pbkdf2() -> Result<()> {
    let secret = hex::decode(
        "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    )?;
    let keystore = load_test_key("key-pbkdf2.json")?;
    assert_eq!(decrypt(&keystore, "testpassword")?, secret);
    assert!(decrypt(&keystore, "wrongtestpassword").is_err());
    Ok(())
}

#[test]
fn test_decrypt_scrypt() -> Result<()> {
    let secret = hex::decode(
        "80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829",
    )
    .unwrap();
    let keystore = load_test_key("key-scrypt.json")?;
    assert_eq!(decrypt(&keystore, "grOQ8QDnGHvpYJf")?, secret);
    assert!(decrypt(&keystore, "thisisnotrandom").is_err());
    Ok(())
}

#[test]
fn test_encrypt_decrypt() -> Result<()> {
    let secret = hex::decode(
        "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    )
    .unwrap();
    let mut rng = rand::thread_rng();
    let keystore = encrypt(&mut rng, &secret, "newpassword", None)?;

    assert_eq!(decrypt(&keystore, "newpassword")?, secret);
    assert!(decrypt(&keystore, "notanewpassword").is_err());
    Ok(())
}
