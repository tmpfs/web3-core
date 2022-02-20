use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
/// Opaque type that represents an encrypted keystore based on the
/// [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
pub struct KeyStore {
    /// Version of the Web3 Secret storage definition specification.
    pub version: u8,
    /// Unique identifier for the keystore.
    pub id: Uuid,
    /// Optional public address for the keystore (non-standard).
    pub address: Option<String>,
    /// Crypto part of the keystore.
    pub(crate) crypto: CryptoData,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "crypto" part of an encrypted keystore.
pub struct CryptoData {
    pub cipher: String,
    pub cipherparams: CipherParams,
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    pub ciphertext: Vec<u8>,
    pub kdf: KdfType,
    pub kdfparams: KdfParamsType,
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    pub mac: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// Represents the "cipherparams" part of an encrypted JSON keystore.
pub struct CipherParams {
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    pub iv: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
/// Types of key derivation functions supported by Web3 Secret Storage.
pub enum KdfType {
    Pbkdf2,
    Scrypt,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
/// Defines the various parameters used in the supported KDFs.
pub enum KdfParamsType {
    Pbkdf2 {
        c: u32,
        dklen: u8,
        prf: String,
        #[serde(
            serialize_with = "hex::serde::serialize",
            deserialize_with = "hex::serde::deserialize"
        )]
        salt: Vec<u8>,
    },
    Scrypt {
        dklen: u8,
        n: u32,
        p: u32,
        r: u32,
        #[serde(
            serialize_with = "hex::serde::serialize",
            deserialize_with = "hex::serde::deserialize"
        )]
        salt: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_deserialize_pbkdf2() -> Result<()> {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "6087dab2f9fdbbfaddc31a909735c1e6"
                },
                "ciphertext" : "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
                "kdf" : "pbkdf2",
                "kdfparams" : {
                    "c" : 262144,
                    "dklen" : 32,
                    "prf" : "hmac-sha256",
                    "salt" : "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                },
                "mac" : "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: KeyStore = serde_json::from_str(data)?;
        assert_eq!(keystore.version, 3);
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6")?
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            hex::decode("6087dab2f9fdbbfaddc31a909735c1e6")?
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            hex::decode("5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46")?
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Pbkdf2);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfParamsType::Pbkdf2 {
                c: 262144,
                dklen: 32,
                prf: String::from("hmac-sha256"),
                salt: hex::decode(
                    "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
                )?,
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            hex::decode("517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2")?
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_scrypt() -> Result<()> {
        let data = r#"
        {
            "crypto" : {
                "cipher" : "aes-128-ctr",
                "cipherparams" : {
                    "iv" : "83dbcc02d8ccb40e466191a123791e0e"
                },
                "ciphertext" : "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c",
                "kdf" : "scrypt",
                "kdfparams" : {
                    "dklen" : 32,
                    "n" : 262144,
                    "p" : 8,
                    "r" : 1,
                    "salt" : "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                },
                "mac" : "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"
            },
            "id" : "3198bc9c-6672-5ab3-d995-4942343ae5b6",
            "version" : 3
        }"#;
        let keystore: KeyStore = serde_json::from_str(data)?;
        assert_eq!(keystore.version, 3);
        assert_eq!(
            keystore.id,
            Uuid::parse_str("3198bc9c-6672-5ab3-d995-4942343ae5b6")?
        );
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");
        assert_eq!(
            keystore.crypto.cipherparams.iv,
            hex::decode("83dbcc02d8ccb40e466191a123791e0e")?
        );
        assert_eq!(
            keystore.crypto.ciphertext,
            hex::decode("d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c")?
        );
        assert_eq!(keystore.crypto.kdf, KdfType::Scrypt);
        assert_eq!(
            keystore.crypto.kdfparams,
            KdfParamsType::Scrypt {
                dklen: 32,
                n: 262144,
                p: 8,
                r: 1,
                salt: hex::decode(
                    "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"
                )?,
            }
        );
        assert_eq!(
            keystore.crypto.mac,
            hex::decode("2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097")?
        );
        Ok(())
    }
}
