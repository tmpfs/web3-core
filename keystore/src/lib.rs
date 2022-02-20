//! Library to encrypt and decrypt keystores as per the
//! [Web3 Secret Storage Definition](https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition).
//!
//! This is a fork of
//! [eth-keystore-rs](https://docs.rs/eth-keystore/latest/eth_keystore/) which
//! does not write to disc automatically so is
//! easier to integrate with WASM and storage
//! destinations other than the file system.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use aes::cipher::{KeyIvInit, StreamCipher};
use digest::{Digest, Update};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use sha2::Sha256;
use sha3::Keccak256;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
/// An error thrown when encrypting or decrypting keystores.
pub enum KeyStoreError {
    /// An error thrown while decrypting an encrypted
    /// keystore if the computed MAC does not
    /// match the MAC declared in the keystore.
    #[error("Mac Mismatch")]
    MacMismatch,
    /// Invalid scrypt parameters
    #[error("scrypt {0:?}")]
    ScryptInvalidParams(scrypt::errors::InvalidParams),
    /// Invalid scrypt output length
    #[error("scrypt {0:?}")]
    ScryptInvalidOuputLen(scrypt::errors::InvalidOutputLen),
    /// Invalid aes key nonce length
    #[error("aes {0:?}")]
    AesInvalidKeyNonceLength(aes::cipher::InvalidLength),
}

impl From<scrypt::errors::InvalidParams> for KeyStoreError {
    fn from(e: scrypt::errors::InvalidParams) -> Self {
        Self::ScryptInvalidParams(e)
    }
}

impl From<scrypt::errors::InvalidOutputLen> for KeyStoreError {
    fn from(e: scrypt::errors::InvalidOutputLen) -> Self {
        Self::ScryptInvalidOuputLen(e)
    }
}

impl From<aes::cipher::InvalidLength> for KeyStoreError {
    fn from(e: aes::cipher::InvalidLength) -> Self {
        Self::AesInvalidKeyNonceLength(e)
    }
}

mod keystore;

use keystore::{CipherParams, CryptoData, KdfParamsType, KdfType};

pub use keystore::KeyStore;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

const DEFAULT_CIPHER: &str = "aes-128-ctr";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

/// Creates a new keystore using a random 32 byte secret and the
/// [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// key derivation function.
///
/// The keystore is encrypted by a key derived from the provided `password`.
///
/// # Example
///
/// ```no_run
/// use web3_keystore::new_random;
/// let mut rng = rand::thread_rng();
/// let password = "super-secret-password";
/// let (keystore, secret) = new_random(&mut rng, password).unwrap();
/// assert_eq!(32, secret.len());
/// ```
pub fn new_random<R, S>(
    rng: &mut R,
    password: S,
) -> Result<(KeyStore, Vec<u8>), KeyStoreError>
where
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    let pk: [u8; DEFAULT_KEY_SIZE] = rng.gen();
    Ok((encrypt(rng, &pk, password, None)?, pk.to_vec()))
}

/// Decrypts an encrypted keystore using the provided `password`.
///
/// Decryption supports the
/// [Scrypt](https://tools.ietf.org/html/rfc7914.html) and
/// [PBKDF2](https://ietf.org/rfc/rfc2898.txt) key derivation functions.
///
/// # Example
///
/// ```
/// use web3_keystore::{decrypt, new_random};
/// let mut rng = rand::thread_rng();
/// let password = "super-secret-password";
/// let (keystore, secret) = new_random(&mut rng, password).unwrap();
/// let private_key = decrypt(&keystore, password).unwrap();
/// assert_eq!(secret, private_key);
/// ```
pub fn decrypt<S>(
    keystore: &KeyStore,
    password: S,
) -> Result<Vec<u8>, KeyStoreError>
where
    S: AsRef<[u8]>,
{
    // Derive the key.
    let key = match &keystore.crypto.kdfparams {
        KdfParamsType::Pbkdf2 {
            c,
            dklen,
            prf: _,
            salt,
        } => {
            let mut key = vec![0u8; *dklen as usize];
            pbkdf2::<Hmac<Sha256>>(
                password.as_ref(),
                salt,
                *c,
                key.as_mut_slice(),
            );
            key
        }
        KdfParamsType::Scrypt {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; *dklen as usize];
            let log_n = (*n as f32).log2() as u8;
            let scrypt_params = ScryptParams::new(log_n, *r, *p)?;
            scrypt(
                password.as_ref(),
                salt,
                &scrypt_params,
                key.as_mut_slice(),
            )?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let derived_mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&keystore.crypto.ciphertext)
        .finalize();

    if derived_mac.as_slice() != keystore.crypto.mac.as_slice() {
        return Err(KeyStoreError::MacMismatch);
    }

    // Decrypt the private key bytes using AES-128-CTR
    let mut decryptor = Aes128Ctr::new(
        (&key[..16]).into(),
        (&keystore.crypto.cipherparams.iv[..16]).into(),
    );

    let mut pk = keystore.crypto.ciphertext.clone();
    decryptor.apply_keystream(&mut pk);

    Ok(pk)
}

/// Encrypts the given private key using the
/// [Scrypt](https://tools.ietf.org/html/rfc7914.html)
/// password-based key derivation function.
///
/// # Example
///
/// ```
/// use web3_keystore::{encrypt, decrypt};
/// use rand::Rng;
/// let mut rng = rand::thread_rng();
/// let secret: [u8; 32] = rng.gen();
/// let password = "super-secret-password";
/// let address = Some(String::from("0x0"));
/// let keystore = encrypt(
///     &mut rng, &secret, password, address).unwrap();
/// let private_key = decrypt(&keystore, password).unwrap();
/// assert_eq!(secret.to_vec(), private_key);
/// ```
pub fn encrypt<R, B, S>(
    rng: &mut R,
    pk: B,
    password: S,
    address: Option<String>,
) -> Result<KeyStore, KeyStoreError>
where
    R: Rng + CryptoRng,
    B: AsRef<[u8]>,
    S: AsRef<[u8]>,
{
    // Generate a random salt.
    let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
    rng.fill_bytes(salt.as_mut_slice());

    // Derive the key.
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());

    let mut encryptor = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());

    let mut ciphertext = pk.as_ref().to_vec();
    encryptor.apply_keystream(&mut ciphertext);

    // Calculate the MAC.
    let mac = Keccak256::new()
        .chain(&key[16..32])
        .chain(&ciphertext)
        .finalize();

    let id = Uuid::new_v4();

    // Construct and serialize the encrypted JSON keystore.
    let keystore = KeyStore {
        id,
        address,
        version: 3,
        crypto: CryptoData {
            cipher: String::from(DEFAULT_CIPHER),
            cipherparams: CipherParams { iv },
            ciphertext: ciphertext.to_vec(),
            kdf: KdfType::Scrypt,
            kdfparams: KdfParamsType::Scrypt {
                dklen: DEFAULT_KDF_PARAMS_DKLEN,
                n: 2u32.pow(DEFAULT_KDF_PARAMS_LOG_N as u32),
                p: DEFAULT_KDF_PARAMS_P,
                r: DEFAULT_KDF_PARAMS_R,
                salt,
            },
            mac: mac.to_vec(),
        },
    };

    Ok(keystore)
}
