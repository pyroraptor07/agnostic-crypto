//! Defines the wrapper structs and functions exposing the RSA key functionality needed
//! by the interactsh-rs client.
#![allow(unused)]

use base64::engine::general_purpose;
use base64::Engine as _;
#[cfg(feature = "openssl")]
use openssl::pkey::{PKey, Private, Public};
#[cfg(feature = "rustcrypto")]
use rsa::{RsaPrivateKey, RsaPublicKey};


pub trait RsaKeyBuilder: Default {
    type Error;
    type Key: RsaPrivKey;

    fn build(self) -> Result<Self::Key, Self::Error>;

    fn with_bit_size(&mut self, num_bits: usize) -> &mut Self;

    fn with_padding_scheme<P: KeyPadding<Self::Key>>(&mut self, padding: P) -> &mut Self;

    // other methods here
}


pub trait KeyPadding<K: RsaPrivKey> {
    type HashType;

    fn into_key_padding(self) -> K::PaddingWithHash;
}


pub trait RsaPrivKey {
    type Error;
    type PublicKey;
    type PaddingWithHash;

    fn extract_public_key(&self) -> Result<Self::PublicKey, Self::Error>;

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}


pub trait RsaPubKey {
    type Error;

    fn as_pem_string(&self) -> Result<String, Self::Error>;

    fn base64_encode<B: base64::Engine>(&self, engine: B) -> Result<String, Self::Error> {
        let pem_string = self.as_pem_string()?;
        let encoded_string = engine.encode(pem_string);

        Ok(encoded_string)
    }
}
