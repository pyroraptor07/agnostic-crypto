#[cfg(feature = "openssl")]
pub use self::openssl::OpensslAesDecryptor;
#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto::RustCryptoAesCfbDecryptor;


pub trait AesDecryptor<T> {
    type Error;

    fn decrypt_data(&self, aes_key: &[u8], encrypted_data: &[u8]) -> Result<T, Self::Error>;
}

#[cfg(feature = "openssl")]
mod openssl {
    use openssl::symm::Cipher;
    use snafu::ResultExt;

    use super::AesDecryptor;

    pub struct OpensslAesDecryptor {
        cipher: Cipher,
    }

    impl OpensslAesDecryptor {
        pub fn new(cipher: Cipher) -> OpensslAesDecryptor {
            Self { cipher }
        }
    }

    impl AesDecryptor<Vec<u8>> for OpensslAesDecryptor {
        type Error = snafu::Whatever;

        fn decrypt_data(
            &self,
            aes_key: &[u8],
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            let iv_length = self.cipher.iv_len();
            let key_length = self.cipher.key_len();

            snafu::ensure_whatever!(
                aes_key.len() == key_length,
                "Length of the aes key does not match the expected cipher key length",
            );

            let (iv, sliced_encrypted_data) = match iv_length {
                Some(iv_len) if encrypted_data.len() <= iv_len => {
                    snafu::whatever!("Length of encrypted data is too short")
                }
                Some(iv_len) => (Some(&encrypted_data[0..iv_len]), &encrypted_data[iv_len..]),
                None => (None, encrypted_data),
            };

            let decrypted_data =
                openssl::symm::decrypt(self.cipher, aes_key, iv, sliced_encrypted_data)
                    .whatever_context("Failed to decrypt data")?;

            Ok(decrypted_data)
        }
    }

    impl Default for OpensslAesDecryptor {
        fn default() -> Self {
            Self::new(openssl::symm::Cipher::aes_256_cfb128())
        }
    }
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    use std::marker::PhantomData;

    use aes::cipher::{
        AsyncStreamCipher,
        BlockCipher,
        BlockEncryptMut,
        BlockSizeUser,
        IvSizeUser,
        KeyInit,
        KeyIvInit,
    };

    use super::AesDecryptor;

    pub struct RustCryptoAesCfbDecryptor<C: BlockEncryptMut + BlockCipher + KeyInit> {
        iv_length: usize,
        _cipher_type: PhantomData<C>,
    }


    impl<C: BlockEncryptMut + BlockCipher + KeyInit> RustCryptoAesCfbDecryptor<C> {
        pub fn new() -> RustCryptoAesCfbDecryptor<C> {
            let cipher_type: PhantomData<C> = PhantomData;
            let iv_length = cfb_mode::Decryptor::<C>::iv_size();

            Self {
                iv_length,
                _cipher_type: cipher_type,
            }
        }
    }


    impl<C: BlockEncryptMut + BlockCipher + KeyInit + BlockSizeUser> AesDecryptor<Vec<u8>>
        for RustCryptoAesCfbDecryptor<C>
    {
        type Error = snafu::Whatever;

        fn decrypt_data(
            &self,
            aes_key: &[u8],
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, Self::Error> {
            snafu::ensure_whatever!(
                encrypted_data.len() > self.iv_length,
                "Length of encrypted data is too short",
            );

            snafu::ensure_whatever!(
                aes_key.len() == C::key_size(),
                "Length of the aes key does not match the expected cipher key length",
            );

            let iv = &encrypted_data[0..self.iv_length];
            // let decryptor = cfb_mode::Decryptor::<C>::new(aes_key.into(), iv.into());
            let decryptor: cfb_mode::Decryptor<C> = KeyIvInit::new(aes_key.into(), iv.into());

            let mut decrypted_data = encrypted_data[self.iv_length..].to_vec();
            decryptor.decrypt(&mut decrypted_data);

            Ok(decrypted_data)
        }
    }

    impl Default for RustCryptoAesCfbDecryptor<aes::Aes256> {
        fn default() -> Self {
            Self::new()
        }
    }
}
