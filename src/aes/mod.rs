#[cfg(feature = "rustcrypto")]
pub use self::rustcrypto::RustCryptoAesDecryptor;

#[cfg(any(feature = "rustcrypto", feature = "openssl"))]
#[allow(dead_code)]
pub enum CryptoPackage {
    #[cfg(feature = "rustcrypto")]
    RustCrypto,
    #[cfg(feature = "openssl")]
    Openssl,
}

#[cfg(any(feature = "rustcrypto", feature = "openssl"))]
impl Default for CryptoPackage {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "rustcrypto", feature = "openssl"))] {
                Self::RustCrypto
            } else if #[cfg(feature = "rustcrypto")] {
                Self::RustCrypto
            } else if #[cfg(feature = "openssl")] {
                Self::Openssl
            }
        }
    }
}

#[cfg(any(feature = "rustcrypto", feature = "openssl"))]
impl CryptoPackage {
    pub fn get_default_aes_decryptor(&self) -> impl AesDecryptor<Vec<u8>> {
        match self {
            #[cfg(feature = "rustcrypto")]
            Self::RustCrypto => RustCryptoAesDecryptor::<aes::Aes256>::default(),

            #[cfg(feature = "openssl")]
            Self::Openssl => todo!(),
        }
    }
}

pub trait AesDecryptor<T> {
    type Error;

    fn decrypt_data(&self, aes_key: &[u8], encrypted_data: &[u8]) -> Result<T, Self::Error>;
}

#[cfg(feature = "rustcrypto")]
mod rustcrypto {
    use std::marker::PhantomData;

    use aes::cipher::{AsyncStreamCipher, BlockCipher, BlockEncryptMut, KeyInit, KeyIvInit};

    use super::AesDecryptor;

    pub struct RustCryptoAesDecryptor<C: BlockEncryptMut + BlockCipher + KeyInit> {
        iv_length: usize,
        _cipher_type: PhantomData<C>,
    }


    impl<C: BlockEncryptMut + BlockCipher + KeyInit> RustCryptoAesDecryptor<C> {
        pub fn new(iv_length: usize) -> RustCryptoAesDecryptor<C> {
            let cipher_type: PhantomData<C> = PhantomData;

            Self {
                iv_length,
                _cipher_type: cipher_type,
            }
        }
    }


    impl<C: BlockEncryptMut + BlockCipher + KeyInit> AesDecryptor<Vec<u8>>
        for RustCryptoAesDecryptor<C>
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

            let iv = &encrypted_data[0..self.iv_length];
            let decryptor = cfb_mode::Decryptor::<C>::new(aes_key.into(), iv.into());

            let mut decrypted_data = encrypted_data[self.iv_length..].to_vec();
            decryptor.decrypt(&mut decrypted_data);

            Ok(decrypted_data)
        }
    }


    impl Default for RustCryptoAesDecryptor<aes::Aes256> {
        fn default() -> Self {
            Self::new(16)
        }
    }
}
