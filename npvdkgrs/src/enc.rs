use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalSerialize, SerializationError};
use ark_std::{rand, vec::Vec};

use ark_bls12_381::G2Affine;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305 as ChaCha, XNonce as Nonce};

use crate::keys::{PublicKey, SecretKey};

/// Encryption is used to encrypt a message using for someone knowing the public key
#[derive(Debug, Clone)]
pub struct Encryption {
    /// The ciphertext produced by the encryption
    ciphertext: Vec<u8>,
    /// The ephemeral public key used in the encryption
    epk: G2Affine,
    /// The nonce used in the encryption
    nonce: Nonce,
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EncryptionError {
    /// Serialization error
    #[cfg_attr(feature = "std", error(transparent))]
    Serialization(#[cfg_attr(feature = "std", from)] SerializationError),
    /// Error in the ChaCha20Poly1305 encryption
    #[cfg_attr(feature = "std", error(transparent))]
    ChaCha20Poly1305(#[cfg_attr(feature = "std", from)] chacha20poly1305::Error),
}

#[cfg(not(feature = "std"))]
impl From<SerializationError> for EncryptionError {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<chacha20poly1305::Error> for EncryptionError {
    fn from(e: chacha20poly1305::Error) -> Self {
        Self::ChaCha20Poly1305(e)
    }
}

impl Encryption {
    pub fn new<R: rand::Rng + rand::CryptoRng>(mut rng: R, msg: &[u8], pk: PublicKey) -> Result<Self, EncryptionError> {
        let esk = SecretKey::rand(&mut rng).expose_secret();
        let epk = G2Affine::from(G2Affine::generator() * esk);
        let encpk = G2Affine::from(pk.into_affine() * esk);
        let mut encpk_bytes = Vec::new();
        encpk.serialize_compressed(&mut encpk_bytes)?;
        let key = crate::hash::hash_to_fp(&encpk_bytes).into_bigint().to_bytes_le();

        let cipher = ChaCha::new(key.as_slice().into());
        let mut nonce_bytes = [0u8; 24];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, msg)?;

        Ok(Self { ciphertext, epk, nonce })
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn epk(&self) -> G2Affine {
        self.epk
    }

    pub fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Decrypt the ciphertext using the provided key directly.
    pub fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let cipher = ChaCha::new(key.into());
        cipher.decrypt(&self.nonce, self.ciphertext.as_ref()).map_err(Into::into)
    }

    /// Decrypt the ciphertext using the secret key.
    ///
    /// This is a convenience method that will compute the encryption public key
    /// and then hash it to get the key to decrypt the ciphertext.
    pub fn decrypt_with_sk(&self, sk: SecretKey) -> Result<Vec<u8>, EncryptionError> {
        let encpk = G2Affine::from(self.epk * sk.expose_secret());
        let mut encpk_bytes = Vec::new();
        encpk.serialize_compressed(&mut encpk_bytes)?;
        let key = crate::hash::hash_to_fp(&encpk_bytes).into_bigint().to_bytes_le();
        self.decrypt(&key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keys::Keypair;
    use ark_std::rand::rngs::OsRng;

    #[test]
    fn encryption_and_decryption() {
        let msg = b"hello_world!!!!";
        let other_msg = b"to whom it may concern";
        let mut rng = OsRng;
        let keypair = Keypair::rand(&mut rng);
        let other_keypair = Keypair::rand(&mut rng);

        let encryption = Encryption::new(rng, msg, keypair.pk()).unwrap();
        let decrypted = encryption.decrypt_with_sk(keypair.sk()).unwrap();
        assert_eq!(decrypted, msg);
        assert!(encryption.decrypt_with_sk(other_keypair.sk()).is_err());
        let encryption = Encryption::new(rng, other_msg, other_keypair.pk()).unwrap();
        let decrypted = encryption.decrypt_with_sk(other_keypair.sk()).unwrap();
        assert_eq!(decrypted, other_msg);
        assert!(encryption.decrypt_with_sk(keypair.sk()).is_err());
    }

    #[test]
    fn non_deterministic_encryption() {
        let msg = b"peepo";
        let pk = G2Affine::generator().into();
        let encryption = Encryption::new(OsRng, msg, pk).unwrap();
        for _ in 0..10 {
            let other_encryption = Encryption::new(OsRng, msg, pk).unwrap();
            assert_ne!(&encryption.ciphertext, &other_encryption.ciphertext);
        }
    }
}
