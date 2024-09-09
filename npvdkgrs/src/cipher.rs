use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand, vec::Vec};

use ark_bls12_381::G2Affine;
use chacha20poly1305::{
    aead::{AeadMutInPlace, Buffer},
    KeyInit, XChaCha20Poly1305 as ChaCha, XNonce as Nonce,
};

use crate::keys::{PublicKey, SecretKey};

/// An Envolope is used to send an encrypted message to someone knowing the public key.
///
/// it could only be decrypted by the person knowing the corresponding secret key.
#[derive(Debug, Clone)]
pub struct Envolope<S> {
    /// The data, encrypted or decrypted
    data: Vec<u8>,
    /// The ephemeral public key used in the encryption
    epk: G2Affine,
    /// The nonce used in the encryption
    nonce: Nonce,
    /// The type of the state
    _s: core::marker::PhantomData<S>,
}

#[derive(Debug, Clone)]
pub struct Plaintext;
#[derive(Debug, Clone)]
pub struct Ciphertext;

/// An Envolope that contains plaintext data.
pub type PlaintextEnvolope = Envolope<Plaintext>;
/// An Envolope that contains ciphertext data.
pub type CiphertextEnvolope = Envolope<Ciphertext>;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Serialization error
    #[cfg_attr(feature = "std", error(transparent))]
    Serialization(#[cfg_attr(feature = "std", from)] SerializationError),
    /// Error in the ChaCha20Poly1305 encryption
    #[cfg_attr(feature = "std", error(transparent))]
    ChaCha20Poly1305(#[cfg_attr(feature = "std", from)] chacha20poly1305::Error),
}

#[cfg(not(feature = "std"))]
impl From<SerializationError> for Error {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<chacha20poly1305::Error> for Error {
    fn from(e: chacha20poly1305::Error) -> Self {
        Self::ChaCha20Poly1305(e)
    }
}

impl<S> Envolope<S> {
    /// Expose the data in the envolope.
    ///
    /// This function is unsafe because it exposes the data in the envolope.
    /// It is the responsibility of the caller to ensure that the data is not exposed to an unauthorized party.
    pub fn expose_data(&self) -> &[u8] {
        &self.data
    }

    /// Serialize the envolope.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let size = self.epk.compressed_size() + 24 /* Nonce */ + self.data.len();
        let mut bytes = Vec::with_capacity(size);
        self.epk.serialize_compressed(&mut bytes)?;
        self.nonce.serialize_compressed(&mut bytes)?;
        bytes.extend_from_slice(&self.data);
        Ok(bytes)
    }

    /// Deserialize the envolope.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;
        let epk = G2Affine::deserialize_compressed(&bytes[offset..])?;
        offset += epk.compressed_size();
        let nonce_len = 24;
        let nonce = Nonce::clone_from_slice(&bytes[offset..offset + nonce_len]);
        offset += nonce_len;
        let data = bytes[offset..].to_vec();
        Ok(Envolope { data, epk, nonce, _s: core::marker::PhantomData })
    }
}

impl Envolope<Plaintext> {
    /// Create a new plaintext envolope from the data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { epk: G2Affine::identity(), nonce: Nonce::default(), data, _s: core::marker::PhantomData }
    }
    /// Encrypt the data for the provided public key.
    ///
    /// Takes self by value to prevent the data from being exposed.
    pub fn encrypt<R: rand::Rng + rand::CryptoRng>(
        mut self,
        rng: &mut R,
        pk: PublicKey,
    ) -> Result<Envolope<Ciphertext>, Error> {
        let esk = SecretKey::rand(rng).expose_secret();
        let epk = G2Affine::from(G2Affine::generator() * esk);
        let encpk = G2Affine::from(pk.into_affine() * esk);
        let mut encpk_bytes = Vec::with_capacity(48);
        encpk.serialize_compressed(&mut encpk_bytes)?;
        let key = crate::hash::hash_to_fp(&encpk_bytes);

        let mut nonce_bytes = [0u8; 24];
        rng.fill_bytes(&mut nonce_bytes);
        encrypt_in_place(&crate::hash::hash_fq_to_32(key), &nonce_bytes, &mut self.data)?;
        Ok(Envolope { data: self.data, epk, nonce: Nonce::from(nonce_bytes), _s: core::marker::PhantomData })
    }
}

impl Envolope<Ciphertext> {
    /// Create a new ciphertext envolope from the data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { epk: G2Affine::identity(), nonce: Nonce::default(), data, _s: core::marker::PhantomData }
    }
    /// Decrypt the data using the provided secret key.
    ///
    /// Takes self by value to prevent the data from being exposed.
    pub fn decrypt(mut self, sk: SecretKey) -> Result<Envolope<Plaintext>, Error> {
        let decpk = G2Affine::from(self.epk * sk.expose_secret());
        let mut decpk_bytes = Vec::new();
        decpk.serialize_compressed(&mut decpk_bytes)?;
        let key = crate::hash::hash_to_fp(&decpk_bytes);

        decrypt_in_place(&crate::hash::hash_fq_to_32(key), &self.nonce, &mut self.data)?;
        Ok(Envolope { data: self.data, epk: self.epk, nonce: self.nonce, _s: core::marker::PhantomData })
    }
}

fn decrypt_in_place<B: Buffer>(key: &[u8], nonce: &[u8], data: &mut B) -> Result<(), Error> {
    let mut cipher = ChaCha::new(key.into());
    cipher.decrypt_in_place(nonce.into(), b"npvdkg", data).map_err(Into::into)
}

fn encrypt_in_place<B: Buffer>(key: &[u8], nonce: &[u8], data: &mut B) -> Result<(), Error> {
    let mut cipher = ChaCha::new(key.into());
    cipher.encrypt_in_place(nonce.into(), b"npvdkg", data).map_err(Into::into)
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

        let envolope = PlaintextEnvolope::new(msg.to_vec());

        let encrypted = envolope.encrypt(&mut rng, keypair.pk()).unwrap();
        let encrypted2 = encrypted.clone();
        let decrypted = encrypted.decrypt(keypair.sk()).unwrap();
        assert_eq!(decrypted.expose_data(), msg);
        assert!(encrypted2.decrypt(other_keypair.sk()).is_err());

        let envolope = PlaintextEnvolope::new(other_msg.to_vec());

        let encrypted = envolope.encrypt(&mut rng, other_keypair.pk()).unwrap();
        let encrypted2 = encrypted.clone();
        let decrypted = encrypted.decrypt(other_keypair.sk()).unwrap();

        assert!(encrypted2.decrypt(keypair.sk()).is_err());
        assert_eq!(decrypted.expose_data(), other_msg);
    }

    #[test]
    fn non_deterministic_encryption() {
        let msg = b"peepo";
        let pk = G2Affine::generator().into();
        let envolope = PlaintextEnvolope::new(msg.to_vec());
        let encrypted = envolope.encrypt(&mut OsRng, pk).unwrap();
        for _ in 0..10 {
            let envolope = PlaintextEnvolope::new(msg.to_vec());
            let other_encrypted = envolope.encrypt(&mut OsRng, pk).unwrap();
            assert_ne!(&encrypted.expose_data(), &other_encrypted.expose_data());
        }
    }
}
