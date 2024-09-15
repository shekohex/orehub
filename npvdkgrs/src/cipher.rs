use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand, vec::Vec};

use ark_bls12_381::{Fq, G2Affine};
use chacha20poly1305::{
    aead::{AeadMutInPlace, Buffer},
    KeyInit, XChaCha20Poly1305 as ChaCha, XNonce as Nonce,
};

use crate::keys::{PublicKey, SecretKey};

pub trait WithData {
    /// Create a new object from the data.
    fn from_data(data: Vec<u8>) -> Self;
    /// Get a reference to the data.
    fn data_ref(&self) -> &[u8];
    /// Get a mutable reference to the data.
    fn data_ref_mut(&mut self) -> &mut [u8];
    /// Get the data, consuming the object.
    fn into_data(self) -> Vec<u8>;
    /// Get the length of the data.
    fn data_len(&self) -> usize;
}

/// An Envolope is used to send an encrypted message to someone knowing the public key.
///
/// it could only be decrypted by the person knowing the corresponding secret key.
#[derive(Debug, Clone)]
pub struct Envolope<S: WithData> {
    /// The ephemeral public key used in the encryption
    epk: G2Affine,
    /// The nonce used in the encryption
    nonce: Nonce,
    /// The type of the state
    s: S,
}

#[derive(Debug, Clone)]
pub struct Plaintext {
    /// Plaintext data
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Ciphertext {
    /// Ciphertext data
    pub ciphertext: Vec<u8>,
}

impl WithData for Plaintext {
    fn from_data(data: Vec<u8>) -> Self {
        Self { plaintext: data }
    }

    fn data_ref(&self) -> &[u8] {
        &self.plaintext
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.plaintext
    }

    fn into_data(self) -> Vec<u8> {
        self.plaintext
    }

    fn data_len(&self) -> usize {
        self.plaintext.len()
    }
}

impl WithData for Ciphertext {
    fn from_data(data: Vec<u8>) -> Self {
        Self { ciphertext: data }
    }

    fn data_ref(&self) -> &[u8] {
        &self.ciphertext
    }

    fn data_ref_mut(&mut self) -> &mut [u8] {
        &mut self.ciphertext
    }

    fn into_data(self) -> Vec<u8> {
        self.ciphertext
    }

    fn data_len(&self) -> usize {
        self.ciphertext.len()
    }
}

/// An Envolope that contains plaintext data.
pub type PlaintextEnvolope = Envolope<Plaintext>;
/// An Envolope that contains ciphertext data.
pub type CiphertextEnvolope = Envolope<Ciphertext>;

/// An Error that can occur during the encryption or decryption of an Envolope.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Serialization error
    Serialization(#[cfg_attr(feature = "std", from, source)] SerializationError),
    /// Error in the ChaCha20Poly1305 encryption
    ChaCha20Poly1305(#[cfg_attr(feature = "std", from, source)] chacha20poly1305::Error),
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

impl<S: WithData> Envolope<S> {
    /// Create a new envolope from the data.
    pub fn new(data: Vec<u8>) -> Self {
        Self { epk: G2Affine::identity(), nonce: Nonce::default(), s: S::from_data(data) }
    }

    /// Serialize the envolope.
    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let size = self.epk.compressed_size() + /* Size */ 8 + 24 /* Nonce */ + /* Size */ 8 + self.s.data_len();
        let mut bytes = Vec::with_capacity(size);
        self.epk.serialize_compressed(&mut bytes)?;
        self.nonce.serialize_compressed(&mut bytes)?;
        bytes.extend_from_slice(&self.s.data_ref());
        Ok(bytes)
    }

    /// Deserialize the envolope.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;
        let epk = G2Affine::deserialize_compressed(&bytes[offset..])?;
        offset += epk.compressed_size();
        let nonce_len = 24;
        let nonce = Nonce::clone_from_slice(&bytes[offset..offset + nonce_len]);
        offset += nonce_len + 8 /* Size */;
        let data = bytes[offset..].to_vec();
        let s = S::from_data(data);
        Ok(Envolope { epk, nonce, s })
    }

    /// Get the ephemeral public key.
    pub fn epk(&self) -> G2Affine {
        self.epk
    }
}

impl Envolope<Plaintext> {
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

        // Encrypt the data in place, so that the we don't expose the plaintext.
        encrypt_in_place(&crate::hash::hash_fq_to_32(key), &nonce_bytes, &mut self.s.plaintext)?;
        Ok(Envolope { epk, nonce: Nonce::from(nonce_bytes), s: Ciphertext { ciphertext: self.s.into_data() } })
    }

    /// Expose the plaintext data.
    pub fn expose_plaintext(&self) -> &[u8] {
        self.s.data_ref()
    }
}

impl Envolope<Ciphertext> {
    /// Decrypt the data using the provided secret key.
    ///
    /// Takes self by value to prevent the data from being exposed.
    pub fn decrypt(self, sk: SecretKey) -> Result<Envolope<Plaintext>, Error> {
        let decpk = G2Affine::from(self.epk * sk.expose_secret());
        let mut decpk_bytes = Vec::new();
        decpk.serialize_compressed(&mut decpk_bytes)?;
        let key = crate::hash::hash_to_fp(&decpk_bytes);
        self.decrypt_with_key(key)
    }

    /// Decrypt the data using the provided public key.
    ///
    /// Takes self by value to prevent the data from being exposed.
    pub fn decrypt_with_pubkey(self, pubkey: PublicKey) -> Result<Envolope<Plaintext>, Error> {
        let mut decpk_bytes = Vec::new();
        pubkey.into_affine().serialize_compressed(&mut decpk_bytes)?;
        let key = crate::hash::hash_to_fp(&decpk_bytes);
        self.decrypt_with_key(key)
    }

    /// Get ciphertext data.
    pub fn ciphertext(&self) -> &[u8] {
        self.s.data_ref()
    }

    fn decrypt_with_key(mut self, key: Fq) -> Result<Envolope<Plaintext>, Error> {
        // Decrypt the data in place, so that the we don't expose the plaintext.
        decrypt_in_place(&crate::hash::hash_fq_to_32(key), &self.nonce, &mut self.s.ciphertext)?;
        Ok(Envolope { epk: self.epk, nonce: self.nonce, s: Plaintext { plaintext: self.s.into_data() } })
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
    use crate::{
        keys::Keypair,
        poly::{self, DenseGPolynomial},
    };
    use ark_bls12_381::{Fr, G2Projective};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
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
        assert_eq!(decrypted.expose_plaintext(), msg);
        assert!(encrypted2.decrypt(other_keypair.sk()).is_err());

        let envolope = PlaintextEnvolope::new(other_msg.to_vec());

        let encrypted = envolope.encrypt(&mut rng, other_keypair.pk()).unwrap();
        let encrypted2 = encrypted.clone();
        let decrypted = encrypted.decrypt(other_keypair.sk()).unwrap();

        assert!(encrypted2.decrypt(keypair.sk()).is_err());
        assert_eq!(decrypted.expose_plaintext(), other_msg);
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
            assert_ne!(&encrypted.ciphertext(), &other_encrypted.ciphertext());
        }
    }

    #[test]
    fn serialization() {
        let msg = b"hello_world!!!!";
        let envolope = PlaintextEnvolope::new(msg.to_vec());
        let bytes = envolope.serialize().unwrap();
        let envolope2 = PlaintextEnvolope::deserialize(&bytes).unwrap();
        assert_eq!(envolope.expose_plaintext(), envolope2.expose_plaintext());
    }

    #[test]
    fn serialization_ciphertext() {
        let msg = b"hello_world!!!!";
        let mut rng = OsRng;
        let keypair = Keypair::rand(&mut rng);
        let envolope = PlaintextEnvolope::new(msg.to_vec());
        let encrypted = envolope.encrypt(&mut rng, keypair.pk()).unwrap();
        let bytes = encrypted.serialize().unwrap();
        let encrypted2 = CiphertextEnvolope::deserialize(&bytes).unwrap();
        assert_eq!(encrypted.ciphertext(), encrypted2.ciphertext());
    }

    #[test]
    fn decryption_from_shares() {
        let mut rng = OsRng;
        let n = 4;
        let id_vec = (0..n).map(|i| Fr::from((10 + i) as u64)).collect::<Vec<_>>();
        // generate coefficients for polynomials
        let private_coeffs = id_vec.iter().map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let public_coeffs = private_coeffs
            .iter()
            .map(|s| G2Affine::generator() * s)
            .map(Into::into)
            .collect::<Vec<G2Projective>>();

        let private_poly = DensePolynomial::from_coefficients_vec(private_coeffs);
        let public_poly = DenseGPolynomial::from_coefficients_vec(public_coeffs);

        // generate test keypairs via evaluating the polynomials
        let share_keypairs = id_vec
            .iter()
            .map(|id| {
                let privkey = private_poly.evaluate(id);
                let pubkey = public_poly.evaluate(id);
                let k = Keypair::from_sk(privkey.into());
                assert_eq!(k.pk(), pubkey.into(), "public key does not match for id {id}");
                k
            })
            .collect::<Vec<Keypair>>();

        // encrypt plaintext with the public verification key (0th poly coeff)
        let msg = b"this is the plaintext";
        let global_public_key = public_poly.coeffs()[0];
        let envolope = PlaintextEnvolope::new(msg.to_vec());
        let encrypted = envolope.encrypt(&mut rng, global_public_key.into()).unwrap();
        // collect decryption key shares
        let decryption_shares = share_keypairs
            .iter()
            .map(|keypair| encrypted.epk * keypair.sk().expose_secret())
            .map(Into::into)
            .collect::<Vec<G2Projective>>();
        // interpolate to get the decryption key
        let decryption_pubkey = poly::interpolate(&id_vec, &decryption_shares).unwrap()[0];

        let decrypted = encrypted.clone().decrypt_with_pubkey(decryption_pubkey.into()).unwrap();
        assert_eq!(decrypted.expose_plaintext(), msg);
        // not enough shares collected
        let decryption_pubkey = poly::interpolate(&id_vec[0..n - 1], &decryption_shares[0..n - 1]).unwrap()[0];

        assert!(encrypted.decrypt_with_pubkey(decryption_pubkey.into()).is_err());
    }
}
