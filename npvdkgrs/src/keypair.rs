use ark_bls12_381::{Fr, G2Affine};
use ark_ec::{hashing::HashToCurveError, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand, UniformRand};
use zeroize::Zeroize;

use crate::signature::Signature;

/// A Public Key is a curve point in G2.
#[derive(Debug, Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey(G2Affine);

impl From<G2Affine> for PublicKey {
    fn from(pk: G2Affine) -> Self {
        Self(pk)
    }
}

impl From<PublicKey> for G2Affine {
    fn from(pk: PublicKey) -> G2Affine {
        pk.0
    }
}

impl AsRef<G2Affine> for PublicKey {
    fn as_ref(&self) -> &G2Affine {
        &self.0
    }
}

impl PublicKey {
    /// Get the PublicKey as an Affine point
    pub fn into_affine(self) -> G2Affine {
        self.0
    }

    /// Get the PublicKey as a Projective point
    pub fn into_projective(self) -> G2Affine {
        self.0
    }
}

/// A Secret Key is a scalar field element.
#[derive(Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SecretKey(Fr);

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"<redacted>").finish()
    }
}

impl From<Fr> for SecretKey {
    fn from(sk: Fr) -> Self {
        Self(sk)
    }
}

impl UniformRand for SecretKey {
    fn rand<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        Self(Fr::rand(rng))
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        <Fr as Zeroize>::zeroize(&mut self.0)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SigningError {
    /// Hashing to G1 failed
    #[cfg_attr(feature = "std", error(transparent))]
    HashingToG1(#[cfg_attr(feature = "std", from)] HashToCurveError),
}

#[cfg(not(feature = "std"))]
impl From<HashToCurveError> for SigningError {
    fn from(e: HashToCurveError) -> Self {
        Self::HashingToG1(e)
    }
}

impl SecretKey {
    /// Get the SecretKey as a field element
    ///
    /// NOTE: you should not use this function unless you know what you are doing.
    pub fn expose_secret(self) -> Fr {
        self.0
    }

    /// Sign a message with the secret key and return the signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SigningError> {
        let msg_hash_g1 = crate::hash::hash_to_g1(message)?;
        let sig = msg_hash_g1 * self.0;
        Ok(Signature::from(sig))
    }
}

/// A Keypair consists of a secret key and a public key.
///
/// The Secret Key is a scalar field element.
/// The Public Key is a curve point in G2.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Keypair {
    /// Secret key
    sk: SecretKey,
    /// Public key
    pk: PublicKey,
}

impl Keypair {
    /// Create a new keypair from a secret key
    pub fn from_sk(sk: SecretKey) -> Self {
        let g = G2Affine::generator();
        let pk = (g * sk.0).into_affine().into();
        Self { sk: sk.into(), pk }
    }

    pub fn rand<R: rand::Rng + rand::CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let sk = SecretKey::rand(rng);
        Self::from_sk(sk)
    }

    /// Get the Public key of the keypair
    pub fn pk(&self) -> PublicKey {
        self.pk
    }

    /// Get the Secret key of the keypair
    pub fn sk(&self) -> &SecretKey {
        &self.sk
    }

    /// Sign a message with the secret key and return the signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SigningError> {
        self.sk.sign(message)
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::rand::rngs::OsRng;

    #[test]
    fn signature() {
        let rng = &mut OsRng;
        let keypair = Keypair::rand(rng);
        let msg = b"message to be signed";
        let signature = keypair.sign(msg).unwrap();
        assert!(signature.verify(msg, &keypair.pk()));
        // wrong message
        assert!(!signature.verify(&[23; 32], &keypair.pk()));

        let other_keypair = Keypair::rand(rng);
        // wrong verifying key
        assert!(!signature.verify(msg, &other_keypair.pk()));
    }
}
