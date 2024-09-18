use core::ops::Add;

use ark_bls12_381::{Fr, G2Affine, G2Projective};
use ark_ec::{hashing::HashToCurveError, AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand, vec::Vec, UniformRand, Zero};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{addr::Address, sig::Signature};

/// A Public Key is a curve point in G2.
#[derive(Debug, Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(#[serde(with = "crate::ark")] G2Affine);

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0
            .x
            .cmp(&other.0.x)
            .then_with(|| self.0.y.cmp(&other.0.y))
            .then_with(|| self.0.infinity.cmp(&other.0.infinity))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

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

impl From<G2Projective> for PublicKey {
    fn from(pk: G2Projective) -> Self {
        Self(pk.into())
    }
}

impl From<PublicKey> for G2Projective {
    fn from(pk: PublicKey) -> G2Projective {
        pk.into_projective()
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
    pub fn into_projective(self) -> G2Projective {
        self.0.into()
    }
}

impl Add<&PublicKey> for PublicKey {
    type Output = Self;

    fn add(self, rhs: &PublicKey) -> Self {
        Self((self.0 + rhs.0).into())
    }
}

impl Add<PublicKey> for PublicKey {
    type Output = Self;

    fn add(self, rhs: PublicKey) -> Self {
        self + &rhs
    }
}

impl ark_std::Zero for PublicKey {
    fn zero() -> Self {
        Self(G2Projective::zero().into())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|_| core::fmt::Error::default())?;
        write!(f, "{}", hex::encode(&bytes))
    }
}

/// A Secret Key is a scalar field element.
#[derive(Copy, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretKey(#[serde(with = "crate::ark")] Fr);

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

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Hashing to G1 failed: {0}
    HashingToG1(#[cfg_attr(feature = "std", from, source)] HashToCurveError),
}

#[cfg(not(feature = "std"))]
impl From<HashToCurveError> for Error {
    fn from(e: HashToCurveError) -> Self {
        Self::HashingToG1(e)
    }
}

impl SecretKey {
    /// Return the public key corresponding to this secret key
    pub fn public(&self) -> PublicKey {
        let g = G2Affine::generator();
        let pk = (g * self.0).into_affine().into();
        pk
    }
    /// Get the SecretKey as a field element
    ///
    /// NOTE: you should not use this function unless you know what you are doing.
    pub fn expose_secret(self) -> Fr {
        self.0
    }

    /// Sign a message with the secret key and return the signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
        let msg_hash_g1 = crate::hash::hash_to_g1(message)?;
        let sig = msg_hash_g1 * self.0;
        Ok(Signature::from(sig))
    }

    /// Is the current secret key is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

/// A Keypair consists of a secret key and a public key.
///
/// The Secret Key is a scalar field element.
/// The Public Key is a curve point in G2.
#[derive(Debug, Clone, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct Keypair {
    /// Secret key
    sk: SecretKey,
    /// Public key
    pk: PublicKey,
}

impl Keypair {
    /// Create a new keypair from a secret key
    pub fn from_sk(sk: SecretKey) -> Self {
        let pk = sk.public();
        Self { sk, pk }
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
    pub fn sk(&self) -> SecretKey {
        self.sk
    }

    /// Get the Address of the keypair
    pub fn address(&self) -> Result<Address, SerializationError> {
        Address::try_from(&self.pk)
    }

    /// Sign a message with the secret key and return the signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
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
