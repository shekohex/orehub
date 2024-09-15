use ark_bls12_381::G2Projective;
use ark_bls12_381::{Fr, G2Affine};
use ark_ec::AffineRepr;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::BTreeMap, rand, vec::Vec, UniformRand};
use serde::{Deserialize, Serialize};

use crate::addr::Address;
use crate::cipher::CiphertextEnvolope;
use crate::keys::Error;
use crate::keys::Keypair;
use crate::keys::PublicKey;
use crate::share::{EncryptedShare, Error as ShareError, PublicShare};
use crate::sig::Signature;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeysharePackage {
    /// The number of parties (the `n` in `t-n` threshold scheme).
    pub n: u16,
    /// The threshold of the scheme (the `t` in `t-n` threshold scheme).
    pub t: u16,
    /// our index in the list of parties.
    pub i: u16,
    /// Local Keypair
    pub share_keypair: Keypair,
    /// Global Public Key Polynomial Coefficients
    #[serde(with = "crate::ark")]
    pub gvk_poly: Vec<G2Projective>,
}

impl KeysharePackage {
    /// Sign a message with our local keyshare.
    pub fn partial_sign(&self, message: &[u8]) -> Result<Signature, Error> {
        self.share_keypair.sign(message)
    }

    /// Get the decryption share of an encrypted envelope.
    pub fn decryption_share(&self, enc: &CiphertextEnvolope) -> G2Projective {
        enc.epk() * self.share_keypair.sk().expose_secret()
    }

    /// Get the global verification key.
    ///
    /// This the public key of the DKG.
    pub fn global_verification_key(&self) -> PublicKey {
        self.gvk_poly[0].into()
    }

    /// Get the local public key.
    pub fn public_key(&self) -> PublicKey {
        self.share_keypair.pk()
    }
}

/// Generates a random polynomial of degree `threshold - 1`.
///
/// in case of resharing, you can pass the old secret as an argument.
pub fn random_polynomial<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    t: u16,
    old_secret: Option<Fr>,
) -> DensePolynomial<Fr> {
    let mut private_coeffs = (0..t).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    // in case of resharing, use the old secret
    if let Some(s) = old_secret {
        private_coeffs[0] = s;
    }
    DensePolynomial::from_coefficients_vec(private_coeffs)
}

/// Generats Shares for the given participants from the given polynomial.
pub fn generate_shares<R: rand::Rng + rand::CryptoRng>(
    rng: &mut R,
    participants: &BTreeMap<Address, PublicKey>,
    polynomial: &DensePolynomial<Fr>,
) -> Result<Vec<PublicShare>, ShareError> {
    participants
        .iter()
        .map(|(address, pubkey)| {
            let secret_share = polynomial.evaluate(&address.as_scalar());
            let vk = G2Affine::from(G2Affine::generator() * secret_share).into();
            let esh = EncryptedShare::new(rng, address.as_bytes(), *pubkey, secret_share)?;
            Ok(PublicShare { vk, esh })
        })
        .collect::<Result<Vec<_>, _>>()
}
