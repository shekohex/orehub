use core::ops::Add;

use ark_bls12_381::{Bls12_381, Config as Bls12Config, G1Affine, G1Projective, G2Affine};
use ark_ec::{
    bls12::{G1Prepared, G2Prepared},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::keys::PublicKey;

/// A Signature is a curve point in G1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct Signature(#[serde(with = "crate::ark")] G1Affine);

impl Signature {
    /// Get the Signature as an Affine point
    pub fn into_affine(self) -> G1Affine {
        self.0
    }
    /// Get the Signature as a Projective point
    pub fn into_projective(self) -> G1Projective {
        self.0.into()
    }

    /// Verify the signature on a message with the public key
    ///
    /// We will do two pairings:
    /// 1. e(H(m), pk) where H(m) is the hash of the message and pk is the public key.
    /// 2. e(sig, g2) where sig is the signature and g2 is the generator of G2.
    /// The verification equation is e(H(m), pk) == e(sig, g2)
    pub fn verify(&self, message: &[u8], public_key: &PublicKey) -> bool {
        let Ok(msg_hash_g1) = crate::hash::hash_to_g1(message) else {
            return false;
        };
        let g2 = G2Affine::generator();
        let e1 = Bls12_381::pairing(&msg_hash_g1, public_key.as_ref());
        let e2 = Bls12_381::pairing(&self.0, &g2);
        e1 == e2
    }
}

/// Batch verify a list of signatures on a message with a list of public keys.
///
/// This is more efficient than verifying each signature individually.
/// However, it is not useful to tell which signature failed, it is either all or nothing.
///
/// To verify a single signature, use the [`Signature::verify`] method.
pub fn batch_verify(
    signatures: impl IntoIterator<Item = impl Into<G1Prepared<Bls12Config>>>,
    public_keys: impl IntoIterator<Item = impl Into<G2Prepared<Bls12Config>>>,
    message: &[u8],
) -> bool {
    let Ok(msg_hash_g1) = crate::hash::hash_to_g1(message) else {
        return false;
    };
    let sigs = signatures.into_iter();
    let pks = public_keys.into_iter();
    let size_hint = sigs.size_hint().0;
    let g2 = core::iter::repeat(G2Affine::generator()).take(size_hint);
    let msg_hashes = core::iter::repeat(msg_hash_g1).take(size_hint);
    let e1 = Bls12_381::multi_pairing(msg_hashes, pks);
    let e2 = Bls12_381::multi_pairing(sigs, g2);
    e1 == e2
}

impl From<G1Affine> for Signature {
    fn from(sig: G1Affine) -> Self {
        Self(sig)
    }
}

impl From<G1Projective> for Signature {
    fn from(sig: G1Projective) -> Self {
        Self(sig.into_affine())
    }
}

impl AsRef<G1Affine> for Signature {
    fn as_ref(&self) -> &G1Affine {
        &self.0
    }
}

impl Add<Signature> for Signature {
    type Output = Self;

    fn add(self, rhs: Signature) -> Self::Output {
        Self((self.0 + rhs.0).into())
    }
}

impl core::fmt::Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
