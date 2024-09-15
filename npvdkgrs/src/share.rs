use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{hashing::HashToCurveError, pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{rand, vec::Vec, UniformRand};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::keys::{PublicKey, SecretKey};

/// A Public Verifiable Secret Share.
///
/// it contains an Encrypted Share and a verification key.
#[derive(Clone, Debug, Copy, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct PublicShare {
    /// The Verification Key
    pub vk: PublicKey,
    /// The Encrypted Share
    pub esh: EncryptedShare,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct EncryptedShare {
    #[serde(with = "crate::ark")]
    pub c: Fr,
    #[serde(with = "crate::ark")]
    pub u: G2Affine,
    #[serde(with = "crate::ark")]
    pub v: G1Affine,
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    /// Serialization error: {0}
    Serialization(#[cfg_attr(feature = "std", from, source)] SerializationError),
    /// Error during Hashing to Curve: {0}
    HashToCurve(#[cfg_attr(feature = "std", from, source)] HashToCurveError),
    /// Error during Calculating the Inverse of $R$
    InverseOfR,
    /// Invalid Encrypted Share
    InvalidShare,
}

#[cfg(not(feature = "std"))]
impl From<SerializationError> for Error {
    fn from(e: SerializationError) -> Self {
        Self::Serialization(e)
    }
}

#[cfg(not(feature = "std"))]
impl From<HashToCurveError> for Error {
    fn from(e: HashToCurveError) -> Self {
        Self::HashToCurve(e)
    }
}

impl EncryptedShare {
    pub fn new<R: rand::Rng + rand::CryptoRng>(
        rng: &mut R,
        id: &[u8],
        pk: PublicKey,
        secret_share: Fr,
    ) -> Result<Self, Error> {
        let mut r = Fr::rand(rng);
        let q = crate::hash::hash_to_g1(id)?;
        let p = (pk.into_affine() * r).into_affine();
        let e = Bls12_381::pairing(q, p);
        let mut eh_bytes = Vec::with_capacity(e.compressed_size());
        e.serialize_compressed(&mut eh_bytes)?;
        let eh = crate::hash::hash_to_fr(&eh_bytes);

        let c = secret_share + eh;
        let u = (G2Affine::generator() * r).into_affine();
        let mut h_bytes = Vec::with_capacity(144);
        q.serialize_compressed(&mut h_bytes)?;
        c.serialize_compressed(&mut h_bytes)?;
        u.serialize_compressed(&mut h_bytes)?;
        let mut h = crate::hash::hash_to_g1(&h_bytes)?;

        let r_inv = r.inverse().ok_or_else(|| Error::InverseOfR)?;
        let v = (h * (eh * r_inv)).into_affine();

        r.zeroize();
        h.zeroize();

        Ok(Self { c, u, v })
    }

    /// Verify the Encrypted Share with the given ID and Public Key
    pub fn verify(&self, id: &[u8], pk: PublicKey) -> Result<(), Error> {
        let q = crate::hash::hash_to_g1(id)?;
        let mut h_bytes = Vec::with_capacity(144);
        q.serialize_compressed(&mut h_bytes)?;
        self.c.serialize_compressed(&mut h_bytes)?;
        self.u.serialize_compressed(&mut h_bytes)?;
        let mut h = crate::hash::hash_to_g1(&h_bytes)?;
        let c_g2 = (G2Affine::generator() * self.c).into_affine();

        let e1 = Bls12_381::pairing(h, c_g2);

        let e2_0 = Bls12_381::pairing(h, pk.into_affine());
        let e2_1 = Bls12_381::pairing(self.v, self.u);
        let e2 = e2_0 + e2_1;
        h.zeroize();

        if e1 == e2 {
            Ok(())
        } else {
            Err(Error::InvalidShare)
        }
    }

    /// Decrypt the Encrypted Share with the given ID and Secret Key.
    pub fn decrypt(&self, id: &[u8], sk: SecretKey) -> Result<Fr, Error> {
        let q = crate::hash::hash_to_g1(id)?;
        let s = (q * sk.expose_secret()).into_affine();
        let e = Bls12_381::pairing(s, self.u);
        let mut eh_bytes = Vec::with_capacity(e.compressed_size());
        e.serialize_compressed(&mut eh_bytes)?;
        let mut eh = crate::hash::hash_to_fr(&eh_bytes);
        let decrypted_share = self.c - eh;
        eh.zeroize();
        eh_bytes.zeroize();

        Ok(decrypted_share)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;

    struct Share {
        public: G2Affine,
        secret: Fr,
    }

    impl Share {
        fn random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
            let secret = Fr::rand(rng);
            Self { public: (G2Affine::generator() * secret).into_affine(), secret }
        }
    }

    #[test]
    fn verify_and_decrypt() {
        let mut rng = rand::rngs::OsRng;
        let g2 = G2Affine::generator();
        let secret_key = Fr::rand(&mut rng);
        let id_bytes = Fr::rand(&mut rng).into_bigint().to_bytes_le();
        let pubkey = G2Affine::from(g2 * secret_key).into();

        let share = Share::random(&mut rng);

        let encrypted_share = EncryptedShare::new(&mut rng, &id_bytes, pubkey, share.secret).unwrap();
        assert!(encrypted_share.verify(&id_bytes, share.public.into()).is_ok());
        let decrypted_share = encrypted_share.decrypt(&id_bytes, secret_key.into()).unwrap();

        assert_eq!(share.secret, decrypted_share);

        let invalid_share = encrypted_share.decrypt(&id_bytes, SecretKey::rand(&mut rng)).unwrap();
        assert_ne!(share.secret, invalid_share);

        let invalid_secret_share = Fr::rand(&mut rng);
        let invalid_public_share = G2Affine::from(g2 * invalid_secret_share);
        assert!(encrypted_share.verify(&id_bytes, invalid_public_share.into()).is_err())
    }
}
