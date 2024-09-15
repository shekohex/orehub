use ark_bls12_381::Fr;
use ark_ff::{BigInteger256, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::keys::PublicKey;

/// An Address is a 32 bytes value that represents a hash of a G2 point (public key).
///
/// This essentially is a hash of a public key, which is used as an address in the system.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    CanonicalSerialize,
    CanonicalDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Address([u8; 32]);

impl TryFrom<PublicKey> for Address {
    type Error = SerializationError;
    fn try_from(pubkey: PublicKey) -> Result<Self, Self::Error> {
        Self::try_from(&pubkey)
    }
}

impl TryFrom<&PublicKey> for Address {
    type Error = SerializationError;
    fn try_from(pubkey: &PublicKey) -> Result<Self, Self::Error> {
        let mut bytes = Vec::with_capacity(pubkey.compressed_size());
        pubkey.serialize_compressed(&mut bytes)?;
        let bigint = crate::hash::hash_to_fr(&bytes).into_bigint();
        // SAFETY: The following code is safe because:
        // 1. The hash is always a valid Fr value.
        // 2. The hash is always 32 bytes long.
        // 3. The ordering of the bytes is always little-endian.
        #[allow(unsafe_code)]
        let address_bytes = unsafe { core::mem::transmute(bigint.0) };
        Ok(Self(address_bytes))
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Address {
    /// Creates a new address from the given bytes.
    ///
    /// Only used for testing purposes.
    #[cfg(test)]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes of the address.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the address as a scalar value [Fr].
    pub fn as_scalar(&self) -> Fr {
        // SAFETY: The following code is safe because:
        // 1. The address is always 32 bytes long.
        // 2. The address is always generated from a hash of a G2 point.
        // 3. The hash is guranteed to be a valid Fr value.
        // 4. The orderings of the bytes are always little-endian.
        //
        // with the above points in mind, we can safely transmute the address
        // to a Limbs type and then to a BigInteger256 type.
        #[allow(unsafe_code)]
        let limbs = unsafe { core::mem::transmute(self.0) };
        let bigint = BigInteger256::new(limbs);
        Fr::from(bigint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;
    use ark_std::Zero;

    #[test]
    fn pubkey_to_address() {
        let zero = PublicKey::zero();
        let addr = Address::try_from(&zero).unwrap();
        assert_eq!(addr.to_string(), "d8dc5bb46215d1445739b46cac9117751d9d8d562df1c8bf0dfbf98a6cdd6f4f");
        let as_scalar = addr.as_scalar();
        assert_eq!(as_scalar.into_bigint().to_bytes_le(), addr.as_bytes());
    }
}
