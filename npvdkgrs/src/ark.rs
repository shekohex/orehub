use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::vec::Vec;

pub fn serialize<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = Vec::with_capacity(a.compressed_size());
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

pub fn deserialize<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: &[u8] = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s, Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}
