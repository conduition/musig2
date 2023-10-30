//! This code is used to assist in deserializing test vectors.

use serde::Deserialize;

#[derive(Debug)]
pub struct FromBytesError {
    pub unexpected: String,
    pub expected: String,
}

pub trait TryFromBytes: Sized {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FromBytesError>;
}

impl TryFromBytes for Vec<u8> {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FromBytesError> {
        Ok(Vec::from(bytes))
    }
}

impl<const SIZE: usize> TryFromBytes for [u8; SIZE] {
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, FromBytesError> {
        if bytes.len() != SIZE {
            return Err(FromBytesError {
                expected: format!("byte vector of length {}", SIZE),
                unexpected: format!("byte vector of length {}", bytes.len()),
            });
        }

        let mut array = [0; SIZE];
        array[..].clone_from_slice(&bytes);
        Ok(array)
    }
}

struct HexVisitor;

impl<'de> serde::de::Visitor<'de> for HexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a hex string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        base16ct::mixed::decode_vec(v)
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &"a hex string"))
    }
}

struct HexString<T: TryFromBytes>(pub T);

impl<'de, T: TryFromBytes> Deserialize<'de> for HexString<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = deserializer.deserialize_str(HexVisitor)?;

        let parsed = T::try_from_bytes(&vec).map_err(|e| {
            <D::Error as serde::de::Error>::invalid_value(
                serde::de::Unexpected::Other(&e.unexpected),
                &e.expected.as_str(),
            )
        })?;

        Ok(HexString(parsed))
    }
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFromBytes,
{
    let HexString(value) = HexString::<T>::deserialize(deserializer)?;
    Ok(value)
}

pub fn deserialize_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: TryFromBytes,
{
    let items = <Vec<HexString<T>>>::deserialize(deserializer)?
        .into_iter()
        .map(|HexString(value)| value)
        .collect();
    Ok(items)
}
