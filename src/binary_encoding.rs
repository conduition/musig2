use crate::errors::DecodeError;

/// Marks a type which can be serialized to and from a binary encoding of either
/// fixed or variable length.
pub trait BinaryEncoding: Sized {
    /// The binary type which is returned by serialization. Should either
    /// be `[u8; N]` or `Vec<u8>`.
    type Serialized;

    /// Serialize this data structure to its binary representation.
    fn to_bytes(&self) -> Self::Serialized;

    /// Deserialize this data structure from a binary representation.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>>;
}

/// Implements various binary encoding traits for both fixed or
/// variable-length encoded data structures.
///
/// Use this macro by first implementing [`BinaryEncoding`] on a type,
/// and then invoking `impl_encoding_traits` on the type.
macro_rules! impl_encoding_traits {
    // Fixed length encoding
    ($typename:ty, $byte_len:expr $(, $max_byte_len:expr)?) => {
        /// assert that $typename implements `BinaryEncoding`
        const _: () = {
            fn __(
                x: $typename,
            ) -> impl BinaryEncoding<Serialized = [u8; $byte_len]>
            {
                x
            }
        };

        impl std::fmt::LowerHex for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let mut buffer = [0; $byte_len * 2];
                let encoded = base16ct::lower::encode_str(&self.to_bytes(), &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }

        impl std::fmt::UpperHex for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let mut buffer = [0; $byte_len * 2];
                let encoded = base16ct::upper::encode_str(&self.to_bytes(), &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }

        impl std::str::FromStr for $typename {
            type Err = DecodeError<Self>;

            /// Parses this type from a hex string, which can be either upper or
            /// lower case. The binary format of the decoded hex data should
            /// match that returned by [`to_bytes`][Self::to_bytes].
            ///
            /// Same as [`Self::from_hex`].
            fn from_str(hex: &str) -> Result<Self, Self::Err> {
                let mut buffer = [0; $byte_len];
                let bytes = base16ct::mixed::decode(hex, &mut buffer)?;
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<&[u8]> for $typename {
            type Error = DecodeError<Self>;

            /// Parse this type from a variable-length byte slice.
            ///
            /// Same as [`Self::from_bytes`][Self::from_bytes].
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        impl TryFrom<[u8; $byte_len]> for $typename {
            type Error = DecodeError<Self>;

            /// Parse this type from its fixed-length binary representation.
            fn try_from(bytes: [u8; $byte_len]) -> Result<Self, Self::Error> {
                Self::from_bytes(&bytes)
            }
        }

        impl TryFrom<&[u8; $byte_len]> for $typename {
            type Error = DecodeError<Self>;

            /// Parse this type from its fixed-length binary representation.
            ///
            /// Same as [`Self::from_bytes`][Self::from_bytes].
            fn try_from(bytes: &[u8; $byte_len]) -> Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        $(
            impl TryFrom<&[u8; $max_byte_len]> for $typename {
                type Error = DecodeError<Self>;

                /// Parse this type from its maximum-length binary representation.
                /// Throws away unused data.
                ///
                /// Same as [`Self::from_bytes`][Self::from_bytes].
                fn try_from(bytes: &[u8; $max_byte_len]) -> Result<Self, Self::Error> {
                    Self::from_bytes(bytes)
                }
            }
        )?

        impl From<$typename> for [u8; $byte_len] {
            /// Serialize this type to a fixed-length byte array.
            fn from(value: $typename) -> Self {
                value.to_bytes()
            }
        }

        impl From<$typename> for Vec<u8> {
            /// Serialize this type to a heap-allocated byte vector.
            fn from(value: $typename) -> Self {
                Vec::from(value.to_bytes())
            }
        }

        impl $typename {
            /// Alias to [the `BinaryEncoding` trait implementation of `to_bytes`][Self::to_bytes].
            pub fn serialize(&self) -> [u8; $byte_len] {
                <Self as BinaryEncoding>::to_bytes(self)
            }

            /// Alias to [the `BinaryEncoding` trait implementation of `from_bytes`][Self::from_bytes].
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
                <Self as BinaryEncoding>::from_bytes(bytes)
            }

            /// Parses this type from a hex string, which can be either upper or
            /// lower case. The binary format of the decoded hex data should
            /// match that returned by [`to_bytes`][Self::to_bytes].
            ///
            /// Same as [`Self::from_str`](#method.from_str).
            pub fn from_hex(hex: &str) -> Result<Self, DecodeError<Self>> {
                hex.parse()
            }
        }

        #[cfg(any(test, feature = "serde"))]
        impl serde::Serialize for $typename {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let bytes = self.to_bytes();
                serdect::array::serialize_hex_lower_or_bin(&bytes, serializer)
            }
        }

        #[cfg(any(test, feature = "serde"))]
        impl<'de> serde::Deserialize<'de> for $typename {
            /// Deserializes this type from a byte array or a hex
            /// string, depending on the human-readability of the data format.
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[allow(unused_mut, unused_variables)]
                let mut buffer = [0u8; $byte_len];

                // Used for a type like SecNonce where we need to accept a longer encoding
                // and throw away the unused bytes.
                $(let mut buffer = [0u8; $max_byte_len];)?

                let bytes = serdect::slice::deserialize_hex_or_bin(&mut buffer, deserializer)?;
                <$typename>::from_bytes(bytes).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Bytes(&bytes),
                        &concat!("a byte array representing ", stringify!($typename)),
                    )
                })
            }
        }
    };

    // Variable-length encoding
    ($typename:ty) => {
        /// assert that $typename implements `BinaryEncoding`
        const _: () = {
            fn __(
                x: $typename,
            ) -> impl BinaryEncoding<Serialized = Vec<u8>> {
                x
            }
        };

        impl std::fmt::LowerHex for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let bytes = self.to_bytes();
                let mut buffer = vec![0; bytes.len() * 2];
                let encoded = base16ct::lower::encode_str(&bytes, &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }

        impl std::fmt::UpperHex for $typename {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                let bytes = self.to_bytes();
                let mut buffer = vec![0; bytes.len() * 2];
                let encoded = base16ct::upper::encode_str(&bytes, &mut buffer).unwrap();
                f.write_str(encoded)
            }
        }

        impl std::str::FromStr for $typename {
            type Err = DecodeError<Self>;

            /// Parses this type from a hex string, which can be either upper or
            /// lower case. The binary format of the decoded hex data should
            /// match that returned by [`to_bytes`][Self::to_bytes].
            ///
            /// Same as [`Self::from_hex`].
            fn from_str(hex: &str) -> Result<Self, Self::Err> {
                let bytes = base16ct::mixed::decode_vec(hex)?;
                Self::from_bytes(&bytes)
            }
        }

        impl TryFrom<&[u8]> for $typename {
            type Error = DecodeError<Self>;

            /// Parse this type from a variable-length byte slice.
            ///
            /// Same as [`Self::from_bytes`][Self::from_bytes].
            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::from_bytes(bytes)
            }
        }

        impl From<$typename> for Vec<u8> {
            /// Serialize this type to a heap-allocated byte vector.
            fn from(value: $typename) -> Self {
                value.to_bytes()
            }
        }

        impl $typename {
            /// Alias to [the `BinaryEncoding` trait implementation of `to_bytes`][Self::to_bytes].
            pub fn serialize(&self) -> Vec<u8> {
                <Self as BinaryEncoding>::to_bytes(self)
            }

            /// Alias to [the `BinaryEncoding` trait implementation of `from_bytes`][Self::from_bytes].
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError<Self>> {
                <Self as BinaryEncoding>::from_bytes(bytes)
            }

            /// Parses this type from a hex string, which can be either upper or
            /// lower case. The binary format of the decoded hex data should
            /// match that returned by [`to_bytes`][Self::to_bytes].
            ///
            /// Same as [`Self::from_str`](#method.from_str).
            pub fn from_hex(hex: &str) -> Result<Self, DecodeError<Self>> {
                hex.parse()
            }
        }

        #[cfg(any(test, feature = "serde"))]
        impl serde::Serialize for $typename {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let bytes = self.to_bytes();
                serdect::slice::serialize_hex_lower_or_bin(&bytes, serializer)
            }
        }

        #[cfg(any(test, feature = "serde"))]
        impl<'de> serde::Deserialize<'de> for $typename {
            /// Deserializes this type from a byte vector or a hex
            /// string, depending on the human-readability of the data format.
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
                <$typename>::from_bytes(&bytes).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Bytes(&bytes),
                        &concat!("a byte vector representing ", stringify!($typename)),
                    )
                })
            }
        }
    };
}

/// Implements the Display trait for a type by formatting it as a lower-case
/// hex string.
macro_rules! impl_hex_display {
    ($typename:ident) => {
        impl std::fmt::Display for $typename {
            /// Formats this type as a lower-case hex string.
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:x}", self)
            }
        }
    };
}
