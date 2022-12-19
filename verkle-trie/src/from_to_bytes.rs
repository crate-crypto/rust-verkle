use ark_serialize::SerializationError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use banderwagon::{Element, Fr};
use std::result::Result;

// TODO: The only things that need to be converted to bytes are Points and scalars
// so maybe we can return a [u8;32] and avoid allocating
// Then use this instead of ark_serialize in the codebase
pub trait ToBytes<T> {
    fn to_bytes(&self) -> Result<T, SerializationError>;
}
pub trait FromBytes<T> {
    fn from_bytes(bytes: T) -> Result<Self, SerializationError>
    where
        Self: Sized;
}

impl ToBytes<[u8; 32]> for Element {
    fn to_bytes(&self) -> Result<[u8; 32], SerializationError> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..])?;
        Ok(bytes)
    }
}
impl FromBytes<&[u8]> for Element {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        CanonicalDeserialize::deserialize(bytes)
    }
}
impl ToBytes<[u8; 32]> for Fr {
    fn to_bytes(&self) -> Result<[u8; 32], SerializationError> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..])?;

        Ok(bytes)
    }
}
impl FromBytes<&[u8]> for Fr {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        CanonicalDeserialize::deserialize(bytes)
    }
}
