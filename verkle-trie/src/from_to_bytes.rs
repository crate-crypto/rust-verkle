use crate::errors::VerkleError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use banderwagon::{Element, Fr};
use std::result::Result;

// TODO: The only things that need to be converted to bytes are Points and scalars
// so maybe we can return a [u8;32] and avoid allocating
// Then use this instead of ark_serialize in the codebase
pub trait ToBytes {
    fn to_bytes(&self) -> Result<Vec<u8>, VerkleError>;
}
pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Result<Self, VerkleError>
    where
        Self: Sized;
}

impl ToBytes for Element {
    fn to_bytes(&self) -> Result<Vec<u8>, VerkleError> {
        let mut bytes = [0u8; 32];
        let result = self.serialize(&mut bytes[..]);
        match result {
            Err(e) => return Err(VerkleError::SerializationError(e)),
            Ok(_) => return Ok(bytes.to_vec()),
        }
    }
}
impl FromBytes for Element {
    fn from_bytes(bytes: &[u8]) -> Result<Self, VerkleError> {
        let result = CanonicalDeserialize::deserialize(bytes);
        match result {
            Err(e) => return Err(VerkleError::SerializationError(e)),
            Ok(v) => return Ok(v),
        }
    }
}
impl ToBytes for Fr {
    fn to_bytes(&self) -> Result<Vec<u8>, VerkleError> {
        let mut bytes = [0u8; 32];
        let result = self.serialize(&mut bytes[..]);
        match result {
            Err(e) => return Err(VerkleError::SerializationError(e)),
            Ok(_) => return Ok(bytes.to_vec()),
        }
    }
}
impl FromBytes for Fr {
    fn from_bytes(bytes: &[u8]) -> Result<Self, VerkleError> {
        let result = CanonicalDeserialize::deserialize(bytes);
        match result {
            Err(e) => return Err(VerkleError::SerializationError(e)),
            Ok(v) => return Ok(v),
        }
    }
}
