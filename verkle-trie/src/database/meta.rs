#![allow(clippy::identity_op)]
#![allow(clippy::large_enum_variant)]
use banderwagon::trait_defs::*;
use banderwagon::{Element, Fr};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StemMeta {
    pub c_1: Element,
    pub hash_c1: Fr,

    pub c_2: Element,
    pub hash_c2: Fr,

    pub stem_commitment: Element,
    pub hash_stem_commitment: Fr,
}
impl std::fmt::Debug for StemMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StemMeta")
            .field(
                "c_1",
                &hex::encode(compress_point_to_array(&self.c_1).unwrap()),
            )
            .field(
                "c_2",
                &hex::encode(compress_point_to_array(&self.c_2).unwrap()),
            )
            .field(
                "hash_c1",
                &hex::encode(scalar_to_array(&self.hash_c1).unwrap()),
            )
            .field(
                "hash_c2",
                &hex::encode(scalar_to_array(&self.hash_c2).unwrap()),
            )
            .field(
                "stem commitment",
                &hex::encode(compress_point_to_array(&self.stem_commitment).unwrap()),
            )
            .field(
                "hash_stem_commitment",
                &hex::encode(scalar_to_array(&self.hash_stem_commitment).unwrap()),
            )
            .finish()
    }
}

fn point_to_array(p: &Element) -> Result<[u8; 64], SerializationError> {
    let mut bytes = [0u8; 64];
    p.serialize_uncompressed(&mut bytes[..])?;

    Ok(bytes)
}
fn compress_point_to_array(p: &Element) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    p.serialize_compressed(&mut bytes[..])?;

    Ok(bytes)
}
fn scalar_to_array(scalar: &Fr) -> Result<[u8; 32], SerializationError> {
    let mut bytes = [0u8; 32];
    scalar.serialize_uncompressed(&mut bytes[..])?;

    Ok(bytes)
}

impl FromBytes<Vec<u8>> for StemMeta {
    // panic if we cannot deserialize, do not call this method if you are unsure if the data is
    // not structured properly. We can guarantee this in verkle trie.
    fn from_bytes(bytes: Vec<u8>) -> Result<StemMeta, SerializationError> {
        let len = bytes.len();
        // TODO: Explain where this number comes from
        if len != 64 * 3 + 32 * 3 {
            return Err(SerializationError::InvalidData); // TODO not the most accurate error msg for now
        }

        let point_bytes = &bytes[0..64 * 3];
        #[allow(clippy::erasing_op)]
        let c_1 = Element::deserialize_uncompressed(&point_bytes[0 * 64..1 * 64])?;
        let c_2 = Element::deserialize_uncompressed(&point_bytes[1 * 64..2 * 64])?;
        let stem_commitment = Element::deserialize_uncompressed(&point_bytes[2 * 64..3 * 64])?;

        let scalar_bytes = &bytes[64 * 3..];
        #[allow(clippy::erasing_op)]
        let hash_c1 = Fr::deserialize_uncompressed(&scalar_bytes[0 * 32..1 * 32])?;
        let hash_c2 = Fr::deserialize_uncompressed(&scalar_bytes[1 * 32..2 * 32])?;
        let hash_stem_commitment = Fr::deserialize_uncompressed(&scalar_bytes[2 * 32..3 * 32])?;

        Ok(StemMeta {
            c_1,
            hash_c1,
            c_2,
            hash_c2,
            stem_commitment,
            hash_stem_commitment,
        })
    }
}

impl ToBytes<Vec<u8>> for StemMeta {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::with_capacity(3 * (64 + 32));

        bytes.extend(point_to_array(&self.c_1)?);
        bytes.extend(point_to_array(&self.c_2)?);
        bytes.extend(point_to_array(&self.stem_commitment)?);

        bytes.extend(scalar_to_array(&self.hash_c1)?);
        bytes.extend(scalar_to_array(&self.hash_c2)?);
        bytes.extend(scalar_to_array(&self.hash_stem_commitment)?);

        Ok(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchMeta {
    pub commitment: Element,
    pub hash_commitment: Fr,
}
impl std::fmt::Debug for BranchMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchMeta")
            .field(
                "commitment",
                &hex::encode(compress_point_to_array(&self.commitment).unwrap()),
            )
            .field(
                "hash_commitment",
                &hex::encode(scalar_to_array(&self.hash_commitment).unwrap()),
            )
            .finish()
    }
}
impl BranchMeta {
    pub fn zero() -> BranchMeta {
        use banderwagon::trait_defs::*;
        BranchMeta {
            commitment: Element::zero(),
            hash_commitment: Fr::zero(),
        }
    }
}

use crate::from_to_bytes::{FromBytes, ToBytes};

impl FromBytes<Vec<u8>> for BranchMeta {
    fn from_bytes(bytes: Vec<u8>) -> Result<BranchMeta, SerializationError> {
        let len = bytes.len();
        if !len == 32 + 64 {
            return Err(SerializationError::InvalidData);
        }

        let point_bytes = &bytes[0..64];
        let scalar_bytes = &bytes[64..64 + 32];

        let commitment = Element::deserialize_uncompressed(point_bytes)?;
        let hash_commitment = Fr::deserialize_uncompressed(scalar_bytes)?;

        Ok(BranchMeta {
            commitment,
            hash_commitment,
        })
    }
}

impl ToBytes<Vec<u8>> for BranchMeta {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::with_capacity(64 + 32);

        bytes.extend(point_to_array(&self.commitment)?);
        bytes.extend(scalar_to_array(&self.hash_commitment)?);

        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Meta {
    Stem(StemMeta),
    Branch(BranchMeta),
}
impl Meta {
    pub fn into_stem(self) -> StemMeta {
        match self {
            Meta::Stem(sm) => sm,
            Meta::Branch(_) => panic!("item is a branch and not a stem"),
        }
    }
    pub fn is_stem_meta(&self) -> bool {
        match self {
            Meta::Stem(_) => true,
            Meta::Branch(_) => false,
        }
    }
    pub fn is_branch_meta(&self) -> bool {
        match self {
            Meta::Stem(_) => false,
            Meta::Branch(_) => true,
        }
    }
    pub fn into_branch(self) -> BranchMeta {
        match self {
            Meta::Stem(_) => panic!("item is a stem and not a branch"),
            Meta::Branch(bm) => bm,
        }
    }
}
impl From<StemMeta> for Meta {
    fn from(sm: StemMeta) -> Self {
        Meta::Stem(sm)
    }
}
impl From<BranchMeta> for Meta {
    fn from(bm: BranchMeta) -> Self {
        Meta::Branch(bm)
    }
}
#[derive(Debug, Clone, Copy)]
pub enum BranchChild {
    Stem([u8; 31]),
    Branch(BranchMeta),
}

impl ToBytes<Vec<u8>> for BranchChild {
    fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        match self {
            BranchChild::Stem(stem_id) => Ok(stem_id.to_vec()),
            BranchChild::Branch(bm) => Ok(bm.to_bytes().unwrap().to_vec()),
        }
    }
}

impl FromBytes<Vec<u8>> for BranchChild {
    fn from_bytes(bytes: Vec<u8>) -> Result<BranchChild, SerializationError> {
        if bytes.len() == 31 {
            return Ok(BranchChild::Stem(bytes.try_into().unwrap()));
        }
        let branch_as_bytes = BranchMeta::from_bytes(bytes)?;
        Ok(BranchChild::Branch(branch_as_bytes))
    }
}

impl BranchChild {
    pub fn is_branch(&self) -> bool {
        match self {
            BranchChild::Stem(_) => false,
            BranchChild::Branch(_) => true,
        }
    }
    pub fn branch(&self) -> Option<BranchMeta> {
        match self {
            BranchChild::Stem(_) => None,
            BranchChild::Branch(bm) => Some(*bm),
        }
    }
    pub fn stem(&self) -> Option<[u8; 31]> {
        match self {
            BranchChild::Stem(stem_id) => Some(*stem_id),
            BranchChild::Branch(_) => None,
        }
    }
}
