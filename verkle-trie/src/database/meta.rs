use banderwagon::{Element, Fr};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StemMeta {
    pub C_1: Element,
    pub hash_c1: Fr,

    pub C_2: Element,
    pub hash_c2: Fr,

    pub stem_commitment: Element,
    pub hash_stem_commitment: Fr,
}

impl std::fmt::Debug for StemMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StemMeta")
            .field("C_1", &hex::encode(compress_point_to_array(&self.C_1)))
            .field("C_2", &hex::encode(compress_point_to_array(&self.C_2)))
            .field("hash_c1", &hex::encode(scalar_to_array(&self.hash_c1)))
            .field("hash_c2", &hex::encode(scalar_to_array(&self.hash_c2)))
            .field(
                "stem commitment",
                &hex::encode(compress_point_to_array(&self.stem_commitment)),
            )
            .field(
                "hash_stem_commitment",
                &hex::encode(scalar_to_array(&self.hash_stem_commitment)),
            )
            .finish()
    }
}

fn point_to_array(p: &EdwardsProjective) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    use ark_serialize::CanonicalSerialize;
    p.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}
fn compress_point_to_array(p: &EdwardsProjective) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    use ark_serialize::CanonicalSerialize;
    p.serialize(&mut bytes[..]).unwrap();
    bytes
}
fn scalar_to_array(scalar: &Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    use ark_serialize::CanonicalSerialize;
    scalar.serialize_uncompressed(&mut bytes[..]).unwrap();
    bytes
}
impl StemMeta {
    // panic if we cannot deserialise, do not call this method if you are unsure if the data is
    // not structured properly. We cn guarantee this in verkle trie.
    pub fn from_bytes(bytes: &[u8]) -> StemMeta {
        let len = bytes.len();
        assert_eq!(len, 64 * 3 + 32 * 3);

        use ark_serialize::CanonicalDeserialize;

        let point_bytes = &bytes[0..64 * 3];
        let C_1 = Element::deserialize_uncompressed(&point_bytes[0 * 64..1 * 64]).unwrap();
        let C_2 = Element::deserialize_uncompressed(&point_bytes[1 * 64..2 * 64]).unwrap();
        let stem_commitment =
            Element::deserialize_uncompressed(&point_bytes[2 * 64..3 * 64]).unwrap();

        let scalar_bytes = &bytes[64 * 3..];
        let hash_c1 = Fr::deserialize_uncompressed(&scalar_bytes[0 * 32..1 * 32]).unwrap();
        let hash_c2 = Fr::deserialize_uncompressed(&scalar_bytes[1 * 32..2 * 32]).unwrap();
        let hash_stem_commitment =
            Fr::deserialize_uncompressed(&scalar_bytes[2 * 32..3 * 32]).unwrap();

        StemMeta {
            C_1,
            hash_c1,
            C_2,
            hash_c2,
            stem_commitment,
            hash_stem_commitment,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(3 * (64 + 32));

        bytes.extend(point_to_array(&self.C_1));
        bytes.extend(point_to_array(&self.C_2));
        bytes.extend(point_to_array(&self.stem_commitment));

        bytes.extend(scalar_to_array(&self.hash_c1));
        bytes.extend(scalar_to_array(&self.hash_c2));
        bytes.extend(scalar_to_array(&self.hash_stem_commitment));

        bytes
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
                &hex::encode(compress_point_to_array(&self.commitment)),
            )
            .field(
                "hash_commitment",
                &hex::encode(scalar_to_array(&self.hash_commitment)),
            )
            .finish()
    }
}

impl BranchMeta {
    pub fn zero() -> BranchMeta {
        use ark_ff::Zero;
        BranchMeta {
            commitment: Element::zero(),
            hash_commitment: Fr::zero(),
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> BranchMeta {
        let len = bytes.len();
        assert_eq!(
            len,
            32 + 64,
            "BranchMeta was not serialised properly, got {}",
            hex::encode(bytes)
        );

        use ark_serialize::CanonicalDeserialize;

        let point_bytes = &bytes[0..64];
        let scalar_bytes = &bytes[64..64 + 32];

        let commitment = Element::deserialize_uncompressed(point_bytes).unwrap();
        let hash_commitment = Fr::deserialize_uncompressed(scalar_bytes).unwrap();

        BranchMeta {
            commitment,
            hash_commitment,
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + 32);

        bytes.extend(point_to_array(&self.commitment));
        bytes.extend(scalar_to_array(&self.hash_commitment));

        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
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

impl BranchChild {
    pub fn from_bytes(bytes: &[u8]) -> BranchChild {
        if bytes.len() == 31 {
            return BranchChild::Stem(bytes.try_into().unwrap());
        }
        BranchChild::Branch(BranchMeta::from_bytes(bytes))
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            BranchChild::Stem(stem_id) => stem_id.to_vec(),
            BranchChild::Branch(bm) => bm.to_bytes(),
        }
    }
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
