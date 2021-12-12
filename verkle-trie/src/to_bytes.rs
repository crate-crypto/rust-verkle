use ark_serialize::CanonicalSerialize;
use bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
// TODO: The only things that need to be converted to bytes are Points and scalars
// so maybe we can return a [u8;32] and avoid allocating
// Then use this instead of ark_serialize in the codebase
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl ToBytes for EdwardsProjective {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..]).unwrap();
        bytes.to_vec()
    }
}
impl ToBytes for Fr {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..]).unwrap();
        bytes.to_vec()
    }
}
impl ToBytes for EdwardsAffine {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.serialize(&mut bytes[..]).unwrap();
        bytes.to_vec()
    }
}
