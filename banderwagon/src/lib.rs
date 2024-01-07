pub mod trait_impls;

mod element;
use ark_ed_on_bls12_381_bandersnatch::Fq;
use ark_ff::BigInteger256;
pub use element::{multi_scalar_mul, Element, Fr};

pub trait VerkleField {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;

    fn one() -> Self;

    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self;
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self;
}

// TODO: This avoids leaking arkworks in verkle_trie, but it's not ideal
impl VerkleField for Fr {
    fn zero() -> Self {
        ark_ff::Zero::zero()
    }
    fn is_zero(&self) -> bool {
        ark_ff::Zero::is_zero(self)
    }

    fn one() -> Self {
        ark_ff::One::one()
    }

    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        ark_ff::PrimeField::from_be_bytes_mod_order(bytes)
    }

    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        ark_ff::PrimeField::from_le_bytes_mod_order(bytes)
    }
}

pub const fn fr_from_u64_limbs(limbs: [u64; 4]) -> Fr {
    Fr::new(BigInteger256::new(limbs))
}

// Takes as input a random byte array and attempts to map it
// to a point in the subgroup.
//
// This is useful in try-and-increment algorithms.
pub fn try_reduce_to_element(bytes: &[u8]) -> Option<Element> {
    use ark_ff::PrimeField;
    use ark_serialize::CanonicalSerialize;

    // The Element::from_bytes method does not reduce the bytes, it expects the
    // input to be in a canonical format, so we must do the reduction ourselves
    let x_coord = Fq::from_be_bytes_mod_order(&bytes);

    let mut bytes = [0u8; 32];
    x_coord.serialize_compressed(&mut bytes[..]).unwrap();

    // TODO: this reverse is hacky, and its because there is no way to specify the endianness in arkworks
    // TODO So we reverse it here, to be interopable with the banderwagon specs which needs big endian bytes

    bytes.reverse();

    // Deserialize the x-coordinate to get a valid banderwagon element
    Element::from_bytes(&bytes)
}
