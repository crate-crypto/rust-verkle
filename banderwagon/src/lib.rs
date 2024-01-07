pub mod trait_impls;

mod element;
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
