pub mod msm;
pub mod trait_impls;

mod element;
use ark_ed_on_bls12_381_bandersnatch::Fq;
use ark_ff::BigInteger256;
pub use element::{multi_scalar_mul, Element, Fr};

// Re-export arkworks traits that one may need to use in order to use
// specific methods on field elements and for serialization.
//
// For example, if we expose Fr directly, then for consumers to call methods like Fr::one()
// they will need to import ark_ff::One, which means they will need to import
// ark_ff as a dependency.
//
// This reexport allows us to avoid that.
pub use trait_defs::*;
pub mod trait_defs {
    pub use ark_ff::{batch_inversion, batch_inversion_and_mul, Field, One, PrimeField, Zero};
    pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
}

pub const fn fr_from_u64_limbs(limbs: [u64; 4]) -> Fr {
    Fr::new(BigInteger256::new(limbs))
}

// Takes as input a random byte array and attempts to map it
// to a point in the subgroup.
//
// This is useful in try-and-increment algorithms.
pub fn try_reduce_to_element(bytes: &[u8]) -> Option<Element> {
    // The Element::from_bytes method does not reduce the bytes, it expects the
    // input to be in a canonical format, so we must do the reduction ourselves
    let x_coord = Fq::from_be_bytes_mod_order(bytes);

    let mut bytes = [0u8; 32];
    x_coord.serialize_compressed(&mut bytes[..]).unwrap();

    // TODO: this reverse is hacky, and its because there is no way to specify the endianness in arkworks
    // TODO So we reverse it here, to be interopable with the banderwagon specs which needs big endian bytes

    bytes.reverse();

    // Deserialize the x-coordinate to get a valid banderwagon element
    Element::from_bytes(&bytes)
}
