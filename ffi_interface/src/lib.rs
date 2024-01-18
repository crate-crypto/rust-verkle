use banderwagon::{trait_defs::*, Element};
use ipa_multipoint::committer::{Committer, DefaultCommitter};

/// A serialized uncompressed group element
pub type Commitment = [u8; 64];

/// A serialized scalar field element
pub type Scalar = [u8; 32];

pub enum Error {
    LengthOfScalarsNotMultipleOf32 { len: usize },
    MoreThan256Scalars { len: usize },
}

/// Compute the key used in the `get_tree_key` method
///
/// Returns a 32 byte slice representing the `key` to be used in `get_tree_key`
///
// TODO: We could probably make this use `map_to_field` instead of `.to_bytes`
pub fn get_tree_key_hash(committer: &DefaultCommitter, input: [u8; 64]) -> [u8; 32] {
    verkle_spec::hash64(&committer, input).to_fixed_bytes()
}
/// Moving to rename this as it causes confusion. For now, I'll call this `get_tree_key_hash`
pub fn pedersen_hash(committer: &DefaultCommitter, input: [u8; 64]) -> [u8; 32] {
    get_tree_key_hash(committer, input)
}

fn _commit_to_scalars(committer: &DefaultCommitter, scalars: &[u8]) -> Result<Element, Error> {
    let scalars_len = scalars.len();
    // scalars when serialized are 32 bytes
    // check that the length of scalars is a multiple of 32
    if scalars_len % 32 != 0 {
        return Err(Error::LengthOfScalarsNotMultipleOf32 { len: scalars_len });
    }

    // A verkle branch can only hold 256 elements, so we never expect to commit
    // to more than 256 scalars.
    let num_scalars = scalars_len / 32;
    if num_scalars > 256 {
        return Err(Error::MoreThan256Scalars { len: num_scalars });
    }

    // We want to ensure interoperability with the Java-EVM for now, so we interpret the scalars as
    // big endian bytes
    let inputs: Vec<banderwagon::Fr> = scalars
        .chunks_exact(32)
        .into_iter()
        // TODO: This is not correct, we should be able to assume that a modular reduction is not needed
        // TODO: it is kept here, so that we do not break the Java implementation in the case
        // TODO that there is a mismatch.
        // TODO: Also I think we should stick to one endianess over the entire library for simplicity
        .map(|scalar_bytes| banderwagon::Fr::from_be_bytes_mod_order(scalar_bytes))
        .collect();

    Ok(committer.commit_lagrange(&inputs))
}

/// Commits to at most 256 scalars
///
/// Returns the commitment to those scalars
pub fn commit_to_scalars(
    committer: &DefaultCommitter,
    scalars: &[u8],
) -> Result<Commitment, Error> {
    let commitment = _commit_to_scalars(committer, scalars)?;
    Ok(commitment.to_bytes_uncompressed())
}

/// Updates a commitment from vG to wG
///
/// Since the commitment is homomorphic, wG = vG - vG + wG = vG + (w-v)G
/// - `vG` is the old commitment
/// - `v` is the old scalar
/// - `w` is the new scalar
///
/// Returns the updated commitment
pub fn update_commitment(
    committer: &DefaultCommitter,
    old_commitment_bytes: Commitment,
    // There can only be at most 256 elements in a verkle branch
    commitment_index: u8,
    old_scalar_bytes: Scalar,
    new_scalar_bytes: Scalar,
) -> Result<Commitment, ()> {
    let old_commitment = Element::from_bytes_unchecked_uncompressed(old_commitment_bytes);
    // TODO: mod_order can be removed and we can error out on non-canonicity
    let old_scalar = banderwagon::Fr::from_be_bytes_mod_order(&old_scalar_bytes);
    let new_scalar = banderwagon::Fr::from_be_bytes_mod_order(&new_scalar_bytes);

    // w-v
    let delta = new_scalar - old_scalar;

    // (w-v)G
    let delta_commitment = committer.scalar_mul(delta, commitment_index as usize);

    // vG + (w-v)G
    Ok((delta_commitment + old_commitment).to_bytes_uncompressed())
}

/// Hashes a commitment
///
/// Note: This commitment can be used as the `commitment root`
///
/// Returns a `Scalar` representing the hash of the commitment
pub fn hash_commitment(commitment: Commitment) -> Scalar {
    let mut bytes = [0u8; 32];

    // TODO: We could introduce a method named `hash_commit_to_scalars`
    // TODO: which would save this serialization roundtrip
    Element::from_bytes_unchecked_uncompressed(commitment)
        .map_to_scalar_field()
        .serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize commitment to bytes");

    bytes
}
/// Hashes a vector of commitments.
///
/// This is more efficient than repeatedly calling `hash_commitment`
///
/// Returns a vector of `Scalar`s representing the hash of each commitment
pub fn hash_commitments(commitments: &[Commitment]) -> Vec<Scalar> {
    let elements = commitments
        .iter()
        .map(|commitment| Element::from_bytes_unchecked_uncompressed(*commitment))
        .collect::<Vec<_>>();

    Element::batch_map_to_scalar_field(&elements)
        .into_iter()
        .map(|scalars| {
            let mut bytes = [0u8; 32];
            scalars
                .serialize_compressed(&mut bytes[..])
                .expect("Failed to serialize scalar to bytes");
            bytes
        })
        .collect()
}
