// This is just a simple interop file that we will delete later. Its only use is to
// ensure that the ffi_interface crate has not changed any behaviour from the
// java jni crate.
//
// Once the java jni crate uses the below implementation, we will remove this file.
pub mod interop;

use banderwagon::Fr;
use banderwagon::{trait_defs::*, Element};
use ipa_multipoint::committer::{Committer, DefaultCommitter};
use ipa_multipoint::crs::CRS;
use ipa_multipoint::lagrange_basis::{LagrangeBasis, PrecomputedWeights};
use ipa_multipoint::multiproof::{MultiPoint, ProverQuery};
use ipa_multipoint::transcript::Transcript;

/// Context holds all of the necessary components needed for cryptographic operations
/// in the Verkle Trie. This includes:
/// - Updating the verkle trie
/// - Generating proofs
///
/// This is useful for caching purposes, since the context can be reused for multiple
/// function calls. More so because the Context is relatively expensive to create
/// compared to making a function call.
pub struct Context {
    pub crs: CRS,
    pub committer: DefaultCommitter,

    pub precomputed_weights: PrecomputedWeights,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub fn new() -> Self {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);
        let precomputed_weights = PrecomputedWeights::new(256);

        Self {
            crs,
            committer,
            precomputed_weights,
        }
    }
}

/// A serialized uncompressed group element
pub type CommitmentBytes = [u8; 64];

/// A serialized scalar field element
pub type ScalarBytes = [u8; 32];

#[derive(Debug, Clone)]
pub enum Error {
    LengthOfScalarsNotMultipleOf32 { len: usize },
    MoreThan256Scalars { len: usize },
    FailedToDeserializeScalar { bytes: Vec<u8> },
}

/// Compute the key prefix used in the `get_tree_key` method
///
/// Returns a 32 byte slice representing the first 31 bytes of the `key` to be used in `get_tree_key`
///
// TODO: We could probably make this use `map_to_field` instead of `.to_bytes`
pub fn get_tree_key_hash(
    committer: &DefaultCommitter,
    address: [u8; 32],
    tree_index_le: [u8; 32],
) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&address);
    input[32..].copy_from_slice(&tree_index_le);

    get_tree_key_hash_flat_input(committer, input)
}
/// Same method as `get_tree_key_hash` but takes a 64 byte input instead of two 32 byte inputs
///
/// This is kept for backwards compatibility and because we have not yet checked if its better
/// for Java to pass in two 32 bytes or one 64 byte input.
///
/// The former probably requires two allocations, while the latter is less type safe.
pub fn get_tree_key_hash_flat_input(committer: &DefaultCommitter, input: [u8; 64]) -> [u8; 32] {
    verkle_spec::hash64(committer, input).to_fixed_bytes()
}
pub fn get_tree_key(
    committer: &DefaultCommitter,
    address: [u8; 32],
    tree_index_le: [u8; 32],
    sub_index: u8,
) -> [u8; 32] {
    let mut hash = get_tree_key_hash(committer, address, tree_index_le);

    hash[31] = sub_index;

    hash
}

/// This is exactly the same as `get_tree_key_hash` method.
/// Use get_tree_key_hash instead.
///
/// Moving to rename this as it causes confusion. For now, I'll call this `get_tree_key_hash`
pub fn pedersen_hash(
    committer: &DefaultCommitter,
    address: [u8; 32],
    tree_index_le: [u8; 32],
) -> [u8; 32] {
    get_tree_key_hash(committer, address, tree_index_le)
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
    let mut inputs = Vec::with_capacity(num_scalars);
    for chunk in scalars.chunks_exact(32) {
        inputs.push(fr_from_le_bytes(chunk)?);
    }

    Ok(committer.commit_lagrange(&inputs))
}

/// Commits to at most 256 scalars
///
/// Returns the commitment to those scalars
pub fn commit_to_scalars(
    committer: &DefaultCommitter,
    scalars: &[u8],
) -> Result<CommitmentBytes, Error> {
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
    old_commitment_bytes: CommitmentBytes,
    // There can only be at most 256 elements in a verkle branch
    commitment_index: u8,
    old_scalar_bytes: ScalarBytes,
    new_scalar_bytes: ScalarBytes,
) -> Result<CommitmentBytes, Error> {
    let old_commitment = Element::from_bytes_unchecked_uncompressed(old_commitment_bytes);
    let old_scalar = fr_from_le_bytes(&old_scalar_bytes)?;
    let new_scalar = fr_from_le_bytes(&new_scalar_bytes)?;

    // w-v
    let delta = new_scalar - old_scalar;

    // (w-v)G
    let delta_commitment = committer.scalar_mul(delta, commitment_index as usize);

    // vG + (w-v)G
    Ok((delta_commitment + old_commitment).to_bytes_uncompressed())
}

/// Update commitment for sparse vector.
pub fn update_commitment_sparse(
    committer: &DefaultCommitter,
    old_commitment_bytes: CommitmentBytes,
    // There can only be at most 256 elements in a verkle branch
    commitment_index_vec: Vec<usize>,
    old_scalar_bytes_vec: Vec<ScalarBytes>,
    new_scalar_bytes_vec: Vec<ScalarBytes>,
) -> Result<CommitmentBytes, Error> {
    let old_commitment = Element::from_bytes_unchecked_uncompressed(old_commitment_bytes);

    let mut delta_values: Vec<(Fr, usize)> = Vec::new();

    // For each index in commitment_index, we compute the delta value.
    for index in 0..commitment_index_vec.len() {
        let old_scalar = fr_from_le_bytes(&old_scalar_bytes_vec[index]).unwrap();
        let new_scalar = fr_from_le_bytes(&new_scalar_bytes_vec[index]).unwrap();

        let tuple = (new_scalar - old_scalar, commitment_index_vec[index]);

        delta_values.push(tuple);
    }

    let delta_commitment = committer.commit_sparse(delta_values);

    Ok((delta_commitment + old_commitment).to_bytes_uncompressed())
}

/// Hashes a commitment
///
/// Note: This commitment can be used as the `commitment root`
///
/// Returns a `Scalar` representing the hash of the commitment
pub fn hash_commitment(commitment: CommitmentBytes) -> ScalarBytes {
    // TODO: We could introduce a method named `hash_commit_to_scalars`
    // TODO: which would save this serialization roundtrip. We should profile/check that
    // TODO: this is actually a bottleneck for the average workflow before doing this.
    fr_to_le_bytes(Element::from_bytes_unchecked_uncompressed(commitment).map_to_scalar_field())
}
/// Hashes a vector of commitments.
///
/// This is more efficient than repeatedly calling `hash_commitment`
///
/// Returns a vector of `Scalar`s representing the hash of each commitment
pub fn hash_commitments(commitments: &[CommitmentBytes]) -> Vec<ScalarBytes> {
    let elements = commitments
        .iter()
        .map(|commitment| Element::from_bytes_unchecked_uncompressed(*commitment))
        .collect::<Vec<_>>();

    Element::batch_map_to_scalar_field(&elements)
        .into_iter()
        .map(fr_to_le_bytes)
        .collect()
}

/// This is kept so that commitRoot in the java implementation can be swapped out
/// Note: I believe we should not need to expose this method.
pub fn deprecated_serialize_commitment(commitment: CommitmentBytes) -> [u8; 32] {
    Element::from_bytes_unchecked_uncompressed(commitment).to_bytes()
}

fn fr_to_le_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}
fn fr_from_le_bytes(bytes: &[u8]) -> Result<banderwagon::Fr, Error> {
    banderwagon::Fr::deserialize_uncompressed(bytes).map_err(|_| Error::FailedToDeserializeScalar {
        bytes: bytes.to_vec(),
    })
}

/// Receives a tuple (C_i, f_i(X), z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 32 bytes
/// f_i(X) is the polynomial serialized as 8192 bytes since we have 256 Fr elements each serialized as 32 bytes
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes
/// Returns a proof serialized as bytes
///
/// This function assumes that the domain is always 256 values and commitment is 32bytes.
/// TODO: change commitment to 64bytes since we are moving to uncompressed commitment.
pub fn create_proof(input: Vec<u8>) -> Vec<u8> {
    // Define the chunk size (8257 bytes)
    // C_i, f_i(X), z_i, y_i
    // 32, 8192, 1, 32
    // = 8257
    let chunk_size = 8257;
    // Create an iterator over the input Vec<u8>
    let chunked_data = input.chunks(chunk_size);

    let mut prover_queries: Vec<ProverQuery> = Vec::new();

    for chunk in chunked_data.into_iter() {
        if chunk.len() >= chunk_size {
            let data = chunk;
            let commitment = Element::from_bytes(&data[0..32]).unwrap();

            // Create f_x from the next 8192 bytes
            let f_i_x: Vec<u8> = chunk[32..8224].to_vec();

            let chunked_f_i_x_data = f_i_x.chunks(32);

            let mut collect_lagrange_basis: Vec<Fr> = Vec::new();
            for chunk_f_i_x in chunked_f_i_x_data.into_iter() {
                if chunk_f_i_x.len() >= 32 {
                    let data_f_i_x = chunk_f_i_x;
                    let fr_data_f_i_x = Fr::from_be_bytes_mod_order(data_f_i_x);
                    collect_lagrange_basis.push(fr_data_f_i_x);
                }
            }

            let lagrange_basis = LagrangeBasis::new(collect_lagrange_basis);

            let z_i: usize = chunk[8224] as usize;

            let y_i = Fr::from_be_bytes_mod_order(&chunk[8225..8257]);

            let prover_query = ProverQuery {
                commitment,
                poly: lagrange_basis,
                point: z_i,
                result: y_i,
            };
            prover_queries.push(prover_query);
        }
    }
    // TODO: This should be passed in as a pointer
    let precomp = PrecomputedWeights::new(256);

    let crs = CRS::default();
    let mut transcript = Transcript::new(b"verkle");
    // TODO: This should not need to clone the CRS, but instead take a reference
    let proof = MultiPoint::open(crs.clone(), &precomp, &mut transcript, prover_queries);
    proof.to_bytes().unwrap()
}

// This is an alternative implementation of create_proof
pub fn create_proof_alt(input: Vec<u8>) -> Vec<u8> {
    // - Checks for the serialized proof queries
    ///
    // Define the chunk size (8257 bytes)
    // C_i, f_i(X), z_i, y_i
    // 32, 8192, 1, 32
    // = 8257
    const CHUNK_SIZE: usize = 8257; // TODO: get this from ipa-multipoint

    if input.len() % CHUNK_SIZE != 0 {
        // TODO: change this to an error
        panic!("Input length must be a multiple of {}", CHUNK_SIZE);
    }
    let num_proofs = input.len() / CHUNK_SIZE;

    let proofs_bytes = input.chunks_exact(CHUNK_SIZE);
    assert!(
        proofs_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the proof"
    );

    // - Deserialize proof queries
    //
    let mut prover_queries: Vec<ProverQuery> = Vec::with_capacity(num_proofs);

    for proof_bytes in proofs_bytes {
        let prover_query = deserialize_proof_query(&proof_bytes);
        prover_queries.push(prover_query);
    }

    // - Create proofs
    //
    // TODO: This should be passed in as a pointer
    let precomp = PrecomputedWeights::new(256);

    let crs = CRS::default();
    let mut transcript = Transcript::new(b"verkle");
    // TODO: This should not need to clone the CRS, but instead take a reference

    let proof = MultiPoint::open(crs.clone(), &precomp, &mut transcript, prover_queries);
    proof.to_bytes().expect("cannot serialize proof")
}

#[must_use]
fn deserialize_proof_query(bytes: &[u8]) -> ProverQuery {
    // Commitment
    let (commitment, mut bytes) = take_group_element(bytes);

    // f_x is a polynomial of degree 255, so we have 256 Fr elements
    const NUMBER_OF_EVALUATIONS: usize = 256;
    let mut collect_lagrange_basis: Vec<Fr> = Vec::with_capacity(NUMBER_OF_EVALUATIONS);
    for _ in 0..NUMBER_OF_EVALUATIONS {
        let (scalar, offsetted_bytes) = take_scalar(bytes);
        collect_lagrange_basis.push(scalar);
        bytes = offsetted_bytes;
    }

    // The input point is a single byte
    let (z_i, bytes) = take_byte(bytes);

    // The evaluation is a single scalar
    let (y_i, bytes) = take_scalar(bytes);

    assert!(bytes.is_empty(), "we should have consumed all the bytes");

    ProverQuery {
        commitment,
        poly: LagrangeBasis::new(collect_lagrange_basis),
        point: z_i,
        result: y_i,
    }
}

#[must_use]
fn take_group_element(bytes: &[u8]) -> (Element, &[u8]) {
    let element = Element::from_bytes(&bytes[0..32]).expect("could not deserialize element");
    // Increment the slice by 32 bytes
    (element, &bytes[32..])
}

#[must_use]
fn take_byte(bytes: &[u8]) -> (usize, &[u8]) {
    let z_i = bytes[0] as usize;
    // Increment the slice by 32 bytes
    (z_i, &bytes[1..])
}
#[must_use]
fn take_scalar(bytes: &[u8]) -> (Fr, &[u8]) {
    let y_i = fr_from_le_bytes(&bytes[0..32]).expect("could not deserialize y_i");
    // Increment the slice by 32 bytes
    (y_i, &bytes[32..])
}

#[cfg(test)]
mod tests {
    use banderwagon::Fr;
    use ipa_multipoint::{
        committer::{Committer, DefaultCommitter},
        crs::CRS,
    };

    use crate::{fr_from_le_bytes, fr_to_le_bytes};
    #[test]
    fn commitment_update() {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let a_0 = banderwagon::Fr::from(123u128);
        let a_1 = banderwagon::Fr::from(123u128);
        let a_2 = banderwagon::Fr::from(456u128);

        // Compute C = a_0 * G_0 + a_1 * G_1
        let commitment = committer.commit_lagrange(&[a_0, a_1]);

        // Now we want to compute C = a_2 * G_0 + a_1 * G_1
        let naive_update = committer.commit_lagrange(&[a_2, a_1]);

        // We can do this by computing C = (a_2 - a_0) * G_0 + a_1 * G_1
        let delta = a_2 - a_0;
        let delta_commitment = committer.scalar_mul(delta, 0);
        let delta_update = delta_commitment + commitment;

        assert_eq!(naive_update, delta_update);

        // Now lets do it using the update_commitment method
        let updated_commitment = super::update_commitment(
            &committer,
            commitment.to_bytes_uncompressed(),
            0,
            fr_to_le_bytes(a_0),
            fr_to_le_bytes(a_2),
        )
        .unwrap();

        assert_eq!(updated_commitment, naive_update.to_bytes_uncompressed())
    }

    #[test]
    fn commitment_exists_sparse_update() {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let a_0 = banderwagon::Fr::from(123u128);
        let a_1 = banderwagon::Fr::from(123u128);
        let a_2 = banderwagon::Fr::from(246u128);

        let a_zero = banderwagon::Fr::from(0u128);

        // Compute C = a_0 * G_0
        let commitment = committer.scalar_mul(a_0, 0);

        let naive_update = commitment + committer.scalar_mul(a_1, 1) + committer.scalar_mul(a_2, 2);

        let val_indices: Vec<(Fr, usize)> = vec![(a_1, 1), (a_2, 2)];

        let new_commitment = commitment + committer.commit_sparse(val_indices);

        assert_eq!(naive_update, new_commitment);

        let commitment_index_vec = vec![1, 2];

        let old_scalar_bytes_vec = vec![fr_to_le_bytes(a_zero), fr_to_le_bytes(a_zero)];
        let new_scalar_bytes_vec = vec![fr_to_le_bytes(a_1), fr_to_le_bytes(a_2)];

        // Now lets do it using the update_commitment_sparse method
        let updated_commitment = super::update_commitment_sparse(
            &committer,
            commitment.to_bytes_uncompressed(),
            commitment_index_vec,
            old_scalar_bytes_vec,
            new_scalar_bytes_vec,
        )
        .unwrap();

        assert_eq!(updated_commitment, naive_update.to_bytes_uncompressed());
    }

    #[test]
    fn from_be_to_be_bytes() {
        let value = banderwagon::Fr::from(123456u128);
        let bytes = fr_to_le_bytes(value);
        let got_value = fr_from_le_bytes(&bytes).unwrap();
        assert_eq!(got_value, value)
    }
}

#[cfg(test)]
mod pedersen_hash_tests {
    use ipa_multipoint::{committer::DefaultCommitter, crs::CRS};

    use crate::{get_tree_key, get_tree_key_hash};

    #[test]
    fn smoke_test_address_zero() {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);

        let address = [0u8; 32];
        let tree_index = [0u8; 32];

        let expected = "bf101a6e1c8e83c11bd203a582c7981b91097ec55cbd344ce09005c1f26d1922";
        let got_hash_bytes = get_tree_key_hash(&committer, address, tree_index);
        let got_hash_hex = hex::encode(got_hash_bytes);
        assert_eq!(expected, got_hash_hex)
    }

    #[test]
    fn smoke_test_input() {
        let crs = CRS::default();
        let committer = DefaultCommitter::new(&crs.G);
        let input = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ];

        // First 32 bytes is the address
        let mut address = [0u8; 32];
        address.copy_from_slice(&input[..32]);

        // Next 32 bytes is the tree index -- But interpreted as a little endian number
        let mut tree_index = [0u8; 32];
        tree_index.copy_from_slice(&input[32..64]);
        tree_index.reverse();

        let got_hash_bytes = get_tree_key(&committer, address, tree_index, 0);

        let expected_hash = "76a014d14e338c57342cda5187775c6b75e7f0ef292e81b176c7a5a700273700";
        let got_hash_hex = hex::encode(got_hash_bytes);
        assert_eq!(expected_hash, got_hash_hex);
    }
}
