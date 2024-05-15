mod serialization;

// TODO: These are re-exported to not break the java code
// TODO: we ideally don't want to export these.
// - deserialize_update_commitment_sparse should not be exported and is an abstraction leak
pub use serialization::{
    deserialize_commitment, deserialize_update_commitment_sparse, serialize_commitment,
};

use banderwagon::Element;
use banderwagon::Fr;
use ipa_multipoint::committer::{Committer, DefaultCommitter};
use ipa_multipoint::crs::CRS;
use ipa_multipoint::lagrange_basis::PrecomputedWeights;
use ipa_multipoint::multiproof::{MultiPoint, MultiPointProof, ProverQuery, VerifierQuery};
use ipa_multipoint::transcript::Transcript;
use serialization::{fr_from_le_bytes, fr_to_le_bytes};
use verkle_trie::proof::golang_proof_format::{bytes32_to_element, hex_to_bytes32, VerkleProofGo};

use crate::serialization::{deserialize_proof_query, deserialize_verifier_query};

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

/// This is the identity element of the group
pub const ZERO_POINT: CommitmentBytes = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Debug, Clone)]
pub enum Error {
    LengthOfScalarsNotMultipleOf32 {
        len: usize,
    },
    TooManyScalars {
        expected: usize,
        got: usize,
    },
    FailedToDeserializeScalar {
        bytes: Vec<u8>,
    },
    LengthIsNotAnExpectedMultiple {
        item_descriptor: &'static str,
        expected_multiple: u64,
        actual_size: u64,
    },
    CouldNotDeserializeCommitment {
        bytes: Vec<u8>,
    },
    ProofVerificationFailed,
}

#[allow(deprecated)]
#[deprecated(note = "moving forward one should implement this method on the caller side")]
/// Compute the key prefix used in the `get_tree_key` method
///
/// Returns a 32 byte slice representing the first 31 bytes of the `key` to be used in `get_tree_key`
///
// TODO: We could probably make this use `map_to_field` instead of `.to_bytes`
pub fn get_tree_key_hash(
    context: &Context,
    address: [u8; 32],
    tree_index_le: [u8; 32],
) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&address);
    input[32..].copy_from_slice(&tree_index_le);

    get_tree_key_hash_flat_input(context, input)
}

#[deprecated(note = "moving forward one should implement this method on the caller side")]
/// Same method as `get_tree_key_hash` but takes a 64 byte input instead of two 32 byte inputs
///
/// This is kept for backwards compatibility and because we have not yet checked if its better
/// for Java to pass in two 32 bytes or one 64 byte input.
///
/// The former probably requires two allocations, while the latter is less type safe.
pub fn get_tree_key_hash_flat_input(context: &Context, input: [u8; 64]) -> [u8; 32] {
    verkle_spec::hash64(&context.committer, input).to_fixed_bytes()
}

#[allow(deprecated)]
#[deprecated(note = "moving forward one should implement this method on the caller side")]
pub fn get_tree_key(
    context: &Context,
    address: [u8; 32],
    tree_index_le: [u8; 32],
    sub_index: u8,
) -> [u8; 32] {
    let mut hash = get_tree_key_hash(context, address, tree_index_le);

    hash[31] = sub_index;

    hash
}

#[allow(deprecated)]
#[deprecated(note = "moving forward one should implement this method on the caller side")]
/// This is exactly the same as `get_tree_key_hash` method.
/// Use get_tree_key_hash instead.
///
/// Moving to rename this as it causes confusion. For now, I'll call this `get_tree_key_hash`
pub fn pedersen_hash(context: &Context, address: [u8; 32], tree_index_le: [u8; 32]) -> [u8; 32] {
    get_tree_key_hash(context, address, tree_index_le)
}

fn _commit_to_scalars(context: &Context, scalars: &[u8]) -> Result<Element, Error> {
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
        return Err(Error::TooManyScalars {
            got: num_scalars,
            expected: context.crs.max_number_of_elements(),
        });
    }

    let mut inputs = Vec::with_capacity(num_scalars);
    for chunk in scalars.chunks_exact(32) {
        inputs.push(fr_from_le_bytes(chunk)?);
    }

    Ok(context.committer.commit_lagrange(&inputs))
}

/// Commits to at most 256 scalars
///
/// Returns the commitment to those scalars
pub fn commit_to_scalars(context: &Context, scalars: &[u8]) -> Result<CommitmentBytes, Error> {
    let commitment = _commit_to_scalars(context, scalars)?;
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
    context: &Context,
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
    let delta_commitment = context
        .committer
        .scalar_mul(delta, commitment_index as usize);

    // vG + (w-v)G
    Ok((delta_commitment + old_commitment).to_bytes_uncompressed())
}

/// Update commitment for sparse vector.
pub fn update_commitment_sparse(
    context: &Context,
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

    let delta_commitment = context.committer.commit_sparse(delta_values);

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

/// Receives a tuple (C_i, f_i(X), z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 32 bytes
/// f_i(X) is the polynomial serialized as 8192 bytes since we have 256 Fr elements each serialized as 32 bytes
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes
/// Returns a proof serialized as bytes
///
/// This function assumes that the domain is always 256 values and commitment is 32bytes.
pub fn create_proof(context: &Context, input: Vec<u8>) -> Result<Vec<u8>, Error> {
    // - Checks for the serialized proof queries
    //
    // Define the chunk size (8257 bytes)
    // C_i, f_i(X), z_i, y_i
    // 32, 8192, 1, 32
    // = 8257
    const CHUNK_SIZE: usize = 8257; // TODO: get this from ipa-multipoint

    if input.len() % CHUNK_SIZE != 0 {
        return Err(Error::LengthIsNotAnExpectedMultiple {
            item_descriptor: "Input length for proof",
            expected_multiple: CHUNK_SIZE as u64,
            actual_size: input.len() as u64,
        });
    }
    let num_openings = input.len() / CHUNK_SIZE;

    let proofs_bytes = input.chunks_exact(CHUNK_SIZE);
    assert!(
        proofs_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the proof"
    );

    // - Deserialize proof queries
    //
    let mut prover_queries: Vec<ProverQuery> = Vec::with_capacity(num_openings);

    for proof_bytes in proofs_bytes {
        let prover_query = deserialize_proof_query(proof_bytes);
        prover_queries.push(prover_query);
    }

    // - Create proofs
    //

    let mut transcript = Transcript::new(b"verkle");

    let proof = MultiPoint::open(
        // TODO: This should not need to clone the CRS, but instead take a reference
        context.crs.clone(),
        &context.precomputed_weights,
        &mut transcript,
        prover_queries,
    );
    Ok(proof.to_bytes().expect("cannot serialize proof"))
}

/// Receives a proof and a tuple (C_i, z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 64 bytes (uncompressed commitment)
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes or Fr (scalar field element)
/// Returns true of false.
/// Proof is verified or not.
/// TODO: Add more tests.
pub fn verify_proof(context: &Context, input: Vec<u8>) -> Result<(), Error> {
    // Proof bytes are 576 bytes
    // First 32 bytes is the g_x_comm_bytes
    // Next 544 bytes are part of IPA proof. Domain size is always 256. Explanation is in IPAProof::from_bytes().
    let proof_bytes = &input[0..576];

    let proof = MultiPointProof::from_bytes(proof_bytes, 256).unwrap();

    let verifier_queries_bytes = &input[576..];

    // Define the chunk size 32+1+32 = 65 bytes for C_i, z_i, y_i
    const CHUNK_SIZE: usize = 65;

    if verifier_queries_bytes.len() % CHUNK_SIZE != 0 {
        return Err(Error::LengthIsNotAnExpectedMultiple {
            item_descriptor: "Verifier queries",
            expected_multiple: CHUNK_SIZE as u64,
            actual_size: verifier_queries_bytes.len() as u64,
        });
    }

    let num_openings = verifier_queries_bytes.len() / CHUNK_SIZE;

    // Create an iterator over the input Vec<u8>
    let chunked_verifier_queries = verifier_queries_bytes.chunks(CHUNK_SIZE);

    // - Deserialize verifier queries
    let mut verifier_queries: Vec<VerifierQuery> = Vec::with_capacity(num_openings);

    for verifier_query_bytes in chunked_verifier_queries {
        let verifier_query = deserialize_verifier_query(verifier_query_bytes);
        verifier_queries.push(verifier_query);
    }

    let mut transcript = Transcript::new(b"verkle");

    if proof.check(
        &context.crs,
        &context.precomputed_weights,
        &verifier_queries,
        &mut transcript,
    ) {
        Ok(())
    } else {
        Err(Error::ProofVerificationFailed)
    }
}

#[deprecated(
    note = "Parsing of the execution witness and preprocessing its input should be done by clients in the future"
)]
/// Verifies an execution witness as specified in the EIP and on Kaustinen.
///
/// For an example of the format, see: https://github.com/ethereumjs/ethereumjs-monorepo/blob/master/packages/statemanager/test/testdata/verkleKaustinenBlock.json#L1-L2626
pub fn verify_execution_witness(root: &str, execution_witness_json_str: &str) -> bool {
    let (verkle_proof, keys_values) = match VerkleProofGo::from_json_str(execution_witness_json_str)
        .from_verkle_proof_go_to_verkle_proof()
    {
        Some((verkle_proof, keys_values)) => (verkle_proof, keys_values),
        None => return false,
    };

    let root = match bytes32_to_element(hex_to_bytes32(root)) {
        Some(root) => root,
        None => return false,
    };

    let (ok, _) = verkle_proof.check(keys_values.keys, keys_values.current_values, root);
    ok
}

#[cfg(test)]
mod tests {
    use crate::{verify_execution_witness, Context};
    use banderwagon::Fr;
    use ipa_multipoint::committer::Committer;
    use verkle_trie::proof::golang_proof_format::{EXECUTION_WITNESS_JSON, PREVIOUS_STATE_ROOT};

    use crate::{fr_from_le_bytes, fr_to_le_bytes};

    #[test]
    fn exec_witness_works() {
        let result = verify_execution_witness(PREVIOUS_STATE_ROOT, EXECUTION_WITNESS_JSON);
        assert!(result);
    }

    #[test]
    fn commitment_update() {
        let context = Context::default();
        let committer = &context.committer;

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
            &context,
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
        let context = Context::default();
        let committer = &context.committer;

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
            &context,
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

#[test]
fn check_identity_constant() {
    let identity = Element::zero();
    let identity_bytes = identity.to_bytes_uncompressed();
    assert_eq!(identity_bytes, ZERO_POINT);
}
#[allow(deprecated)]
#[cfg(test)]
mod pedersen_hash_tests {

    use crate::{get_tree_key, get_tree_key_hash, Context};

    #[test]
    fn smoke_test_address_zero() {
        let context = Context::default();
        let address = [0u8; 32];
        let tree_index = [0u8; 32];

        let expected = "1a100684fd68185060405f3f160e4bb6e034194336b547bdae323f888d533207";
        let got_hash_bytes = get_tree_key_hash(&context, address, tree_index);
        let got_hash_hex = hex::encode(got_hash_bytes);
        assert_eq!(expected, got_hash_hex)
    }

    #[test]
    fn smoke_test_input() {
        let context = Context::default();
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

        let got_hash_bytes = get_tree_key(&context, address, tree_index, 0);

        let expected_hash = "ff7e3916badeb510dfcdad458726273319280742e553d8d229bd676428147300";
        let got_hash_hex = hex::encode(got_hash_bytes);
        assert_eq!(expected_hash, got_hash_hex);
    }
}

#[cfg(test)]
mod prover_verifier_test {

    use super::Context;
    use crate::fr_to_le_bytes;
    use crate::verify_proof;

    use ipa_multipoint::{committer::Committer, lagrange_basis::LagrangeBasis};

    #[test]
    fn test_one_opening_create_proof_verify_proof() {
        let a_0 = banderwagon::Fr::from(123u128);
        let a_1 = banderwagon::Fr::from(123u128);
        let a_2 = banderwagon::Fr::from(456u128);
        let a_3 = banderwagon::Fr::from(789u128);

        let mut _poly: LagrangeBasis;
        let mut all_vals = Vec::new();
        for _i in 0..64 {
            all_vals.push(a_0);
            all_vals.push(a_1);
            all_vals.push(a_2);
            all_vals.push(a_3);
        }

        let context = Context::new();

        let commitment = context.committer.commit_lagrange(all_vals.as_slice());

        let commitment_bytes = commitment.to_bytes();

        let mut poly_bytes: Vec<u8> = Vec::new();

        for val in all_vals.clone() {
            let bytes = fr_to_le_bytes(val);
            poly_bytes.extend_from_slice(&bytes);
        }

        let point_bytes = [2u8; 1];

        let result_bytes = fr_to_le_bytes(a_2);

        let mut create_prover_bytes: Vec<u8> = Vec::new();

        create_prover_bytes.extend_from_slice(&commitment_bytes);
        create_prover_bytes.extend_from_slice(&poly_bytes);
        create_prover_bytes.extend_from_slice(&point_bytes);
        create_prover_bytes.extend_from_slice(&result_bytes);

        let proof_bytes = super::create_proof(&context, create_prover_bytes).unwrap();

        let mut create_verifier_bytes: Vec<u8> = Vec::new();
        create_verifier_bytes.extend_from_slice(&commitment_bytes);
        create_verifier_bytes.extend_from_slice(&point_bytes);
        create_verifier_bytes.extend_from_slice(&result_bytes);

        let mut verifier_call_bytes: Vec<u8> = Vec::new();

        verifier_call_bytes.extend_from_slice(&proof_bytes);
        verifier_call_bytes.extend_from_slice(&create_verifier_bytes);

        let verified = verify_proof(&context, verifier_call_bytes).is_ok();

        assert!(verified);
    }

    #[test]
    fn test_multiple_openings_create_proof_verify_proof() {
        let a_0 = banderwagon::Fr::from(123u128);
        let a_1 = banderwagon::Fr::from(123u128);
        let a_2 = banderwagon::Fr::from(456u128);
        let a_3 = banderwagon::Fr::from(789u128);
        let context = Context::new();

        let mut create_prover_bytes: Vec<u8> = Vec::new();

        let mut create_verifier_bytes: Vec<u8> = Vec::new();
        for _iterate in 0..100 {
            let mut _poly: LagrangeBasis;
            let mut all_vals = Vec::new();
            for _i in 0..64 {
                all_vals.push(a_0);
                all_vals.push(a_1);
                all_vals.push(a_2);
                all_vals.push(a_3);
            }
            let commitment = context.committer.commit_lagrange(all_vals.as_slice());
            let commitment_bytes = commitment.to_bytes();

            let mut poly_bytes: Vec<u8> = Vec::new();

            for val in all_vals.clone() {
                let bytes = fr_to_le_bytes(val);
                poly_bytes.extend_from_slice(&bytes);
            }

            let point_bytes = [2u8; 1];

            let result_bytes = fr_to_le_bytes(a_2);

            create_prover_bytes.extend_from_slice(&commitment_bytes);
            create_prover_bytes.extend_from_slice(&poly_bytes);
            create_prover_bytes.extend_from_slice(&point_bytes);
            create_prover_bytes.extend_from_slice(&result_bytes);

            create_verifier_bytes.extend_from_slice(&commitment_bytes);
            create_verifier_bytes.extend_from_slice(&point_bytes);
            create_verifier_bytes.extend_from_slice(&result_bytes);
        }
        let proof_bytes = super::create_proof(&context, create_prover_bytes).unwrap();

        let mut verifier_call_bytes: Vec<u8> = Vec::new();

        verifier_call_bytes.extend_from_slice(&proof_bytes);
        verifier_call_bytes.extend_from_slice(&create_verifier_bytes);

        let verified = verify_proof(&context, verifier_call_bytes).is_ok();

        assert!(verified);
    }
}
