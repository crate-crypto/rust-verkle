use banderwagon::Fr;
use banderwagon::{trait_defs::*, Element};
use ipa_multipoint::committer::{Committer, DefaultCommitter};
use ipa_multipoint::crs::CRS;
use ipa_multipoint::lagrange_basis::{LagrangeBasis, PrecomputedWeights};
use ipa_multipoint::multiproof::{MultiPoint, MultiPointProof, ProverQuery, VerifierQuery};
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
    MoreThan256Scalars {
        len: usize,
    },
    FailedToDeserializeScalar {
        bytes: Vec<u8>,
    },
    LengthIsNotAnExpectedMultiple {
        item_descriptor: &'static str,
        expected_multiple: u64,
        actual_size: u64,
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
        return Err(Error::MoreThan256Scalars { len: num_scalars });
    }

    // We want to ensure interoperability with the Java-EVM for now, so we interpret the scalars as
    // big endian bytes
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

// TODO: Find a better name for this
pub type DeserializedSparseCommitmentItem = (
    CommitmentBytes,
    Vec<usize>,
    Vec<ScalarBytes>,
    Vec<ScalarBytes>,
);

/// This is used for deserializing the input for `update_commitment_sparse`.
pub fn deserialize_update_commitment_sparse(
    input: Vec<u8>,
) -> Result<DeserializedSparseCommitmentItem, Error> {
    // First 64 bytes is the commitment
    let commitment_bytes = CommitmentBytes::try_from(&input[0..64]).unwrap();

    // Chunkify leftover with 65 bytes (32, 32, 1)
    const CHUNK_SIZE: usize = 65;

    let input_without_commitment_bytes = &input[64..];

    if input_without_commitment_bytes.len() % CHUNK_SIZE != 0 {
        return Err(Error::LengthIsNotAnExpectedMultiple {
            item_descriptor: "input for update commitment",
            expected_multiple: CHUNK_SIZE as u64,
            actual_size: input_without_commitment_bytes.len() as u64,
        });
    }

    let update_commitment_bytes = input_without_commitment_bytes.chunks_exact(CHUNK_SIZE);
    assert!(
        update_commitment_bytes.remainder().is_empty(),
        "There should be no left over bytes when chunking the input"
    );

    let mut indexes: Vec<usize> = Vec::new();
    let mut old_scalars: Vec<ScalarBytes> = Vec::new();
    let mut new_scalars: Vec<ScalarBytes> = Vec::new();

    for update_commitment_bytes in update_commitment_bytes {
        // First 32 bytes is the old scalar
        let old_scalar = ScalarBytes::try_from(&update_commitment_bytes[0..32]).unwrap();
        old_scalars.push(old_scalar);
        // Next 32 bytes is the new scalar
        let new_scalar = ScalarBytes::try_from(&update_commitment_bytes[32..64]).unwrap();
        new_scalars.push(new_scalar);
        // Last byte is the index
        // This works properly with only with this syntax
        let index: &usize = &update_commitment_bytes[64].into();
        indexes.push(*index);
    }
    Ok((commitment_bytes, indexes, old_scalars, new_scalars))
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
pub fn create_proof(context: &Context, input: Vec<u8>) -> Result<Vec<u8>, Error> {
    // - Checks for the serialized proof queries
    ///
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
#[allow(dead_code)]
pub fn verify_proof(input: Vec<u8>) -> Result<(), Error> {
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

    let context = Context::new();

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
fn deserialize_verifier_query(bytes: &[u8]) -> VerifierQuery {
    // Commitment
    let (commitment, bytes) = take_group_element(bytes);

    // The input point is a single byte
    let (z_i, bytes) = take_byte(bytes);

    // The evaluation is a single scalar
    let (y_i, bytes) = take_scalar(bytes);

    assert!(bytes.is_empty(), "we should have consumed all the bytes");

    VerifierQuery {
        commitment,
        point: Fr::from(z_i as u128),
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
    use crate::deserialize_update_commitment_sparse;
    use crate::update_commitment_sparse;
    use crate::Context;
    use crate::ZERO_POINT;
    use banderwagon::Fr;
    use ipa_multipoint::committer::Committer;

    use crate::{fr_from_le_bytes, fr_to_le_bytes};
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
    #[test]
    fn test_byte_array_input_update_commitment_sparse() {
        let old_commitment_bytes = ZERO_POINT;

        let index = 7u8;
        let old_scalar = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let new_scalar = [
            19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let index2 = 8u8;
        let old_scalar2 = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let new_scalar2 = [
            17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let mut concatenated: Vec<u8> = Vec::from(ZERO_POINT);
        concatenated.extend_from_slice(&old_scalar);
        concatenated.extend_from_slice(&new_scalar);
        concatenated.push(index);

        concatenated.extend_from_slice(&old_scalar2);
        concatenated.extend_from_slice(&new_scalar2);
        concatenated.push(index2);

        let (_old_commitment, commitment_index_vec, old_scalar_bytes_vec, new_scalar_bytes_vec) =
            deserialize_update_commitment_sparse(concatenated).unwrap();

        let context = Context::default();
        let committer = &context.committer;

        let new_commitment = update_commitment_sparse(
            &context,
            old_commitment_bytes,
            commitment_index_vec,
            old_scalar_bytes_vec,
            new_scalar_bytes_vec,
        )
        .unwrap();

        let val_indices: Vec<(Fr, usize)> = vec![(Fr::from(17u8), 7), (Fr::from(15u8), 8)];

        let test_comm = committer.commit_sparse(val_indices);

        assert_eq!(test_comm.to_bytes_uncompressed(), new_commitment);
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

        let expected = "bf101a6e1c8e83c11bd203a582c7981b91097ec55cbd344ce09005c1f26d1922";
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

        let expected_hash = "76a014d14e338c57342cda5187775c6b75e7f0ef292e81b176c7a5a700273700";
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

        let verified = verify_proof(verifier_call_bytes).is_ok();

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

        let verified = verify_proof(verifier_call_bytes).is_ok();

        assert!(verified);
    }
}
