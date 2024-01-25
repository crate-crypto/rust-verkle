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
use ipa_multipoint::multiproof::{MultiPoint, MultiPointProof, ProverQuery, VerifierQuery};
use ipa_multipoint::transcript::Transcript;

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

/// Compute the key used in the `get_tree_key` method
///
/// Returns a 32 byte slice representing the `key` to be used in `get_tree_key`
///
// TODO: We could probably make this use `map_to_field` instead of `.to_bytes`
pub fn get_tree_key_hash(committer: &DefaultCommitter, input: [u8; 64]) -> [u8; 32] {
    verkle_spec::hash64(committer, input).to_fixed_bytes()
}
/// This is exactly the same as `get_tree_key_hash` method.
/// Use get_tree_key_hash instead.
///
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
    // little endian bytes
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
    let old_scalar = fr_from_le_bytes(&old_scalar_bytes)?;
    let new_scalar = fr_from_le_bytes(&new_scalar_bytes)?;

    // w-v
    let delta = new_scalar - old_scalar;

    // (w-v)G
    let delta_commitment = committer.scalar_mul(delta, commitment_index as usize);

    // If commitment is empty, then we are creating a new commitment.
    if old_commitment_bytes == [0u8; 64] {
        Ok(delta_commitment.to_bytes_uncompressed())
    } else {
        let old_commitment = Element::from_bytes_unchecked_uncompressed(old_commitment_bytes);
        // vG + (w-v)G
        Ok((delta_commitment + old_commitment).to_bytes_uncompressed())
    }
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

    // If commitment is empty, then we are creating a new commitment.
    if old_commitment_bytes == [0u8; 64] {
        return Ok(delta_commitment.to_bytes_uncompressed());
    }
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
pub fn deprecated_serialize_commitment(commitment: CommitmentBytes) -> [u8; 64] {
    Element::from_bytes_unchecked_uncompressed(commitment).to_bytes_uncompressed()
}

// TODO: We use big endian bytes here to be interopable with the java implementation
// TODO: we should stick to one endianness everywhere to avoid confusion
#[allow(dead_code)]
fn fr_to_be_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    // serialized compressed outputs bytes in LE order, so we reverse to get BE order
    bytes.reverse();
    bytes
}
#[allow(dead_code)]
fn fr_from_be_bytes(bytes: &[u8]) -> Result<banderwagon::Fr, Error> {
    let mut bytes = bytes.to_vec();
    bytes.reverse(); // deserialize expects the bytes to be in little endian order
    banderwagon::Fr::deserialize_compressed(&bytes[..]).map_err(|_| {
        Error::FailedToDeserializeScalar {
            bytes: bytes.to_vec(),
        }
    })
}

// Little endian since java implementation will move to LE
// Will be used when we move to LE on java side.
#[allow(dead_code)]
fn fr_to_le_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}

fn fr_from_le_bytes(bytes: &[u8]) -> Result<banderwagon::Fr, Error> {
    let bytes = bytes.to_vec();
    banderwagon::Fr::deserialize_compressed(&bytes[..]).map_err(|_| {
        Error::FailedToDeserializeScalar {
            bytes: bytes.to_vec(),
        }
    })
}

/// Receives a tuple (C_i, f_i(X), z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 64 bytes
/// f_i(X) is the polynomial serialized as 8192 bytes since we have 256 Fr elements each serialized as 32 bytes
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes
/// Returns a proof serialized as bytes
///
/// This function assumes that the domain is always 256 values and commitment is 64bytes.
/// TODO: Test this function.
pub fn create_proof(
    precomputed_weights: &mut PrecomputedWeights,
    transcript: &mut Transcript,
    input: Vec<u8>,
) -> Vec<u8> {
    // Define the chunk size (8289 bytes)
    // C_i, f_i(X), z_i, y_i
    // 64, 8192, 1, 32
    // = 8289
    let chunk_size = 8289;
    // Create an iterator over the input Vec<u8>
    let chunked_data = input.chunks(chunk_size);

    let mut prover_queries: Vec<ProverQuery> = Vec::new();

    for chunk in chunked_data.into_iter() {
        if chunk.len() >= chunk_size {
            // Create c_i from the first 64 bytes
            let mut chunk_exact_size: [u8; 64] = [0u8; 64];
            chunk_exact_size.copy_from_slice(&chunk[0..64]);
            let c_i = Element::from_bytes_unchecked_uncompressed(chunk_exact_size);
            // Create f_x from the next 8192 bytes
            let f_i_x: Vec<u8> = chunk[64..8256].to_vec();

            let chunked_f_i_x_data = f_i_x.chunks(32);

            let mut collect_lagrange_basis: Vec<Fr> = Vec::new();
            for chunk_f_i_x in chunked_f_i_x_data.into_iter() {
                if chunk_f_i_x.len() >= 32 {
                    let data_f_i_x = chunk_f_i_x;
                    // Expect Fr to come as little endian bytes
                    let fr_data_f_i_x = Fr::from_le_bytes_mod_order(data_f_i_x);
                    collect_lagrange_basis.push(fr_data_f_i_x);
                }
            }

            let lagrange_basis = LagrangeBasis::new(collect_lagrange_basis);

            // Get the index from the chunk.
            let z_i: usize = chunk[8256] as usize;

            // Expect value(Fr) to come as little endian bytes.
            let y_i = Fr::from_le_bytes_mod_order(&chunk[8257..8289]);

            // Create a prover query from the current chunk.
            let prover_query = ProverQuery {
                commitment: c_i,
                poly: lagrange_basis,
                point: z_i,
                result: y_i,
            };
            prover_queries.push(prover_query);
        }
    }

    let crs = CRS::default();

    let proof = MultiPoint::open(crs, precomputed_weights, transcript, prover_queries);
    proof.to_bytes().unwrap()
}

/// Receives a proof and a tuple (C_i, z_i, y_i)
/// Where C_i is a commitment to f_i(X) serialized as 64 bytes (uncompressed commitment)
/// z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
/// y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes or Fr (scalar field element)
/// Returns true of false.
/// Proof is verified or not.
/// TODO: Test this function.
#[allow(dead_code)]
fn exposed_verify_call(
    precomputed_weights: &mut PrecomputedWeights,
    transcript: &mut Transcript,
    input: Vec<u8>,
) -> bool {
    // Proof bytes are 576 bytes
    // First 32 bytes is the g_x_comm_bytes
    // Next 544 bytes are part of IPA proof.
    let proof_bytes = &input[0..576];

    let proof = MultiPointProof::from_bytes(proof_bytes, 256).unwrap();

    let verifier_queries = &input[576..];

    // Define the chunk size 64+1+32 = 97 bytes for C_i, z_i, y_i
    let chunk_size = 97;
    // Create an iterator over the input Vec<u8>
    let chunked_data = verifier_queries.chunks(chunk_size);

    let mut verifier_queries: Vec<VerifierQuery> = Vec::new();

    for chunk in chunked_data.into_iter() {
        // We are expecting uncompressed 64 byte commitment (c_i)
        let mut chunk_exact_size: [u8; 64] = [0u8; 64];
        chunk_exact_size.copy_from_slice(&chunk[0..64]);
        let c_i = Element::from_bytes_unchecked_uncompressed(chunk_exact_size);

        // We are expecting 1 byte for the index (z_i)
        let z_i: Fr = Fr::from(chunk[32] as u128);

        // We are expecting 32 bytes for Fr value (y_i) little endian
        let y_i = Fr::from_le_bytes_mod_order(&chunk[33..65]);

        let verifier_query = VerifierQuery {
            commitment: c_i,
            point: z_i,
            result: y_i,
        };

        verifier_queries.push(verifier_query);
    }

    let crs = CRS::default();

    proof.check(&crs, precomputed_weights, &verifier_queries, transcript)
}

#[cfg(test)]
mod tests {
    use std::vec;

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
        let _a_3 = banderwagon::Fr::from(457u128);

        let _a_4 = banderwagon::Fr::from(0u128);

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
    fn from_le_to_le_bytes() {
        let value = banderwagon::Fr::from(123456u128);
        let bytes = fr_to_le_bytes(value);
        let got_value = fr_from_le_bytes(&bytes).unwrap();
        assert_eq!(got_value, value)
    }
}
