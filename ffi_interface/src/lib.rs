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
    // big endian bytes
    let mut inputs = Vec::with_capacity(num_scalars);
    for chunk in scalars.chunks_exact(32) {
        inputs.push(fr_from_be_bytes(chunk)?);
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
    let old_scalar = fr_from_be_bytes(&old_scalar_bytes)?;
    let new_scalar = fr_from_be_bytes(&new_scalar_bytes)?;

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
pub fn hash_commitment(commitment: CommitmentBytes) -> ScalarBytes {
    // TODO: We could introduce a method named `hash_commit_to_scalars`
    // TODO: which would save this serialization roundtrip. We should profile/check that
    // TODO: this is actually a bottleneck for the average workflow before doing this.
    fr_to_be_bytes(Element::from_bytes_unchecked_uncompressed(commitment).map_to_scalar_field())
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
        .map(fr_to_be_bytes)
        .collect()
}

/// This is kept so that commitRoot in the java implementation can be swapped out
/// Note: I believe we should not need to expose this method.
pub fn deprecated_serialize_commitment(commitment: CommitmentBytes) -> [u8; 32] {
    Element::from_bytes_unchecked_uncompressed(commitment).to_bytes()
}

// TODO: We use big endian bytes here to be interopable with the java implementation
// TODO: we should stick to one endianness everywhere to avoid confusion
fn fr_to_be_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    // serialized compressed outputs bytes in LE order, so we reverse to get BE order
    bytes.reverse();
    bytes
}
fn fr_from_be_bytes(bytes: &[u8]) -> Result<banderwagon::Fr, Error> {
    let mut bytes = bytes.to_vec();
    bytes.reverse(); // deserialize expects the bytes to be in little endian order
    banderwagon::Fr::deserialize_compressed(&bytes[..]).map_err(|_| {
        Error::FailedToDeserializeScalar {
            bytes: bytes.to_vec(),
        }
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

    for (_i, chunk) in chunked_data.enumerate() {
        if chunk.len() >= chunk_size {
            let data = chunk.clone();
            let commitment = Element::from_bytes(&data[0..32]).unwrap();

            // Create f_x from the next 8192 bytes
            let f_i_x: Vec<u8> = chunk[32..8224].to_vec();

            let chunked_f_i_x_data = f_i_x.chunks(32);

            let mut collect_lagrange_basis: Vec<Fr> = Vec::new();
            for (_j, chunk_f_i_x) in chunked_f_i_x_data.enumerate() {
                if chunk_f_i_x.len() >= 32 {
                    let data_f_i_x = chunk_f_i_x.clone();
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
    // TODO: This should be stored as static data somewhere.
    let precomp = PrecomputedWeights::new(256);

    let crs = CRS::default();
    // TODO: This should be stored as static data somewhere.
    let mut transcript = Transcript::new(b"verkle");

    let proof = MultiPoint::open(crs.clone(), &precomp, &mut transcript, prover_queries);
    proof.to_bytes().unwrap()
}

#[cfg(test)]
mod tests {
    use ipa_multipoint::{
        committer::{Committer, DefaultCommitter},
        crs::CRS,
    };

    use crate::{fr_from_be_bytes, fr_to_be_bytes};
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
            fr_to_be_bytes(a_0),
            fr_to_be_bytes(a_2),
        )
        .unwrap();

        assert_eq!(updated_commitment, naive_update.to_bytes_uncompressed())
    }

    #[test]
    fn from_be_to_be_bytes() {
        let value = banderwagon::Fr::from(123456u128);
        let bytes = fr_to_be_bytes(value);
        let got_value = fr_from_be_bytes(&bytes).unwrap();
        assert_eq!(got_value, value)
    }
}
