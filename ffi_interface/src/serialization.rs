use banderwagon::{CanonicalDeserialize, CanonicalSerialize};
use banderwagon::{Element, Fr};
use ipa_multipoint::{
    lagrange_basis::LagrangeBasis,
    multiproof::{ProverQuery, VerifierQuery},
};

use crate::{CommitmentBytes, Error, ScalarBytes};

// TODO: Find a better name for this
pub type DeserializedSparseCommitmentItem = (
    CommitmentBytes,
    Vec<usize>,
    Vec<ScalarBytes>,
    Vec<ScalarBytes>,
);

/// TODO: This method should not be exported. Leave it exported for now, so that its not
/// a breaking change.
///
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

/// Serializes a commitment to a byte array
///
/// Note: This is used so that we can serialize the root node.
pub fn serialize_commitment(commitment: CommitmentBytes) -> [u8; 32] {
    Element::from_bytes_unchecked_uncompressed(commitment).to_bytes()
}
/// Deserialize a serialized commitment
///
/// Note: This is used so that we can deserialize the root node.
pub fn deserialize_commitment(serialized_commitment: [u8; 32]) -> Result<CommitmentBytes, Error> {
    let element = Element::from_bytes(&serialized_commitment).ok_or_else(|| {
        Error::CouldNotDeserializeCommitment {
            bytes: serialized_commitment.to_vec(),
        }
    })?;
    Ok(element.to_bytes_uncompressed())
}

#[must_use]
pub(crate) fn deserialize_proof_query(bytes: &[u8]) -> ProverQuery {
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
pub(crate) fn deserialize_verifier_query(bytes: &[u8]) -> VerifierQuery {
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
pub(crate) fn take_group_element(bytes: &[u8]) -> (Element, &[u8]) {
    let element = Element::from_bytes(&bytes[0..32]).expect("could not deserialize element");
    // Increment the slice by 32 bytes
    (element, &bytes[32..])
}

#[must_use]
pub(crate) fn take_byte(bytes: &[u8]) -> (usize, &[u8]) {
    let z_i = bytes[0] as usize;
    // Increment the slice by 32 bytes
    (z_i, &bytes[1..])
}
#[must_use]
pub(crate) fn take_scalar(bytes: &[u8]) -> (Fr, &[u8]) {
    let y_i = fr_from_le_bytes(&bytes[0..32]).expect("could not deserialize y_i");
    // Increment the slice by 32 bytes
    (y_i, &bytes[32..])
}

pub(crate) fn fr_to_le_bytes(fr: banderwagon::Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fr.serialize_compressed(&mut bytes[..])
        .expect("Failed to serialize scalar to bytes");
    bytes
}
pub(crate) fn fr_from_le_bytes(bytes: &[u8]) -> Result<banderwagon::Fr, Error> {
    banderwagon::Fr::deserialize_uncompressed(bytes).map_err(|_| Error::FailedToDeserializeScalar {
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use banderwagon::{Element, Fr};
    use ipa_multipoint::committer::Committer;

    use crate::{
        serialization::deserialize_update_commitment_sparse, serialize_commitment,
        update_commitment_sparse, Context, ZERO_POINT,
    };

    use super::deserialize_commitment;

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

    #[test]
    fn serialize_commitment_roundtrip() {
        let gen = Element::zero();

        // Serialize the commitment
        let gen_uncompressed_bytes = gen.to_bytes_uncompressed();
        let serialized_commitment = serialize_commitment(gen_uncompressed_bytes);

        let got_commitment_bytes = deserialize_commitment(serialized_commitment).unwrap();
        let got_commitment = Element::from_bytes_unchecked_uncompressed(got_commitment_bytes);

        // Note that we do not compare the raw uncompressed_bytes.
        //
        // See the note on `to_bytes_uncompressed` -- that method does not guarantee uniqueness
        // of the decoding with respects to the quotient group.

        assert_eq!(gen, got_commitment);
    }
}
