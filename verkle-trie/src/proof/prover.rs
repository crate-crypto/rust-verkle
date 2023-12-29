use super::{VerificationHint, VerkleProof};
use crate::{
    constants::{CRS, PRECOMPUTED_WEIGHTS},
    database::ReadOnlyHigherDb,
    errors::ProofCreationError,
    proof::opening_data::{OpeningData, Openings},
};
use ipa_multipoint::{
    multiproof::{MultiPoint, ProverQuery},
    transcript::Transcript,
};
use itertools::Itertools;
use std::collections::BTreeSet;

pub fn create_verkle_proof<Storage: ReadOnlyHigherDb>(
    storage: &Storage,
    keys: Vec<[u8; 32]>,
) -> Result<VerkleProof, ProofCreationError> {
    if keys.is_empty() {
        return Err(ProofCreationError::EmptyKeySet);
    }
    let (queries, verification_hint) = create_prover_queries(storage, keys);

    // Commitments without duplicates and without the root, (implicitly) sorted by path, since the queries were
    // processed by path order
    let root_query = match queries.first() {
        Some(query) => query,
        None => return Err(ProofCreationError::ExpectedOneQueryAgainstRoot),
    };

    let root_comm = root_query.commitment;

    let comms_sorted: Vec<_> = queries
        .iter()
        // Filter out the root commitment
        .filter(|query| query.commitment != root_comm)
        // Pull out the commitments from each query
        .map(|query| query.commitment)
        // Duplicate all commitments
        .dedup()
        .collect();

    let mut transcript = Transcript::new(b"vt");
    let proof = MultiPoint::open(CRS.clone(), &PRECOMPUTED_WEIGHTS, &mut transcript, queries);

    Ok(VerkleProof {
        comms_sorted,
        verification_hint,
        proof,
    })
}

// First we need to produce all of the key paths for a key
// We can do some caching here to save memory, in particular if we fetch the same node more than once
// we just need to save it once.
//
// Notes on this abstraction, since a stem always comes with an extension, we can abstract this away
// An extension always has two openings, so we can also abstract this away (1, stem)
pub(super) fn create_prover_queries<Storage: ReadOnlyHigherDb>(
    storage: &Storage,
    keys: Vec<[u8; 32]>,
) -> (Vec<ProverQuery>, VerificationHint) {
    assert!(!keys.is_empty(), "cannot create a proof without keys");

    let opening_data = OpeningData::collect_opening_data(keys, storage);
    let openings = opening_data.openings;
    let extension_present_by_stem = opening_data.extension_present_by_stem;
    let depths_by_stem = opening_data.depths_by_stem;

    // Process all of the node openings data and create polynomial queries from them
    // We also collect all of the stems which are in the trie, however they do not have their own proofs
    // These are the Openings which are jus extensions
    let mut queries = Vec::new();

    //Stems that are in the trie, but don't have their own extension proofs
    let mut diff_stem_no_proof = BTreeSet::new();
    for (path, openings) in &openings {
        match openings {
            Openings::Suffix(so) => queries.extend(so.open_query(storage)),
            Openings::Branch(bo) => queries.extend(bo.open_query(path, storage)),
            Openings::Extension(eo) => {
                diff_stem_no_proof.insert(eo.stem);
                queries.extend(eo.open_query(false, false));
            }
        }
    }

    // Values to help the verifier reconstruct the trie and verify the proof
    let depths: Vec<_> = depths_by_stem.into_values().collect();
    let extension_present: Vec<_> = extension_present_by_stem.into_values().collect();

    (
        queries,
        VerificationHint {
            depths,
            extension_present,
            diff_stem_no_proof,
        },
    )
}
