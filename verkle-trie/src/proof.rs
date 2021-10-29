use bandersnatch::{EdwardsProjective, Fr};
use std::collections::{BTreeMap, BTreeSet};

mod key_path_finder;
mod opening_data;
pub(crate) mod prover;
pub mod stateless_updater;
pub(crate) mod verifier;

// Given a polynomial `f`
// - `commitment` denotes the commitment to `f`
// - `point` denotes the point that we evaluate the polynomial `f` at
// - and result denotes the result of this evaluation.
#[derive(Debug)]
pub struct ProverQuery {
    pub commitment: EdwardsProjective,
    pub point: Fr,
    pub result: Fr,
    pub polynomial: Vec<Fr>,
}

#[derive(Debug)]
pub struct VerifierQuery {
    pub commitment: EdwardsProjective,
    pub point: Fr,
    pub result: Fr,
}

// Every stem node has an associated extension node
// This extension node commits to all of the data in a stem
// This is needed because a stem has multiple commitments associated with it,
// ie C1, C2, stem_commitment
// TODO we could probably not use ExtPresent and use KeyState directly?
// TODO Need to check if this is fine with the Verifier algorithm
// TODO Note KeyState holds more information
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ExtPresent {
    // This means that there is no extensions present at all
    // this corresponds to the case of when the key is not in the trie
    // and the place where we would place it is empty.
    None,
    // This means that there is an extension for a stem in the place where we would insert this key
    // but it is not the stem for the key in question
    // This also corresponds to the case where the key is not in the trie
    DifferentStem,
    // This means there is an extension for the stem for the key in question.
    // Note: This does not tell us if the key is in the trie.
    Present,
}

// Auxillary data that the verifier needs in order to reconstruct the verifier queries
#[derive(Debug, Clone)]
pub struct VerificationHint {
    // depths and extension present status sorted by stem
    depths: Vec<u8>,
    extension_present: Vec<ExtPresent>,
    // All of the stems which are in the trie,
    // however, we are not directly proving any of their values
    diff_stem_no_proof: BTreeSet<[u8; 31]>,
}

// Auxillary information that the verifier needs in order to update the root statelessly
pub struct UpdateHint {
    depths_and_ext_by_stem: BTreeMap<[u8; 31], (ExtPresent, u8)>,
    // This will be used to get the old commitment for a particular node
    // So that we can compute the delta between it and the new commitment
    commitments_by_path: BTreeMap<Vec<u8>, EdwardsProjective>,
    other_stems_by_prefix: BTreeMap<Vec<u8>, [u8; 31]>,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    verification_hint: VerificationHint,
    // Commitments sorted by their paths and then their indices
    // The root is taken out when we serialise, so the verifier does not receive it
    comms_sorted: Vec<EdwardsProjective>,
    //
    // TODO: We are missing the IPA proof structure
}

impl VerkleProof {
    pub fn from_bytes(bytes: &[u8]) -> VerkleProof {
        todo!()
    }

    pub fn check(
        self,
        keys: Vec<[u8; 32]>,
        values: Vec<Option<[u8; 32]>>,
        root: EdwardsProjective,
    ) -> (bool, Option<UpdateHint>) {
        let queries_update_hint = verifier::create_verifier_queries(self, keys, values, root);

        let (queries, update_hint) = match queries_update_hint {
            Some((queries, update_hint)) => (queries, update_hint),
            None => return (false, None),
        };

        // TODO: Verify queries when IPA is added

        (true, Some(update_hint))
    }
}

#[cfg(test)]
mod test {

    use crate::database::memory_db::MemoryDb;
    use crate::database::ReadOnlyHigherDb;
    use crate::proof::{prover, verifier};
    use crate::{trie::Trie, BasicCommitter};

    #[test]
    fn basic_proof_true() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(db, BasicCommitter);

        let mut keys = Vec::new();
        for i in 0..=3 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert(key_0, key_0);
        }
        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone());
        let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
        let (ok, _) = proof.check(keys, values, meta.commitment);
        assert!(ok);
    }

    #[test]
    fn prover_queries_match_verifier_queries() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(db, BasicCommitter);

        let mut keys = Vec::new();
        for i in 0..=3 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert(key_0, key_0);
        }
        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let (pq, _) = prover::create_prover_queries(&trie.storage, keys.clone());
        let proof = prover::create_verkle_proof(&trie.storage, keys.clone());

        let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
        let (vq, _) =
            verifier::create_verifier_queries(proof, keys, values, meta.commitment).unwrap();

        for (p, v) in pq.into_iter().zip(vq) {
            assert_eq!(p.commitment, v.commitment);
            assert_eq!(p.point, v.point);
            assert_eq!(p.result, v.result);
        }
    }
}
