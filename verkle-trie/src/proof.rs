use crate::{
    constants::{CRS, PRECOMPUTED_WEIGHTS},
    errors::HintError,
};

use banderwagon::Element;
use ipa_multipoint::multiproof::MultiPointProof;
use ipa_multipoint::transcript::Transcript;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

pub mod golang_proof_format;
mod key_path_finder;
mod opening_data;
pub(crate) mod prover;
pub mod stateless_updater;
pub(crate) mod verifier;

// Every stem node has an associated extension node
// This extension node commits to all of the data in a stem
// This is needed because a stem has multiple commitments associated with it,
// ie C1, C2, stem_commitment
// TODO we could probably not use ExtPresent and use KeyState directly?
// TODO Need to check if this is fine with the Verifier algorithm
// TODO Note KeyState holds more information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtPresent {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationHint {
    // depths and extension present status sorted by stem
    pub depths: Vec<u8>,
    pub extension_present: Vec<ExtPresent>,
    // All of the stems which are in the trie,
    // however, we are not directly proving any of their values
    pub diff_stem_no_proof: BTreeSet<[u8; 31]>,
}

impl std::fmt::Display for VerificationHint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for d in &self.depths {
            write!(f, "{} ", d)?;
        }
        for e in &self.extension_present {
            write!(f, "{:?} ", e)?;
        }
        for s in &self.diff_stem_no_proof {
            write!(f, "{} ", hex::encode(s))?;
        }
        std::fmt::Result::Ok(())
    }
}

impl VerificationHint {
    // We need the number of keys because we do not serialize the length of
    // the ext_status|| depth. This is equal to the number of keys in the proof, which
    // we assume the user knows.
    pub fn read<R: Read>(mut reader: R) -> Result<VerificationHint, HintError> {
        // First extract the stems with no values opened for them
        let mut num_stems = [0u8; 4];
        reader.read_exact(&mut num_stems)?;
        let num_stems = u32::from_le_bytes(num_stems);

        let mut diff_stem_no_proof: BTreeSet<[u8; 31]> = BTreeSet::new();
        for _ in 0..num_stems {
            let mut stem = [0u8; 31];
            reader.read_exact(&mut stem)?;
            diff_stem_no_proof.insert(stem);
        }

        // Now extract the depth and ext status
        let mut num_depths = [0u8; 4];
        reader.read_exact(&mut num_depths)?;
        let num_depths: usize = u32::from_le_bytes(num_depths) as usize; // Assuming hardware is 32/64 bit, so usize is at least a u32

        let mut depths = Vec::new();
        let mut extension_present = Vec::new();

        let mut buffer = vec![0u8; num_depths];
        reader.read_exact(&mut buffer)?;

        for byte in buffer {
            // use a mask to get the last two bits
            const MASK: u8 = 3;
            let ext_status = MASK & byte;
            let ext_status = match ext_status {
                0 => ExtPresent::None,
                1 => ExtPresent::DifferentStem,
                2 => ExtPresent::Present,
                x => panic!("unexpected ext status number {} ", x),
            };
            // shift away the last 3 bits in order to get the depth
            let depth = byte >> 3;
            depths.push(depth);
            extension_present.push(ext_status)
        }

        Ok(VerificationHint {
            depths,
            extension_present,
            diff_stem_no_proof,
        })
    }
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), HintError> {
        // Encode the number of stems with no value openings
        let num_stems = self.diff_stem_no_proof.len() as u32;
        writer.write_all(&num_stems.to_le_bytes())?;

        for stem in &self.diff_stem_no_proof {
            writer.write_all(stem)?;
        }

        let num_depths = self.depths.len() as u32;
        writer.write_all(&num_depths.to_le_bytes())?;

        // The depths and extension status can be put into a single byte
        // because extension status only needs 3 bits and depth only needs at most 5 bits
        for (depth, ext_status) in self.depths.iter().zip(&self.extension_present) {
            let mut byte = 0;
            // Encode extension status into the byte
            match ext_status {
                ExtPresent::None => {
                    // For None, we set the bit to be zero, so do nothing
                }
                ExtPresent::DifferentStem => {
                    // For different stem, we set the first bit to be 1
                    // This corresponds to the number 1.
                    byte = 1;
                }
                ExtPresent::Present => {
                    // For present, we set the second bit to be 1
                    // and the first bit to be zero
                    // This corresponds to the number 2.
                    byte = 2;
                }
            };

            // Encode depth into the byte, it should only be less
            // than or equal to 32, and so we only need 5 bits.
            debug_assert!(*depth <= 32);
            byte |= depth << 3;

            writer.write_all(&[byte])?;
        }
        Ok(())
    }
}

// Auxillary information that the verifier needs in order to update the root statelessly
pub struct UpdateHint {
    depths_and_ext_by_stem: BTreeMap<[u8; 31], (ExtPresent, u8)>,
    // This will be used to get the old commitment for a particular node
    // So that we can compute the delta between it and the new commitment
    commitments_by_path: BTreeMap<Vec<u8>, Element>,
    other_stems_by_prefix: BTreeMap<Vec<u8>, [u8; 31]>,
}

// TODO: We make the fields of VerkleProof public due to these being exposed in
// TODO: the Block/golang code, so for now they need to be public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerkleProof {
    pub verification_hint: VerificationHint,
    // Commitments sorted by their paths and then their indices
    // The root is taken out when we serialize, so the verifier does not receive it
    pub comms_sorted: Vec<Element>,
    //
    pub proof: MultiPointProof,
}

impl VerkleProof {
    pub fn read<R: Read>(mut reader: R) -> Result<VerkleProof, HintError> {
        let verification_hint = VerificationHint::read(&mut reader)?;

        let mut num_comms = [0u8; 4];
        reader.read_exact(&mut num_comms)?;
        let num_comms = u32::from_le_bytes(num_comms);

        let mut comms_sorted = Vec::new();
        for _ in 0..num_comms {
            let mut comm_serialized = [0u8; 32];
            reader.read_exact(&mut comm_serialized)?;

            let point = Element::from_bytes(&comm_serialized).ok_or(HintError::from(
                std::io::Error::from(std::io::ErrorKind::InvalidData),
            ))?;

            comms_sorted.push(point);
        }
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let proof = MultiPointProof::from_bytes(&bytes, crate::constants::VERKLE_NODE_WIDTH)?;

        Ok(VerkleProof {
            verification_hint,
            comms_sorted,
            proof,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> Result<(), HintError> {
        // Errors are handled via anyhow because they are generic IO errors, not Verkle-specific
        self.verification_hint.write(&mut writer)?;

        let num_comms = self.comms_sorted.len() as u32;
        writer.write_all(&num_comms.to_le_bytes())?;

        for comm in &self.comms_sorted {
            let comm_serialized = comm.to_bytes();
            writer.write_all(&comm_serialized)?;
        }

        // Serialize the Multipoint proof
        let proof_bytes = self.proof.to_bytes()?;
        writer.write_all(&proof_bytes)?;

        Ok(())
    }

    pub fn check(
        self,
        keys: Vec<[u8; 32]>,
        values: Vec<Option<[u8; 32]>>,
        root: Element,
    ) -> (bool, Option<UpdateHint>) {
        // TODO: check the commitments are in the correct subgroup
        // TODO: possibly will be done with Decaf

        // TODO: remove need for this Clone, by splitting off the IPA proof object
        // TODO here and sending the rest of the struct to create_verifier_queries
        let proof = self.proof.clone();
        let queries_update_hint = verifier::create_verifier_queries(self, keys, values, root);

        let (queries, update_hint) = match queries_update_hint {
            Some((queries, update_hint)) => (queries, update_hint),
            None => return (false, None),
        };

        let mut transcript = Transcript::new(b"vt");
        let ok = proof.check(&CRS, &PRECOMPUTED_WEIGHTS, &queries, &mut transcript);

        (ok, Some(update_hint))
    }
}

impl std::fmt::Display for VerkleProof {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Verkle proof:")?;
        writeln!(f, " * verification hints: {}", self.verification_hint)?;
        write!(f, " * commitments: ")?;
        for comm in self
            .comms_sorted
            .iter()
            .map(|comm| hex::encode(comm.to_bytes()))
        {
            write!(f, "{} ", comm)?;
        }
        std::fmt::Result::Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::VerkleProof;
    use crate::database::{memory_db::MemoryDb, ReadOnlyHigherDb};
    use crate::proof::{prover, verifier};
    use crate::{trie::Trie, DefaultConfig, TrieTrait};
    use banderwagon::Fr;

    #[test]
    fn basic_proof_true() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let mut keys = Vec::new();
        for i in 0..=3 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert_single(key_0, key_0);
        }
        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();
        let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
        let (ok, _) = proof.check(keys, values, meta.commitment);
        assert!(ok);
    }
    #[test]
    fn proof_of_absence_edge_case() {
        let db = MemoryDb::new();
        let trie = Trie::new(DefaultConfig::new(db));

        let absent_keys = vec![[3; 32]];
        let absent_values = vec![None];

        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, absent_keys.clone()).unwrap();

        let (ok, _) = proof.check(absent_keys, absent_values, meta.commitment);
        assert!(ok);
    }

    #[test]
    fn prover_queries_match_verifier_queries() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let mut keys = Vec::new();
        for i in 0..=3 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert_single(key_0, key_0);
        }
        let root = vec![];
        let meta = trie.storage.get_branch_meta(&root).unwrap();

        let (pq, _) = prover::create_prover_queries(&trie.storage, keys.clone());
        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

        let values: Vec<_> = keys.iter().map(|val| Some(*val)).collect();
        let (vq, _) =
            verifier::create_verifier_queries(proof, keys, values, meta.commitment).unwrap();

        for (p, v) in pq.into_iter().zip(vq) {
            assert_eq!(p.commitment, v.commitment);
            assert_eq!(Fr::from(p.point as u128), v.point);
            assert_eq!(p.result, v.result);
        }
    }

    #[test]
    fn simple_serialization_consistency() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let mut keys = Vec::new();
        for i in 0..=3 {
            let mut key_0 = [0u8; 32];
            key_0[0] = i;
            keys.push(key_0);
            trie.insert_single(key_0, key_0);
        }
        let root = vec![];
        let _meta = trie.storage.get_branch_meta(&root).unwrap();

        let proof = prover::create_verkle_proof(&trie.storage, keys.clone()).unwrap();

        let mut bytes = Vec::new();
        proof.write(&mut bytes).unwrap();
        let deserialized_proof = VerkleProof::read(&bytes[..]).unwrap();
        assert_eq!(proof, deserialized_proof);
    }
}
