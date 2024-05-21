#![allow(clippy::large_enum_variant)]
use super::ExtPresent;
use crate::{
    constants::TWO_POW_128,
    database::{Meta, ReadOnlyHigherDb},
    proof::key_path_finder::{KeyNotFound, KeyPathFinder, KeyState},
};

use banderwagon::{trait_defs::*, Fr};
use ipa_multipoint::{lagrange_basis::LagrangeBasis, multiproof::ProverQuery};
use std::collections::{BTreeMap, BTreeSet};

// Stores opening data that can then be used to form opening queries
#[derive(Debug, Default)]
pub(crate) struct OpeningData {
    pub(crate) openings: BTreeMap<Vec<u8>, Openings>,
    // Auxillary data that we collect while fetching the opening data
    pub(crate) extension_present_by_stem: BTreeMap<[u8; 31], ExtPresent>,
    pub(crate) depths_by_stem: BTreeMap<[u8; 31], u8>,
}

impl OpeningData {
    fn insert_stem_extension_status(&mut self, stem: [u8; 31], ext: ExtPresent) {
        self.extension_present_by_stem.insert(stem, ext);
    }
    fn insert_branch_opening(&mut self, path: Vec<u8>, child_index: u8, meta: Meta) {
        let bo = BranchOpeningData {
            meta,
            children: BTreeSet::new(),
        };

        // Check if this opening has already been inserted.
        // If so, we just need to append the child_index to the existing list
        let old_branch = self
            .openings
            .entry(path)
            .or_insert(Openings::Branch(bo))
            .as_mut_branch();
        old_branch.children.insert(child_index);
    }
    fn insert_ext_opening(&mut self, path: Vec<u8>, stem: [u8; 31], meta: Meta) {
        let ext_open = ExtOpeningData { stem, meta };
        // Check if there is already an extension opening for this path inserted
        // If there is, then it will just have the same data, if not we insert it
        self.openings
            .entry(path)
            .or_insert(Openings::Extension(ext_open));
    }
    fn insert_suffix_opening(
        &mut self,
        path: Vec<u8>,
        ext_open: ExtOpeningData,
        suffix_value: (u8, Option<[u8; 32]>),
    ) {
        let mut suffices = BTreeSet::new();
        suffices.insert(suffix_value);
        let so = SuffixOpeningData {
            ext: ext_open,
            suffices,
        };

        // Check if this suffix opening has already been inserted
        // Note, it could also be an opening for an extension at the path
        // In that case, we overwrite the extension opening data with the suffix opening data
        match self.openings.get_mut(&path) {
            Some(old_val) => {
                // If the previous value was an extension opening
                // then we can just overwrite it, since the suffix opening
                // implicitly opens the extension
                //
                // If it was a suffix opening, then we just need to append
                // this suffix to that list
                match old_val {
                    Openings::Suffix(so) => {
                        assert_eq!(so.ext, ext_open);
                        so.suffices.insert(suffix_value);
                    }
                    Openings::Extension(eo) => {
                        assert_eq!(eo, &ext_open);
                        *old_val = Openings::Suffix(so);
                    }
                    Openings::Branch(_) => unreachable!(),
                }
            }
            None => {
                // If there was nothing inserted at this path,
                // then we just add the new suffixOpening
                self.openings.insert(path, Openings::Suffix(so));
            }
        };
    }
    pub(crate) fn collect_opening_data<Storage: ReadOnlyHigherDb>(
        keys: Vec<[u8; 32]>,
        storage: &Storage,
    ) -> OpeningData {
        let mut opening_data = OpeningData::default();

        for key in keys {
            let key_path = KeyPathFinder::find_key_path(storage, key);

            let requires_ext_proof = key_path.requires_extension_proof();
            let node_path = key_path.nodes;
            let key_state = key_path.key_state;
            let value = key_state.value();

            let stem: [u8; 31] = key[0..31].try_into().unwrap();
            let suffix = key[31];

            let ext_pres = match key_state {
                KeyState::Found(_) => ExtPresent::Present,
                KeyState::NotFound(nf) => match nf {
                    KeyNotFound::DifferentStem(_) => ExtPresent::DifferentStem,
                    KeyNotFound::StemFound => ExtPresent::Present,
                    KeyNotFound::Empty => ExtPresent::None,
                },
            };

            let (last_node_path, _, last_node_meta) = node_path.last().cloned().unwrap();

            // First iterate the node path and add the necessary branch opening data
            for (path, z, node) in node_path.into_iter() {
                if node.is_branch_meta() {
                    opening_data.insert_branch_opening(path, z, node);
                }
            }

            // We now need to check if the node_path leads to the key we want
            // or if it leads to a key-not-present state, we can check this with the KeyPath object.
            // Alternatively, we can note:
            //
            // - If the meta data for the last node was a branch
            // then no key was found and instead the slot where the key _would_
            // be found, if we inserted it, is empty.
            //
            // - If the metadata for the last node was a stem, then this does not mean that the key is present
            //
            // Here are the following cases:
            //
            //  - It could be the case that the stem we found does not belong to the key
            // This means that the key we searched for and the stem have a common prefix.
            //
            // - It could also be the case that the stem does match, however the key
            // is still not present. This means that there is a key in the trie
            // which shares the same stem, as the key we are inserting.
            //
            // It could be the case that the key was found

            // If an extension proof is not required, then no stem was found
            //
            if !requires_ext_proof {
                opening_data.depths_by_stem.insert(stem, key_path.depth);
                opening_data.insert_stem_extension_status(stem, ext_pres);
                continue;
            };
            assert!(last_node_meta.is_stem_meta());

            // Arriving here means that the key path terminated at a stem
            // Unconditionally, we need to provide an opening for the first two elements in the stems
            // extension, this is (1, stem)

            opening_data.depths_by_stem.insert(stem, key_path.depth - 1);
            let current_stem = key_state.different_stem().unwrap_or(stem);

            // Lets see if it was the stem for the key in question
            // If it is for a different stem, then we only need to show
            // existence of the extension, and not open C1 or C2
            if key_state.different_stem().is_some() {
                opening_data.insert_stem_extension_status(stem, ext_pres);
                opening_data.insert_ext_opening(last_node_path, current_stem, last_node_meta);

                continue;
            }

            // We now know that the key does in fact correspond to the stem
            // we found
            // If value is None, then the key is not in the trie
            // This function however does care whether the value was None or if it was written to
            // since both cases lead to one needing to have a Suffix Opening
            opening_data.insert_stem_extension_status(stem, ext_pres);

            let ext_open = ExtOpeningData {
                stem: current_stem,
                meta: last_node_meta,
            };
            opening_data.insert_suffix_opening(last_node_path, ext_open, (suffix, value))
        }

        opening_data
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
// Data needed to open an extension node
pub(crate) struct ExtOpeningData {
    pub(crate) stem: [u8; 31],
    pub(crate) meta: Meta,
}

impl ExtOpeningData {
    // Creates two openings for at points 0 and 1
    pub fn open_query(&self, open_c1: bool, open_c2: bool) -> Vec<ProverQuery> {
        let stem = self.stem;
        let stem_meta = self.meta.into_stem();

        let ext_func = vec![
            Fr::one(),
            Fr::from_le_bytes_mod_order(&stem),
            stem_meta.hash_c1,
            stem_meta.hash_c2,
        ];

        // Open(Ext, 0) = 1
        let open_at_one = ProverQuery {
            commitment: stem_meta.stem_commitment,
            point: 0,
            result: Fr::one(),
            poly: LagrangeBasis::new(ext_func.clone()),
        };

        // Open(Ext, 1) = stem
        let open_at_stem = ProverQuery {
            commitment: stem_meta.stem_commitment,
            point: 1,
            result: Fr::from_le_bytes_mod_order(&stem),
            poly: LagrangeBasis::new(ext_func.clone()),
        };

        let mut open_queries = Vec::with_capacity(4);
        open_queries.push(open_at_one);
        open_queries.push(open_at_stem);

        if open_c1 {
            let open_at_c1 = ProverQuery {
                commitment: stem_meta.stem_commitment,
                point: 2,
                result: stem_meta.hash_c1,
                poly: LagrangeBasis::new(ext_func.clone()),
            };
            open_queries.push(open_at_c1);
        }
        if open_c2 {
            let open_at_c2 = ProverQuery {
                commitment: stem_meta.stem_commitment,
                point: 3,
                result: stem_meta.hash_c2,
                poly: LagrangeBasis::new(ext_func),
            };
            open_queries.push(open_at_c2);
        }

        open_queries
    }
}

// Data needed to open a suffix
// This does not include all of the values in the polynomial
// for that, we make an external call to the database when creating OpeningQueries
#[derive(Debug)]
pub(crate) struct SuffixOpeningData {
    // All suffixes must have an associated extension opening
    pub(crate) ext: ExtOpeningData,

    // The suffices to open this suffix tree at
    // and their associated value. value is none if the key is not in
    // the trie
    pub(crate) suffices: BTreeSet<(u8, Option<[u8; 32]>)>,
}

impl SuffixOpeningData {
    // Returns all of the queries needed for the associated extension
    // and the suffices
    pub fn open_query<Storage: ReadOnlyHigherDb>(&self, storage: &Storage) -> Vec<ProverQuery> {
        // Find out if we need to open up at C1 and/or C2
        let mut open_c1 = false;
        let mut open_c2 = false;
        for (sfx, _) in self.suffices.iter() {
            if *sfx < 128 {
                open_c1 = true;
            } else {
                open_c2 = true;
            }
        }

        // Open the extension
        let mut ext_queries = self.ext.open_query(open_c1, open_c2);
        // Open all suffices
        let mut suffice_queries = Vec::with_capacity(self.suffices.len());
        let stem_meta = self.ext.meta.into_stem();

        for (sfx, value) in &self.suffices {
            let value_lower_index = 2 * (sfx % 128);
            let value_upper_index = value_lower_index + 1;

            let (value_low, value_high) = match value {
                Some(bytes) => (
                    Fr::from_le_bytes_mod_order(&bytes[0..16]) + TWO_POW_128,
                    Fr::from_le_bytes_mod_order(&bytes[16..32]),
                ),
                None => (Fr::zero(), Fr::zero()),
            };

            let offset = if *sfx < 128 { 0 } else { 128 };
            let c1_or_c2 =
                get_half_of_stem_children_children_hashes(self.ext.stem, offset, storage);

            let commitment = if *sfx < 128 {
                stem_meta.c_1
            } else {
                stem_meta.c_2
            };
            let open_at_val_low = ProverQuery {
                commitment,
                point: value_lower_index as usize,
                result: value_low,
                poly: LagrangeBasis::new(c1_or_c2.clone()),
            };
            let open_at_val_upper = ProverQuery {
                commitment,
                point: value_upper_index as usize,
                result: value_high,
                poly: LagrangeBasis::new(c1_or_c2),
            };

            suffice_queries.push(open_at_val_low);
            suffice_queries.push(open_at_val_upper);
        }
        ext_queries.extend(suffice_queries);
        ext_queries
    }
}
#[derive(Debug)]
pub(crate) struct BranchOpeningData {
    pub(crate) meta: Meta,
    // open this node at these children
    pub(crate) children: BTreeSet<u8>,
}

impl BranchOpeningData {
    pub fn open_query<Storage: ReadOnlyHigherDb>(
        &self,
        branch_path: &[u8],
        storage: &Storage,
    ) -> Vec<ProverQuery> {
        let mut branch_queries = Vec::with_capacity(self.children.len());
        let branch_meta = self.meta.into_branch();

        // Get all children hashes for this branch, return zero if the child is missing
        let polynomial = get_branch_children_hashes(branch_path.to_vec(), storage);

        // Create queries for all of the children we need
        for child_index in &self.children {
            let child_value = polynomial[*child_index as usize];

            let branch_query = ProverQuery {
                commitment: branch_meta.commitment,
                point: *child_index as usize,
                result: child_value,
                poly: LagrangeBasis::new(polynomial.clone()),
            };

            branch_queries.push(branch_query);
        }

        branch_queries
    }
}
#[derive(Debug)]
pub(crate) enum Openings {
    Suffix(SuffixOpeningData),
    Branch(BranchOpeningData),
    Extension(ExtOpeningData),
}

impl Openings {
    pub(crate) fn as_mut_branch(&mut self) -> &mut BranchOpeningData {
        match self {
            Openings::Suffix(_) | Openings::Extension(_) => {
                panic!("unexpected enum variant")
            }
            Openings::Branch(b) => b,
        }
    }
}

fn get_branch_children_hashes<Storage: ReadOnlyHigherDb>(
    path: Vec<u8>,
    storage: &Storage,
) -> Vec<Fr> {
    let mut child_hashes = Vec::with_capacity(256);
    for i in 0..=255 {
        let child = storage.get_branch_child(&path, i); // TODO this should use a range query
        let hash = match child {
            Some(b_child) => match b_child {
                crate::database::BranchChild::Stem(stem_id) => {
                    storage.get_stem_meta(stem_id).unwrap().hash_stem_commitment
                }
                crate::database::BranchChild::Branch(b_meta) => b_meta.hash_commitment,
            },
            None => Fr::zero(),
        };
        child_hashes.push(hash);
    }
    child_hashes
}
fn get_half_of_stem_children_children_hashes<Storage: ReadOnlyHigherDb>(
    stem_id: [u8; 31],
    start: u8,
    storage: &Storage,
) -> Vec<Fr> {
    assert!(start == 0 || start == 128);
    let mut child_hashes = Vec::with_capacity(256);

    // 0 to 127 is first 128 elements
    // 128 to 255 is the second 128 elements
    let end = start + 127;
    for i in start..=end {
        let mut leaf_key = stem_id.to_vec();
        leaf_key.push(i);
        let leaf_key: [u8; 32] = leaf_key.try_into().unwrap();
        let leaf_val = storage.get_leaf(leaf_key); //TODO this should use a range query

        let (lower, upper) = match leaf_val {
            Some(bytes) => {
                let lower = Fr::from_le_bytes_mod_order(&bytes[0..16]) + TWO_POW_128;
                let upper = Fr::from_le_bytes_mod_order(&bytes[16..32]);
                (lower, upper)
            }
            None => {
                let val = [0u8; 32];
                let lower = Fr::from_le_bytes_mod_order(&val[0..16]);
                let upper = Fr::from_le_bytes_mod_order(&val[16..32]);
                (lower, upper)
            }
        };
        child_hashes.push(lower);
        child_hashes.push(upper);
    }

    assert_eq!(child_hashes.len(), 256);

    child_hashes
}
