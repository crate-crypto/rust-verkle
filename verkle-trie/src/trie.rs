#![allow(clippy::large_enum_variant)]
use crate::constants::{CRS, TWO_POW_128};
use crate::database::{BranchMeta, Flush, Meta, ReadWriteHigherDb, StemMeta};
use crate::Config;
use crate::{group_to_field, TrieTrait};
use ipa_multipoint::committer::Committer;

use banderwagon::{trait_defs::*, Element, Fr};

#[derive(Debug, Clone)]
// The trie implements the logic to insert values, fetch values, and create paths to said values
pub struct Trie<Storage, PolyCommit: Committer> {
    pub(crate) storage: Storage,
    committer: PolyCommit,
}

// Implementation of the trie trait that should be considered the public API for the trie
impl<S: ReadWriteHigherDb, P: Committer> TrieTrait for Trie<S, P> {
    fn insert(&mut self, kv: impl Iterator<Item = (crate::Key, crate::Value)>) {
        for (key_bytes, value_bytes) in kv {
            let ins = self.create_insert_instructions(key_bytes, value_bytes);
            self.process_instructions(ins);
        }
    }

    fn get(&self, key: crate::Key) -> Option<crate::Value> {
        self.storage.get_leaf(key)
    }

    fn root_hash(&self) -> Fr {
        // This covers the case when the tree is empty
        // If the number of stems is zero, then this branch will return zero
        let root_node = self
            .storage
            .get_branch_meta(&[])
            .expect("this should be infallible as every trie should have a root upon creation");
        root_node.hash_commitment
    }

    fn create_verkle_proof(
        &self,
        keys: impl Iterator<Item = [u8; 32]>,
    ) -> Result<crate::proof::VerkleProof, crate::errors::ProofCreationError> {
        use crate::proof::prover;
        prover::create_verkle_proof(&self.storage, keys.collect())
    }

    fn root_commitment(&self) -> Element {
        // TODO: This is needed for proofs, can we remove the root hash as the root?
        let root_node = self.storage.get_branch_meta(&[]).unwrap();
        root_node.commitment
    }
}

// To identify a branch, we only need to provide the path to the branch
pub(crate) type BranchId = Vec<u8>;

// Modifying the Trie is done by creating Instructions and
// then executing them. The trie can only be modified via the
// component that executes the instruction. However, it can be
// read by any component.
//
// The main reason to do it like this, is so that on insertion
// we can "read and prepare" all of the necessary updates, which
// works well with Rust's somewhat limited borrow checker (pre-polonius).
#[derive(Debug)]
enum Ins {
    // This Opcode modifies the leaf, stem and inner node all at once!
    // We know that whenever a leaf is modified, the stem metadata is also modified,
    // and the inner node which references the stem's metadata is also modified
    UpdateLeaf {
        // Data needed for leaf
        //
        key: [u8; 32],
        new_leaf_value: [u8; 32],
        // depth is needed for caching
        depth: u8,

        //
        // Data needed for a internal node
        //
        // internal nodes are referenced using 8 bytes
        // This is the internal node which references the stem of the leaf we just modified
        branch_id: BranchId,

        // This is the index of the stem in the inner node
        branch_child_index: u8,
        //
        // We know the key for the child node since we have the leaf
    },

    // ChainInsert is only initiated when the key being inserted shares < 31 indices with an
    // existing key
    ChainInsert {
        starting_depth: u8,
        chain_insert_path: Vec<u8>,
        parent_branch_node: BranchId,
        // This is the index of the child which currently has a stem node,
        // but wil become a branch node
        child_index: u8,
        // This is the index in the new branch node where we should store this old leaf (the previous stem)
        old_leaf_index: u8,
        // previous_stem_value : we can omit this and just fetch it when we process the instruction (maybe change this everywhere, so insert does not hold the old values)
        new_leaf_key: [u8; 32],
        new_leaf_value: [u8; 32],
        new_leaf_index: u8,
    },

    // This instruction updates the map for the internal node.
    // Specifically it specifies that the branch now points to some child.
    InternalNodeFallThrough {
        // internal nodes are referenced using 8 bytes
        branch_id: BranchId,

        // This is the index of the child that the inner node points to,
        // that has triggered the node to update its commitment
        // We track this because if the same child triggers multiple updates
        // within a child, we only need the last one.
        // Maybe we should have this as one instruction with InsertLeaf?
        branch_child_index: u8,

        child: BranchId,
        old_child_value: Option<Meta>,
        // depth is needed for caching
        depth: u8,
    },
}

impl<Storage: ReadWriteHigherDb, PolyCommit: Committer> Trie<Storage, PolyCommit> {
    // Creates a new Trie object
    pub fn new(config: Config<Storage, PolyCommit>) -> Self {
        // TODO: We should have a way to populate the cache from the persistent db here.
        // TODO: we first check if it is an new database and if it is not
        // TODO: then we pull in all nodes on level 3 or lower
        // TODO: This way, if it is not in the cache, we know it is not in the key-value db either
        let mut db = config.db;
        let pc = config.committer;

        // Add the root node to the database with the root index, if the database does not have it
        // If the root is missing, then it means it is a fresh database
        if db.root_is_missing() {
            let old_val = db.insert_branch(vec![], BranchMeta::zero(), 0);
            assert!(old_val.is_none());
        }
        Trie {
            storage: db,
            committer: pc,
        }
    }

    // Inserting a leaf in the trie is done in two steps
    // First we need to modify the corresponding parts of the
    // tree to account for the new leaf
    // Then, we need to store the leaf in the key-value database
    // and possibly the cached layer depending on the depth of the
    // leaf in the trie. The first 3/4 layers are stored in the cache
    fn create_insert_instructions(&self, key_bytes: [u8; 32], value_bytes: [u8; 32]) -> Vec<Ins> {
        let mut instructions = Vec::new();

        let path_indices = key_bytes.into_iter();

        let mut current_node_index = vec![];

        // The loop index lets us know what level in the tree we are at
        for (loop_index, path_index) in path_indices.enumerate() {
            // enumerate starts counting at 0, we want to start from 1
            let loop_index = loop_index + 1;

            // Note: For each layer that we pass, we need to re-compute the
            // inner node's commitment for that layer.

            // Lets find the child node of the current path_index
            let child = self
                .storage
                .get_branch_child(&current_node_index, path_index);

            let child = match child {
                Some(child) => child,
                None => {
                    // Case 1: The child was empty. This means that this is a new leaf, since it has no stem or branch.
                    //
                    instructions.push(Ins::UpdateLeaf {
                        key: key_bytes,
                        new_leaf_value: value_bytes,
                        depth: loop_index as u8,
                        branch_id: current_node_index,
                        branch_child_index: path_index,
                    });

                    return instructions;
                }
            };

            // Lets first figure out if it was a stem or a branch
            //
            // Case2: We have encountered an internal node
            if child.is_branch() {
                let mut node_path = current_node_index.clone();
                node_path.push(path_index);
                instructions.push(Ins::InternalNodeFallThrough {
                    branch_id: current_node_index,
                    branch_child_index: path_index,
                    child: node_path.clone(),
                    depth: loop_index as u8,
                    // TODO this does not need to be optional
                    old_child_value: child.branch().map(Meta::from),
                });
                current_node_index = node_path;

                continue;
            }

            // Since the child is neither empty nor an inner node,
            // it must be a stem.
            // We have some sub-cases to consider:
            // Case3a: The existing stem already has this key saved or it should be saved under this stem. In which case, we need to update the node
            // Case3b: The existing node does not have this key stored, however the stem shares a path with this key. In which case, we need to create branch nodes
            // to represent this.

            let (shared_path, path_diff_old, path_diff_new) =
                path_difference(child.stem().unwrap(), key_bytes[0..31].try_into().unwrap());

            // Case3a: Lets check if this key belongs under the stem
            if shared_path.len() == 31 {
                // TODO this is the only place here, where we require a get_leaf
                // TODO should we just allow users to update keys to be the same
                // TODO value and catch it maybe when we compute the delta?
                // TODO rationale is that get_leaf only gets a single 32 bytes
                // TODO and database work in pages of ~4Kb
                // The new key and the old child belong under the same stem
                let leaf_val = self.storage.get_leaf(key_bytes);
                let (old_leaf_val, leaf_already_present_in_trie) = match leaf_val {
                    Some(old_val) => {
                        // There was an old value in the stem, so this is an update
                        (old_val, true)
                    }
                    None => {
                        // There are other values under this stem, but this is the first value under this entry
                        ([0u8; 32], false)
                    }
                };

                // If the key is being updated to exactly the same value, we just return nothing
                // This is an optimization that allows one to avoid doing work,
                // when the value being inserted has not been updated
                if path_diff_old.is_none() {
                    // This means that they share all 32 bytes
                    assert!(path_diff_new.is_none());
                    // We return nothing if the value is the same
                    // and the leaf was already present.
                    // This means that if one inserts a leaf with value zero,
                    // it is still inserted in the trie
                    if (old_leaf_val == value_bytes) & leaf_already_present_in_trie {
                        return Vec::new();
                    }
                }

                instructions.push(Ins::UpdateLeaf {
                    key: key_bytes,
                    new_leaf_value: value_bytes,
                    depth: loop_index as u8,
                    branch_id: current_node_index,
                    branch_child_index: path_index,
                });

                return instructions;
            }

            // Case3b: The key shares a path with the child, but not 31,so we need to add branch nodes
            // path_difference returns all shared_paths.
            // Even shared paths before the current internal node.
            // Lets remove all of those paths
            let relative_shared_path = &shared_path[(loop_index - 1)..];

            // p_diff_a and p_diff_b tell us the first path index that these paths disagree
            // since the keys are not equal, these should have values
            let p_diff_old = path_diff_old.unwrap();
            let p_diff_new = path_diff_new.unwrap();

            instructions.push(Ins::ChainInsert {
                chain_insert_path: relative_shared_path.to_vec(),
                starting_depth: loop_index as u8,
                parent_branch_node: current_node_index,
                child_index: path_index,
                old_leaf_index: p_diff_old,
                new_leaf_key: key_bytes,
                new_leaf_value: value_bytes,
                new_leaf_index: p_diff_new,
            });

            return instructions;
        }

        instructions
    }
    // Process instructions in reverse order
    fn process_instructions(&mut self, instructions: Vec<Ins>) {
        for ins in instructions.into_iter().rev() {
            match ins {
                Ins::InternalNodeFallThrough {
                    branch_id,
                    branch_child_index,
                    child,
                    depth,
                    old_child_value,
                } => {
                    // By the time we get to this instruction, the child would have been modified by a previous instruction
                    let new_branch_meta = self.storage.get_branch_meta(&child).unwrap();
                    let new_hash_comm = new_branch_meta.hash_commitment;

                    let old_hash_comm = match old_child_value {
                        Some(old_branch_meta) => old_branch_meta.into_branch().hash_commitment,
                        None => Fr::zero(),
                    };

                    let delta = new_hash_comm - old_hash_comm;
                    let delta_comm = self
                        .committer
                        .scalar_mul(delta, branch_child_index as usize);

                    let old_parent_branch_metadata =
                        self.storage.get_branch_meta(&branch_id).unwrap();

                    let old_branch_comm = old_parent_branch_metadata.commitment;
                    let updated_comm = old_branch_comm + delta_comm;
                    let hash_updated_comm = group_to_field(&updated_comm);

                    self.storage.insert_branch(
                        branch_id,
                        BranchMeta {
                            commitment: updated_comm,
                            hash_commitment: hash_updated_comm,
                        },
                        depth,
                    );

                    // Then compute the delta between the old and new Value, we use the index to compute the delta commitment
                    // Then modify the branch commitment data
                }

                Ins::UpdateLeaf {
                    key,
                    new_leaf_value,
                    depth,
                    branch_id,
                    branch_child_index,
                } => {
                    let leaf_update = match self.update_leaf_table(key, new_leaf_value, depth) {
                        Some(leaf_update) => leaf_update,
                        None => {
                            // No value was updated, early exit
                            return;
                        }
                    };

                    let stem_update = self.update_stem_table(leaf_update, depth);

                    self.update_branch_table(stem_update, branch_id, branch_child_index, depth);
                }

                // TODO update comments on this function
                Ins::ChainInsert {
                    chain_insert_path,
                    starting_depth,
                    old_leaf_index,
                    parent_branch_node,
                    child_index,
                    new_leaf_key,
                    new_leaf_value,
                    new_leaf_index,
                } => {
                    assert!(!chain_insert_path.is_empty());

                    //0. Compute the path for each inner node
                    let mut inner_node_paths =
                        expand_path(&parent_branch_node, &chain_insert_path).rev();
                    //
                    // 1. First check that before modification, the node which starts the chain is a stem
                    // we will later replace it later with an inner node.
                    // If it is not a stem, then this is a bug, as chain insert should not have been called.

                    let old_child = self
                        .storage
                        .get_branch_child(&parent_branch_node, child_index)
                        .unwrap();
                    let old_stem_child = old_child.stem().unwrap();

                    //2a. Now lets create the inner node which will hold the two stems
                    // Note; it's position will be at the bottom of the chain.
                    let bottom_inner_node_path = inner_node_paths.next().unwrap();
                    let bottom_inode_depth = bottom_inner_node_path.len() as u8;
                    self.storage.insert_branch(
                        bottom_inner_node_path.clone(),
                        BranchMeta::zero(),
                        bottom_inode_depth,
                    );

                    //2b We then attach the two stems as children in the correct positions
                    // The new leaf has not been saved yet, so we need to put it in the leaf and stem table first
                    let leaf_update = self
                        .update_leaf_table(new_leaf_key, new_leaf_value, bottom_inode_depth)
                        .unwrap();
                    let new_stem_update = self.update_stem_table(leaf_update, bottom_inode_depth);
                    self.update_branch_table(
                        new_stem_update,
                        bottom_inner_node_path.clone(),
                        new_leaf_index,
                        bottom_inode_depth,
                    );

                    // Add second stem to branch, since it is already in the database
                    // We just need to state that this branch node points to it and
                    // update this nodes commitment and commitment value
                    let stem_meta_data = self.storage.get_stem_meta(old_stem_child).unwrap();
                    let old_stem_updated = StemUpdated {
                        old_val: None,
                        new_val: stem_meta_data.hash_stem_commitment,
                        stem: old_stem_child,
                    };
                    let bottom_branch_root = self.update_branch_table(
                        old_stem_updated,
                        bottom_inner_node_path.clone(),
                        old_leaf_index,
                        bottom_inode_depth,
                    );

                    //3) We now have the root for the branch node which holds the two stem nodes.
                    // We now need to create a chain of branch nodes up to the parent, updating their commitments
                    // along the way
                    // The inner node at the depth below, will become the child for the node at the depth above
                    //
                    //
                    // Note: We could now use a single for loop, however, we can optimise the next section by observing that:
                    // All nodes except the first node will have an old_value of 0 (Since they are being created now)
                    // This allows us to skip fetching their values from the database. We will just need to manually update the
                    // First node which had an old value equal to the stems value
                    let shortened_path = inner_node_paths;

                    // We now want to start from the bottom and update each inner node's commitment and hash

                    let mut inner_node_below_val = bottom_branch_root;

                    for (child_path, parent_branch_node) in
                        chain_insert_path.iter().rev().zip(shortened_path)
                    {
                        let depth = parent_branch_node.len() as u8;

                        let delta = inner_node_below_val; // Remember the old value will be zero, since we just created it.

                        let updated_comm = self.committer.scalar_mul(delta, *child_path as usize);
                        let branch_root = group_to_field(&updated_comm);

                        self.storage.insert_branch(
                            parent_branch_node.clone(),
                            BranchMeta {
                                commitment: updated_comm,
                                hash_commitment: branch_root,
                            },
                            depth,
                        );

                        inner_node_below_val = branch_root;
                    }

                    // 4)  We now only need to modify the branch node which was previously holding the stem
                    // This is the parent branch node

                    let old_stem_value = stem_meta_data.hash_stem_commitment;
                    let new_inner_node_value = inner_node_below_val;
                    let delta = new_inner_node_value - old_stem_value;

                    let top_parent = self.storage.get_branch_meta(&parent_branch_node).unwrap();

                    let updated_top_comm = top_parent.commitment
                        + self.committer.scalar_mul(delta, child_index as usize);
                    let top_parent_root = group_to_field(&updated_top_comm);

                    self.storage.insert_branch(
                        parent_branch_node.clone(),
                        BranchMeta {
                            commitment: updated_top_comm,
                            hash_commitment: top_parent_root,
                        },
                        starting_depth,
                    );
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct LeafUpdated {
    old_val: Option<Vec<u8>>,
    new_value: Vec<u8>,
    key: Vec<u8>,
}
#[derive(Debug)]
pub(crate) struct StemUpdated {
    old_val: Option<Fr>,
    new_val: Fr,
    stem: [u8; 31],
}

impl<Storage: ReadWriteHigherDb, PolyCommit: Committer> Trie<Storage, PolyCommit> {
    // Store the leaf, we return data on the old leaf, so that we can do the delta optimization
    //
    // If a leaf was not updated, this function will return None
    // else Some will be returned with the old value
    fn update_leaf_table(
        &mut self,
        key: [u8; 32],
        value: [u8; 32],
        depth: u8,
    ) -> Option<LeafUpdated> {
        let old_val = match self.storage.insert_leaf(key, value, depth) {
            Some(vec) => {
                // Check if they have just inserted the previous value
                // if so, we early exit and return None
                if vec == value {
                    return None;
                }
                Some(vec)
            }
            None => None,
        };

        Some(LeafUpdated {
            old_val,
            new_value: value.to_vec(),
            key: key.to_vec(),
        })

        // Storing a leaf means we need to change the stem table too
    }

    fn update_stem_table(&mut self, update_leaf: LeafUpdated, depth: u8) -> StemUpdated {
        // If a leaf is updated, then we need to update the stem.
        // In particular, we need to update the commitment for that stem and the stem value
        //
        // There are two cases here:
        // - old_value is None. So there was a fresh update
        // - old_value as Some and we have modified a value
        // We can treat both cases as one because to compute the delta we do (new_value - old_value)
        // When the value has not changed, it's (new_value - 0)
        //

        // Split values into low_16 and high_16
        let new_value_low_16 = update_leaf.new_value[0..16].to_vec();
        let new_value_high_16 = update_leaf.new_value[16..32].to_vec();

        let (old_value_low_16, old_value_high_16) = match update_leaf.old_val {
            Some(val) => (
                Fr::from_le_bytes_mod_order(&val[0..16]) + TWO_POW_128,
                Fr::from_le_bytes_mod_order(&val[16..32]),
            ),
            None => (Fr::zero(), Fr::zero()),
        };

        // We need to compute two deltas
        let delta_low =
            Fr::from_le_bytes_mod_order(&new_value_low_16) + TWO_POW_128 - old_value_low_16;
        let delta_high = Fr::from_le_bytes_mod_order(&new_value_high_16) - old_value_high_16;

        // We need to compute which group elements in the srs are being used
        // We know that the first 128 values are mapped to the first 256 group elements
        // and the last 128 values are mapped to the second 256 group elements
        //
        // So given our position is `0`, the values would map to (0,1)
        // Given our position is `1` the values would map to (2,3)
        // Given our position is `2`, the values would map to (4,5)
        // Given our position is `n`. the values would map to (2n, 2n+1) where n < 128 ie 0 <= n <= 127
        //
        // For n >= 128, we mod 128 n then apply the same algorithm as above.
        // Given our position is `255`, 255 mod 128 = 127. The values would be (254,255)
        // Given our position is `128`, 128 mod 128 = 0. The values would be (0,1)

        let position = update_leaf.key[31];
        let pos_mod_128 = position % 128;

        let low_index = 2 * pos_mod_128 as usize;
        let high_index = low_index + 1;

        let generator_low = self.committer.scalar_mul(delta_low, low_index);
        let generator_high = self.committer.scalar_mul(delta_high, high_index);

        let stem: [u8; 31] = update_leaf.key[0..31].try_into().unwrap();

        let (c_1, old_hash_c1, c_2, old_hash_c2, stem_comm, old_hash_stem_comm) =
            match self.storage.get_stem_meta(stem) {
                Some(comm_val) => (
                    comm_val.c_1,
                    comm_val.hash_c1,
                    comm_val.c_2,
                    comm_val.hash_c2,
                    comm_val.stem_commitment,
                    Some(comm_val.hash_stem_commitment),
                ),
                None => {
                    // This is the first leaf for the stem, so the C1, C2 commitments will be zero
                    // The stem commitment will be 1 * G_1 + stem * G_2

                    let stem_comm = CRS[0]
                        + self
                            .committer
                            .scalar_mul(Fr::from_le_bytes_mod_order(&stem), 1);
                    (
                        Element::zero(),
                        group_to_field(&Element::zero()),
                        Element::zero(),
                        group_to_field(&Element::zero()),
                        stem_comm,
                        None,
                    )
                }
            };

        // Compute the delta for the stem commitment
        let (updated_c_1, new_hash_c1, updated_c_2, new_hash_c2, updated_stem_comm) =
            if position < 128 {
                // update c_1
                let updated_c_1 = c_1 + generator_low + generator_high;
                let new_hash_c1 = group_to_field(&updated_c_1);

                let c_1_delta = new_hash_c1 - old_hash_c1;
                let c_1_point = self.committer.scalar_mul(c_1_delta, 2);

                let updated_stem_comm = stem_comm + c_1_point;

                (
                    updated_c_1,
                    new_hash_c1,
                    c_2,
                    old_hash_c2,
                    updated_stem_comm,
                )
            } else {
                // update c_2
                let updated_c_2 = c_2 + generator_low + generator_high;
                let new_hash_c2 = group_to_field(&updated_c_2);

                let c_2_delta = new_hash_c2 - old_hash_c2;
                let c_2_point = self.committer.scalar_mul(c_2_delta, 3);

                let updated_stem_comm = stem_comm + c_2_point;
                (
                    c_1,
                    old_hash_c1,
                    updated_c_2,
                    new_hash_c2,
                    updated_stem_comm,
                )
            };

        let updated_hash_stem_comm = group_to_field(&updated_stem_comm);

        self.storage.insert_stem(
            stem,
            StemMeta {
                c_1: updated_c_1,
                hash_c1: new_hash_c1,
                c_2: updated_c_2,
                hash_c2: new_hash_c2,
                stem_commitment: updated_stem_comm,
                hash_stem_commitment: updated_hash_stem_comm,
            },
            depth,
        );

        StemUpdated {
            old_val: old_hash_stem_comm,
            new_val: updated_hash_stem_comm,
            stem,
        }
    }

    fn update_branch_table(
        &mut self,
        stem_update: StemUpdated,
        branch_id: BranchId,
        branch_index: u8,
        depth: u8,
    ) -> Fr {
        // To update the branch, we need to compute the delta and figure out the
        // generator we want to use.
        //
        // If the hash of the stem commitment is None,
        // then this means that this is the first time we are inserting this stem.
        // We return the hash as zero because if the stem did not exist, the branch node
        // does not commit to it.
        let old_stem_hash = stem_update.old_val.unwrap_or_else(Fr::zero);
        let new_stem_hash = stem_update.new_val;
        let delta = new_stem_hash - old_stem_hash;

        let old_branch_comm = self.storage.get_branch_meta(&branch_id).unwrap().commitment;
        let delta_comm = self.committer.scalar_mul(delta, branch_index as usize);
        let updated_branch_comm = old_branch_comm + delta_comm;
        let hash_updated_branch_comm = group_to_field(&updated_branch_comm);

        // Update the branch metadata

        self.storage.insert_branch(
            branch_id.clone(),
            BranchMeta {
                commitment: updated_branch_comm,
                hash_commitment: hash_updated_branch_comm,
            },
            depth,
        );
        let mut branch_child_id = branch_id;
        branch_child_id.push(branch_index);
        self.storage
            .add_stem_as_branch_child(branch_child_id, stem_update.stem, depth);

        hash_updated_branch_comm
    }
}

impl<Storage: ReadWriteHigherDb + Flush, PolyCommit: Committer> Trie<Storage, PolyCommit> {
    // TODO: maybe make this private, and automatically flush
    // TODO after each insert. This will promote users to use insert()
    // TODO If the amount of items in insert is too much, we will need to chop it up
    // TODO and flush multiple times
    pub fn flush_database(&mut self) {
        self.storage.flush()
    }
}
// Returns a list of all of the path indices where the two stems
// are the same and the next path index where they both differ for each
// stem.
// TODO: Clean up
fn path_difference(key_a: [u8; 31], key_b: [u8; 31]) -> (Vec<u8>, Option<u8>, Option<u8>) {
    const AVERAGE_NUMBER_OF_SHARED_INDICES: usize = 3;

    let mut same_path_indices = Vec::with_capacity(AVERAGE_NUMBER_OF_SHARED_INDICES);

    for (p_a, p_b) in key_a.into_iter().zip(key_b.into_iter()) {
        if p_a != p_b {
            return (same_path_indices, Some(p_a), Some(p_b));
        }
        same_path_indices.push(p_a)
    }

    (same_path_indices, None, None)
}

// TODO: Is this hurting performance? If so can we rewrite it to be more efficient?
// TODO Eagerly, we can use SmallVec32
/// Expand a base path by the sequential children of relative path.
///
/// # Example
///
/// Given a base path [0, 1, 2] and relative path [5, 6, 7] the base path
/// will be expanded to 3 paths:
/// [0, 1, 2, 5]
/// [0, 1, 2, 5, 6]
/// [0, 1, 2, 5, 6, 7]
fn expand_path<'a>(
    base: &'a [u8],
    relative: &'a [u8],
) -> impl DoubleEndedIterator<Item = Vec<u8>> + 'a {
    assert!(!relative.is_empty());

    (0..relative.len()).map(|idx| Vec::from_iter(base.iter().chain(&relative[0..=idx]).cloned()))
}

#[cfg(test)]
mod tests {

    use crate::constants::{CRS, TWO_POW_128};
    use crate::database::memory_db::MemoryDb;
    use crate::database::ReadOnlyHigherDb;
    use crate::trie::Trie;
    use crate::TrieTrait;
    use crate::{group_to_field, DefaultConfig};
    use banderwagon::{trait_defs::*, Element, Fr};
    use std::ops::Mul;

    #[test]
    // Inserting where the key and value are all zeros
    // The zeroes cancel out a lot of components, so this is a general fuzz test
    // and hopefully the easiest to pass
    fn insert_key0value0() {
        let db = MemoryDb::new();

        let mut trie = Trie::new(DefaultConfig::new(db));

        let key = [0u8; 32];
        let stem: [u8; 31] = key[0..31].try_into().unwrap();

        let ins = trie.create_insert_instructions(key, key);
        trie.process_instructions(ins);

        // Value at that leaf should be zero
        assert_eq!(trie.storage.get_leaf(key).unwrap(), key);

        // There should be one stem child at index 0 which should hold the value of 0
        let mut stem_children = trie.storage.get_stem_children(stem);
        assert_eq!(stem_children.len(), 1);

        let (stem_index, leaf_value) = stem_children.pop().unwrap();
        assert_eq!(stem_index, 0);
        assert_eq!(leaf_value, key);

        // Checking correctness of the stem commitments and hashes
        let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

        // C1 = (value_low + 2^128) * G0 + value_high * G1
        let value_low = Fr::from_le_bytes_mod_order(&[0u8; 16]) + TWO_POW_128;

        let c_1 = CRS[0].mul(value_low);
        assert_eq!(c_1, stem_meta.c_1);
        assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

        // c_2 is not being used so it is the identity point
        let c_2 = Element::zero();
        assert_eq!(stem_meta.c_2, c_2);
        assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

        // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
        let stem_comm_0 = CRS[0];
        let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
        let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
        let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
        let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
        assert_eq!(stem_meta.stem_commitment, stem_comm);

        // Root is computed as the hash of the stem_commitment * G_0
        // G_0 since the stem is situated at the first index in the child
        let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
        let root_comm = CRS[0].mul(hash_stem_comm);
        let root = group_to_field(&root_comm);

        assert_eq!(root, trie.root_hash())
    }

    #[test]
    // Test when the key is 1 to 32
    fn insert_key1_val1() {
        use crate::database::ReadOnlyHigherDb;

        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let stem: [u8; 31] = key[0..31].try_into().unwrap();

        let ins = trie.create_insert_instructions(key, key);
        trie.process_instructions(ins);

        // Value at that leaf should be [1,32]
        assert_eq!(trie.storage.get_leaf(key).unwrap(), key);

        // There should be one stem child at index 32 which should hold the value of [1,32]
        let mut stem_children = trie.storage.get_stem_children(stem);
        assert_eq!(stem_children.len(), 1);

        let (stem_index, leaf_value) = stem_children.pop().unwrap();
        assert_eq!(stem_index, 32);
        assert_eq!(leaf_value, key);

        // Checking correctness of the stem commitments and hashes
        let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

        // C1 = (value_low + 2^128) * G_64 + value_high * G_65
        let value_low =
            Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                + TWO_POW_128;
        let value_high = Fr::from_le_bytes_mod_order(&[
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);

        let c_1 = CRS[64].mul(value_low) + CRS[65].mul(value_high);

        assert_eq!(c_1, stem_meta.c_1);
        assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

        // c_2 is not being used so it is the identity point
        let c_2 = Element::zero();
        assert_eq!(stem_meta.c_2, c_2);
        assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

        // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
        let stem_comm_0 = CRS[0];
        let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
        let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
        let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
        let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
        assert_eq!(stem_meta.stem_commitment, stem_comm);

        // Root is computed as the hash of the stem_commitment * G_1
        // G_1 since the stem is situated at the second index in the child (key starts with 1)
        let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
        let root_comm = CRS[1].mul(hash_stem_comm);
        let root = group_to_field(&root_comm);

        assert_eq!(root, trie.root_hash())
    }

    #[test]
    // Test when we insert two leaves under the same stem
    fn insert_same_stem_two_leaves() {
        use crate::database::ReadOnlyHigherDb;
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let stem_a: [u8; 31] = key_a[0..31].try_into().unwrap();
        let key_b = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 128,
        ];
        let stem_b: [u8; 31] = key_b[0..31].try_into().unwrap();
        assert_eq!(stem_a, stem_b);
        let stem = stem_a;

        let ins = trie.create_insert_instructions(key_a, key_a);
        trie.process_instructions(ins);
        let ins = trie.create_insert_instructions(key_b, key_b);
        trie.process_instructions(ins);

        // Fetch both leaves to ensure they have been inserted
        assert_eq!(trie.storage.get_leaf(key_a).unwrap(), key_a);
        assert_eq!(trie.storage.get_leaf(key_b).unwrap(), key_b);

        // There should be two stem children, one at index 32 and the other at index 128
        let stem_children = trie.storage.get_stem_children(stem);
        assert_eq!(stem_children.len(), 2);

        for (stem_index, leaf_value) in stem_children {
            if stem_index == 32 {
                assert_eq!(leaf_value, key_a);
            } else if stem_index == 128 {
                assert_eq!(leaf_value, key_b);
            } else {
                panic!("unexpected stem index {}", stem_index)
            }
        }

        // Checking correctness of the stem commitments and hashes
        let stem_meta = trie.storage.get_stem_meta(stem).unwrap();

        // C1 = (value_low + 2^128) * G_64 + value_high * G_65
        let value_low =
            Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                + TWO_POW_128;
        let value_high = Fr::from_le_bytes_mod_order(&[
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ]);

        let c_1 = CRS[64].mul(value_low) + CRS[65].mul(value_high);

        assert_eq!(c_1, stem_meta.c_1);
        assert_eq!(group_to_field(&c_1), stem_meta.hash_c1);

        // C2 = (value_low + 2^128) * G_0 + value_high * G_1
        let value_low =
            Fr::from_le_bytes_mod_order(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                + TWO_POW_128;
        let value_high = Fr::from_le_bytes_mod_order(&[
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 128,
        ]);

        let c_2 = CRS[0].mul(value_low) + CRS[1].mul(value_high);

        assert_eq!(stem_meta.c_2, c_2);
        assert_eq!(group_to_field(&c_2), stem_meta.hash_c2);

        // The stem commitment is: 1 * G_0 + stem * G_1 + group_to_field(C1) * G_2 + group_to_field(C2) * G_3
        let stem_comm_0 = CRS[0];
        let stem_comm_1 = CRS[1].mul(Fr::from_le_bytes_mod_order(&stem));
        let stem_comm_2 = CRS[2].mul(group_to_field(&c_1));
        let stem_comm_3 = CRS[3].mul(group_to_field(&c_2));
        let stem_comm = stem_comm_0 + stem_comm_1 + stem_comm_2 + stem_comm_3;
        assert_eq!(stem_meta.stem_commitment, stem_comm);

        // Root is computed as the hash of the stem_commitment * G_1
        let hash_stem_comm = group_to_field(&stem_meta.stem_commitment);
        let root_comm = CRS[1].mul(hash_stem_comm);
        let root = group_to_field(&root_comm);

        assert_eq!(root, trie.root_hash())
    }
    #[test]
    // Test where we insert two leaves, which correspond to two stems
    // TODO: Is this manual test needed, or can we add it as a consistency test?
    fn insert_key1_val1_key2_val2() {
        use crate::database::ReadOnlyHigherDb;

        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [0u8; 32];
        let stem_a: [u8; 31] = key_a[0..31].try_into().unwrap();
        let key_b = [1u8; 32];
        let stem_b: [u8; 31] = key_b[0..31].try_into().unwrap();

        let ins = trie.create_insert_instructions(key_a, key_a);
        trie.process_instructions(ins);
        let ins = trie.create_insert_instructions(key_b, key_b);
        trie.process_instructions(ins);

        let a_meta = trie.storage.get_stem_meta(stem_a).unwrap();
        let b_meta = trie.storage.get_stem_meta(stem_b).unwrap();

        let root_comm =
            CRS[0].mul(a_meta.hash_stem_commitment) + CRS[1].mul(b_meta.hash_stem_commitment);

        let expected_root = group_to_field(&root_comm);
        let got_root = trie.root_hash();
        assert_eq!(expected_root, got_root);
    }

    #[test]
    // Test where keys create the longest path
    fn insert_longest_path() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        key_b[30] = 1;

        trie.insert_single(key_a, key_a);
        trie.insert_single(key_b, key_b);

        let mut byts = [0u8; 32];
        trie.root_hash()
            .serialize_compressed(&mut byts[..])
            .unwrap();
        assert_eq!(
            hex::encode(byts),
            "fe2e17833b90719eddcad493c352ccd491730643ecee39060c7c1fff5fcc621a"
        );
    }
    #[test]
    // Test where keys create the longest path and the new key traverses that path
    fn insert_and_traverse_longest_path() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [0u8; 32];
        let ins = trie.create_insert_instructions(key_a, key_a);
        trie.process_instructions(ins);

        let mut key_b = [0u8; 32];
        key_b[30] = 1;

        let ins = trie.create_insert_instructions(key_b, key_b);
        trie.process_instructions(ins);
        // Since those inner nodes were already created with key_b
        // The insertion algorithm will traverse these inner nodes
        // and later signal an update is needed, once it is inserted
        let mut key_c = [0u8; 32];
        key_c[29] = 1;

        let ins = trie.create_insert_instructions(key_c, key_c);
        trie.process_instructions(ins);

        let mut byts = [0u8; 32];
        trie.root_hash()
            .serialize_compressed(&mut byts[..])
            .unwrap();
        assert_eq!(
            hex::encode(byts),
            "74ff8821eca20188de49340124f249dac94404efdb3838bb6b4d298e483cc20e"
        );
    }

    #[test]
    fn empty_trie() {
        // An empty tree should return zero as the root

        let db = MemoryDb::new();
        let trie = Trie::new(DefaultConfig::new(db));

        assert_eq!(trie.root_hash(), Fr::zero())
    }

    #[test]
    fn simple_insert() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        trie.insert_single(key_a, key_a);

        let mut byts = [0u8; 32];
        let root = trie.root_hash();
        root.serialize_compressed(&mut byts[..]).unwrap();

        assert_eq!(
            "029b6c4c8af9001f0ac76472766c6579f41eec84a73898da06eb97ebdab80a09",
            hex::encode(byts)
        )
    }

    #[test]
    fn simple_update() {
        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let key_a = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        trie.insert_single(key_a, [0u8; 32]);
        trie.insert_single(key_a, key_a);

        let mut byts = [0u8; 32];
        let root = trie.root_hash();
        root.serialize_compressed(&mut byts[..]).unwrap();

        assert_eq!(
            "029b6c4c8af9001f0ac76472766c6579f41eec84a73898da06eb97ebdab80a09",
            hex::encode(byts)
        )
    }

    #[test]
    fn simple_rel_paths() {
        let parent = vec![0, 1, 2];
        let rel = vec![5, 6, 7];
        let expected = vec![
            vec![0, 1, 2, 5],
            vec![0, 1, 2, 5, 6],
            vec![0, 1, 2, 5, 6, 7],
        ];
        let result = super::expand_path(&parent, &rel).collect::<Vec<_>>();

        assert_eq!(result.len(), expected.len());
        for (got, expected) in result.into_iter().zip(expected) {
            assert_eq!(got, expected)
        }
    }

    #[test]
    fn insert_get() {
        use tempfile::tempdir;
        let _temp_dir = tempdir().unwrap();

        let db = MemoryDb::new();
        let mut trie = Trie::new(DefaultConfig::new(db));

        let tree_key_version: [u8; 32] = [
            121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197,
            120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 0,
        ];

        let tree_key_balance: [u8; 32] = [
            121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197,
            120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 1,
        ];

        let tree_key_nonce: [u8; 32] = [
            121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197,
            120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 2,
        ];

        let tree_key_code_keccak: [u8; 32] = [
            121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197,
            120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 3,
        ];

        let tree_key_code_size: [u8; 32] = [
            121, 85, 7, 198, 131, 230, 143, 90, 165, 129, 173, 81, 186, 89, 19, 191, 13, 107, 197,
            120, 243, 229, 224, 183, 72, 25, 6, 8, 210, 159, 31, 4,
        ];

        let empty_code_hash_value: [u8; 32] = [
            197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182,
            83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
        ];

        let value_0: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let value_2: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ];

        trie.insert_single(tree_key_version, value_0);
        trie.insert_single(tree_key_balance, value_2);
        trie.insert_single(tree_key_nonce, value_0);
        trie.insert_single(tree_key_code_keccak, empty_code_hash_value);
        trie.insert_single(tree_key_code_size, value_0);

        let _val = trie.get(tree_key_version).unwrap();
        let _val = trie.get(tree_key_balance).unwrap();
        let _val = trie.get(tree_key_nonce).unwrap();
        let _val = trie.get(tree_key_code_keccak).unwrap();
        let _val = trie.get(tree_key_code_size).unwrap();
    }
}
