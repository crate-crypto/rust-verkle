pub mod default;
mod generic;
pub mod memory_db;
pub mod meta;

pub use default::VerkleDb;
pub use meta::{BranchChild, BranchMeta, Meta, StemMeta};
pub trait ReadWriteHigherDb: ReadOnlyHigherDb + WriteOnlyHigherDb {}
impl<T: ReadOnlyHigherDb + WriteOnlyHigherDb> ReadWriteHigherDb for T {}
// There are two ways to use your database with this trie implementation:
// 1) Implement the traits in this file; Flush, WriteOnlyHigherDb, ReadOnlyHigherDb
//
// 2) Implement lower level traits in verkle-db, then use VerkleDb. The traits in this file will
// be automatically implemented using the traits in verkle-db

// TODO we need a populate cache method that populates the cache from storage
// TODO Think of a better name than ReadOnlyHigherDb, WriteOnlyHigherDb
// Allows a component to flush their memory database to disk
// This is a no-op for components which are just memory databases
pub trait Flush {
    fn flush(&mut self);
}

// WriteOnly trait which will be implemented by BatchWriters and memory databases
// This will not be implemented by disk storage directly, they just need to flush
// the BatchWriter
// TODO: we could auto implement `update` methods which assert that
// TODO there was a previous value
// TODO they would just wrap the insert methods and check for `None`
pub trait WriteOnlyHigherDb {
    fn insert_leaf(&mut self, key: [u8; 32], value: [u8; 32], _depth: u8) -> Option<Vec<u8>>;

    fn insert_stem(&mut self, key: [u8; 31], meta: StemMeta, _depth: u8) -> Option<StemMeta>;

    // TODO we can probably combine `add_stem_as_branch_child` and `insert_branch`
    // TODO into a single method called `insert_branch_child`
    fn add_stem_as_branch_child(
        &mut self,
        branch_child_id: Vec<u8>,
        stem_id: [u8; 31],
        _depth: u8,
    ) -> Option<BranchChild>;

    // TODO maybe we can return BranchChild, as the previous data could have been a stem or branch_meta
    // TODO then we can leave it upto the caller on how to deal with it
    fn insert_branch(&mut self, key: Vec<u8>, meta: BranchMeta, _depth: u8) -> Option<BranchMeta>;
}

// Notice that these take self, which effectively forces the implementer
// to implement these for self or use a struct which is Copyable
// One should aim for the former
pub trait ReadOnlyHigherDb {
    fn get_stem_meta(&self, stem_key: [u8; 31]) -> Option<StemMeta>;

    fn get_branch_meta(&self, key: &[u8]) -> Option<BranchMeta>;

    // TODO add a range query for the default database in verkle_db
    fn get_branch_children(&self, branch_id: &[u8]) -> Vec<(u8, BranchChild)>;
    fn get_branch_child(&self, branch_id: &[u8], index: u8) -> Option<BranchChild>;

    // TODO add a range query for the default database in verkle_db
    fn get_stem_children(&self, stem_key: [u8; 31]) -> Vec<(u8, [u8; 32])>;
    fn get_leaf(&self, key: [u8; 32]) -> Option<[u8; 32]>;

    fn root_is_missing(&self) -> bool {
        let root = vec![];
        self.get_branch_meta(&root).is_none()
    }
}
