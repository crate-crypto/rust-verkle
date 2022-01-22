use crate::committer::{precompute::PrecomputeLagrange, test::TestCommitter};
use crate::constants::CRS;

/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}

pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let committer = PrecomputeLagrange::precompute(&CRS.G);
        Config { db, committer }
    }
}

pub(crate) type TestConfig<Storage> = Config<Storage, TestCommitter>;
impl<Storage> TestConfig<Storage> {
    pub(crate) fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
