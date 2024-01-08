use crate::constants::new_crs;
use ipa_multipoint::committer::test::TestCommitter;

// TODO: We may not need to have this be generic, now that we have gotten rid of
// TODO the config with precomputed points

/// Generic configuration file to initialize a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}

pub type TestConfig<Storage> = Config<Storage, TestCommitter>;
impl<Storage> TestConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let committer = TestCommitter(new_crs());
        Config { db, committer }
    }
}

pub type VerkleConfig<Storage> = TestConfig<Storage>;
