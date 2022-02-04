use std::fs::File;
use crate::committer::{precompute::PrecomputeLagrange, test::TestCommitter};
use crate::constants::CRS;

use ark_ec::ProjectiveCurve;
use ark_serialize::CanonicalSerialize;

/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}

pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let committer_bin_path = "precomputed_points.bin";
        if !std::path::Path::new(committer_bin_path).exists() {
            let mut file = File::create(committer_bin_path).unwrap();
            let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
            let committer = PrecomputeLagrange::precompute(&g_aff);
            committer.write(&mut file).unwrap();
            Config { db, committer }
        } else {
            let mut file = File::open(committer_bin_path).unwrap();
            let committer = PrecomputeLagrange::read(&mut file).unwrap();
            Config { db, committer }
        }
    }
}

pub(crate) type TestConfig<Storage> = Config<Storage, TestCommitter>;
impl<Storage> TestConfig<Storage> {
    pub(crate) fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
