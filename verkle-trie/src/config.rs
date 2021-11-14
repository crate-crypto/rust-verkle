use crate::committer::{precompute::PrecomputeLagrange, test::TestCommitter, Committer};
use crate::constants::CRS;

use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, Zero};
use bandersnatch::{EdwardsProjective, Fr};

/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}

pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
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
