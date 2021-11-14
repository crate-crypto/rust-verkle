use crate::{constants::CRS, precompute::PrecomputeLagrange, Committer};

use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, Zero};
use bandersnatch::{EdwardsProjective, Fr};
/// Generic configuration file to initialise a verkle trie struct
#[derive(Debug, Clone)]
pub struct Config<Storage, PolyCommit> {
    pub db: Storage,
    pub committer: PolyCommit,
}
pub(crate) type TestConfig<Storage> = Config<Storage, TestCommitter>;
pub type VerkleConfig<Storage> = Config<Storage, PrecomputeLagrange>;

impl<Storage> TestConfig<Storage> {
    pub(crate) fn new(db: Storage) -> Self {
        let committer = TestCommitter;
        Config { db, committer }
    }
}
impl<Storage> VerkleConfig<Storage> {
    pub fn new(db: Storage) -> Self {
        let g_aff: Vec<_> = CRS.G.iter().map(|point| point.into_affine()).collect();
        let committer = PrecomputeLagrange::precompute(&g_aff);
        Config { db, committer }
    }
}

// A Basic Commit struct to be used in tests.
// In production, we will use the Precomputed points
pub struct TestCommitter;
impl Committer for TestCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        let mut res = EdwardsProjective::zero();
        for (val, point) in evaluations.iter().zip(CRS.G.iter()) {
            res += point.mul(val.into_repr())
        }
        res
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        CRS[lagrange_index].mul(value.into_repr())
    }
}

impl Default for TestCommitter {
    fn default() -> Self {
        TestCommitter
    }
}
