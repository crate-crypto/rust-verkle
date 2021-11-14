use crate::{committer::Committer, constants::CRS};
use ark_ec::ProjectiveCurve;
use ark_ff::PrimeField;
use ark_ff::Zero;
use bandersnatch::{EdwardsProjective, Fr};
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
