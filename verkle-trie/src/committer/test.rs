use crate::{committer::Committer, constants::CRS};
use banderwagon::{Element, Fr};

// A Basic Commit struct to be used in tests.
// In production, we will use the Precomputed points
#[derive(Debug, Clone, Copy)]
pub struct TestCommitter;
impl Committer for TestCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> Element {
        let mut res = Element::zero();
        for (val, point) in evaluations.iter().zip(CRS.G.iter()) {
            res += point * val;
        }
        res
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        CRS[lagrange_index] * value
    }
}

impl Default for TestCommitter {
    fn default() -> Self {
        TestCommitter
    }
}
