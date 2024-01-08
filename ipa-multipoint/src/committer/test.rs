use crate::{committer::Committer, crs::CRS};
use banderwagon::{Element, Fr};

// A Basic Commit struct to be used in tests.
// In production, we will use the Precomputed points
#[derive(Debug, Clone)]
pub struct TestCommitter(pub CRS);
impl Committer for TestCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr; 256]) -> Element {
        let mut res = Element::zero();
        for (val, point) in evaluations.iter().zip(self.0.G.iter()) {
            res += point * val;
        }
        res
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        self.0.G[lagrange_index] * value
    }
}
