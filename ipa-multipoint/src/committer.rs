use banderwagon::{Element, Fr};

// This is the functionality that commits to the branch nodes and computes the delta optimisation
// For consistency with the Pcs, ensure that this component uses the same CRS as the Pcs
// This is being done in the config file automatically
pub trait Committer {
    // Commit to a lagrange polynomial, evaluations.len() must equal the size of the SRS at the moment
    fn commit_lagrange(&self, evaluations: &[Fr; 256]) -> Element;

    // compute value * G for a specific generator in the SRS
    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element;

    // TODO: For large vectors, we could probably do this in parallel
    fn commit_sparse(&self, val_indices: Vec<(Fr, usize)>) -> Element {
        let mut result = Element::zero();

        for (value, lagrange_index) in val_indices {
            result += self.scalar_mul(value, lagrange_index)
        }

        result
    }
}

use crate::crs::CRS;

#[derive(Debug, Clone)]
pub struct DefaultCommitter(pub CRS);
impl Committer for DefaultCommitter {
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
