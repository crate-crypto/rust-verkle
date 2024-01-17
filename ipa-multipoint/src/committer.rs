use banderwagon::{msm::MSMPrecompWnaf, Element, Fr};

// This is the functionality that commits to the branch nodes and computes the delta optimization
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

pub struct DefaultCommitter {
    precomp: MSMPrecompWnaf,
}

impl DefaultCommitter {
    pub fn new(element: Vec<Element>) -> Self {
        let precomp = MSMPrecompWnaf::new(&element, 12);

        Self { precomp }
    }
}

impl Committer for DefaultCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr; 256]) -> Element {
        self.precomp.mul_par(evaluations)
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        self.precomp.mul_index(value, lagrange_index)
    }
}
