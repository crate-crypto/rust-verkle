use banderwagon::{msm::MSMPrecompWnaf, msm_windowed_sign::MSMPrecompWindowSigned, Element, Fr};

// This is the functionality that commits to the branch nodes and computes the delta optimization
// For consistency with the Pcs, ensure that this component uses the same CRS as the Pcs
// This is being done in the config file automatically
pub trait Committer {
    // Commit to a lagrange polynomial, evaluations.len() must equal the size of the SRS at the moment
    fn commit_lagrange(&self, evaluations: &[Fr]) -> Element;

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

#[derive(Clone, Debug)]
pub struct DefaultCommitter {
    precomp_first_five: MSMPrecompWindowSigned,
    precomp: MSMPrecompWnaf,
}

impl DefaultCommitter {
    pub fn new(points: &[Element]) -> Self {
        // Take the first five elements and use a more aggressive optimization strategy
        // since they are used for computing storage keys.

        let (points_five, _) = points.split_at(5);
        let precomp_first_five = MSMPrecompWindowSigned::new(points_five, 16);
        let precomp = MSMPrecompWnaf::new(points, 12);

        Self {
            precomp,
            precomp_first_five,
        }
    }
}

impl Committer for DefaultCommitter {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> Element {
        if evaluations.len() <= 5 {
            return self.precomp_first_five.mul(&evaluations);
        }
        // Preliminary benchmarks indicate that the parallel version is faster
        // for vectors of length 64 or more
        if evaluations.len() >= 64 {
            self.precomp.mul_par(evaluations)
        } else {
            self.precomp.mul(evaluations)
        }
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        if lagrange_index < 5 {
            let mut arr = [Fr::from(0u64); 5];
            arr[lagrange_index] = value;
            self.precomp_first_five.mul(&arr)
        } else {
            self.precomp.mul_index(value, lagrange_index)
        }
    }
}
