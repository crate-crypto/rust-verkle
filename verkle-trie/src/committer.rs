use bandersnatch::{EdwardsProjective, Fr};

pub mod precompute;
pub mod test;

// This is the functionality that commits to the branch nodes and computes the delta optimisation
// For consistency with the PCS, ensure that this component uses the same CRS as the PCS
// This is being done in the config file automatically
pub trait Committer {
    // Commit to a lagrange polynomial, evaluations.len() must equal the size of the SRS at the moment
    //XXX: We can make this &[Fr;256] since we have committed to 256, this would force the caller
    // to handle the size of the slice
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective;
    // compute value * G for a specific generator in the SRS
    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective;

    fn commit_sparse(&self, val_indices: Vec<(Fr, usize)>) -> EdwardsProjective {
        let mut result = EdwardsProjective::default();

        for (value, lagrange_index) in val_indices {
            result += self.scalar_mul(value, lagrange_index)
        }

        return result;
    }
}
