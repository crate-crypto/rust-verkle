use ark_ec::scalar_mul::wnaf::WnafContext;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsProjective, Fr};
use rayon::prelude::*;

use crate::Element;

pub struct MSMPrecompWnaf {
    wnaf_context: WnafContext,
    tables: Vec<Vec<EdwardsProjective>>,
}

impl MSMPrecompWnaf {
    pub fn new(bases: &[Element], window_size: usize) -> MSMPrecompWnaf {
        let wnaf_context = WnafContext::new(window_size);
        let mut tables = Vec::with_capacity(bases.len());

        for base in bases {
            tables.push(wnaf_context.table(base.0));
        }

        MSMPrecompWnaf {
            tables,
            wnaf_context,
        }
    }

    pub fn mul_index(&self, scalar: Fr, index: usize) -> Element {
        Element(
            self.wnaf_context
                .mul_with_table(&self.tables[index], &scalar)
                .unwrap(),
        )
    }

    pub fn mul(&self, scalars: &[Fr]) -> Element {
        let results: Vec<_> = scalars
            .into_iter()
            .zip(self.tables.iter())
            .map(|(scalar, table)| self.wnaf_context.mul_with_table(table, scalar).unwrap())
            .collect();

        Element(results.into_iter().sum())
    }
    // TODO: This requires more benchmarking and feedback to see if we should
    // TODO put this behind a config flag
    pub fn mul_par(&self, scalars: &[Fr]) -> Element {
        let results: Vec<_> = scalars
            .into_par_iter()
            .zip(self.tables.par_iter())
            .map(|(scalar, table)| self.wnaf_context.mul_with_table(table, scalar).unwrap())
            .collect();

        Element(results.into_par_iter().sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{multi_scalar_mul, Element};

    #[test]
    fn correctness_smoke_test() {
        let mut crs = Vec::with_capacity(256);
        for i in 0..256 {
            crs.push(Element::prime_subgroup_generator() * Fr::from((i + 1) as u64));
        }

        let mut scalars = vec![];
        for i in 0..256 {
            scalars.push(-Fr::from(i + 1));
        }

        let result = multi_scalar_mul(&crs, &scalars);

        let precomp = MSMPrecompWnaf::new(&crs, 12);
        let got_result = precomp.mul(&scalars);
        let got_par_result = precomp.mul_par(&scalars);

        assert_eq!(result, got_result);
        assert_eq!(result, got_par_result);
    }
}
