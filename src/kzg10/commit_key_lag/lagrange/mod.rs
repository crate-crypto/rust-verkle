use std::ops::{Add, Index, Mul};

use ark_ec::PairingEngine;
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
};
use rayon::prelude::*;
// Wrapper around Evaluations with extra methods

pub struct LagrangeBasis<E: PairingEngine>(pub Vec<E::Fr>);

impl<E: PairingEngine> LagrangeBasis<E> {
    pub fn interpolate(&self) -> DensePolynomial<E::Fr> {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(self.0.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(self.0.to_vec(), domain);
        evaluations.interpolate_by_ref()
    }
    // XXX: cannot add as a trait due to Rust
    pub fn add_scalar(mut self, element: &E::Fr) -> Self {
        self.0
            .par_iter_mut()
            .for_each(|eval| *eval = *eval + *element);
        self
    }

    pub fn zero(num_points: usize) -> LagrangeBasis<E> {
        let evals = vec![E::Fr::zero(); num_points];

        LagrangeBasis::from(evals)
    }

    pub fn domain(&self) -> GeneralEvaluationDomain<E::Fr> {
        GeneralEvaluationDomain::<E::Fr>::new(self.0.len()).unwrap()
    }
    pub fn values(&self) -> &[E::Fr] {
        &self.0
    }

    // convenience method
    pub fn divide_by_linear_vanishing_from_point(
        point: &E::Fr,
        f_x: &[E::Fr],
        precomputed_inverses: &[E::Fr],
        domain: &[E::Fr],
    ) -> LagrangeBasis<E> {
        // find index for this point
        let index = domain.iter().position(|f| f == point).unwrap();

        LagrangeBasis::<E>::divide_by_linear_vanishing(index, f_x, precomputed_inverses, domain)
    }
    // This function computes f(x) - f(omega^i) / x - omega^i
    //
    // f(x) vanishes on a subdomain of the domain, as X - omega^i
    // is a linear factor of the vanishing polynomial
    //
    // XXX: This function is general and so it is not optimised at the moment.
    pub fn divide_by_linear_vanishing(
        index: usize,
        f_x: &[E::Fr],
        inv: &[E::Fr],
        domain_elements: &[E::Fr],
    ) -> LagrangeBasis<E> {
        use rayon::prelude::*;

        let domain_size = domain_elements.len();

        let y = f_x[index];

        let quot_i = f_x.into_par_iter().enumerate().map(|(i, elem)| {
            if i == index {
                return (i, E::Fr::zero());
            }

            let quot_i = (*elem - y)
                * domain_elements[(domain_size - i) % domain_size]
                * inv[index.wrapping_sub(i).rem_euclid(domain_size)];

            (i, quot_i)
        });

        // compute the value at index
        let quot_index: E::Fr = quot_i
            .clone()
            .map(|(i, quot_i)| {
                if i == index {
                    return E::Fr::zero();
                }
                -domain_elements[(i.wrapping_sub(index)).rem_euclid(domain_size)] * quot_i
            })
            .sum();

        let quotient: Vec<_> = quot_i
            .into_par_iter()
            .map(|(i, elem)| {
                if i == index {
                    return quot_index;
                }
                return elem;
            })
            .collect();

        LagrangeBasis::from(quotient)
    }

    pub fn evaluate_point_outside_domain(&self, point: &E::Fr) -> E::Fr {
        let domain = self.domain();

        let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(*point);

        let mut interpolated_eval = E::Fr::zero();
        for i in 0..domain.size() {
            interpolated_eval += lagrange_coeffs[i] * &self.0[i];
        }
        interpolated_eval
    }
}

impl<E: PairingEngine> From<Vec<E::Fr>> for LagrangeBasis<E> {
    fn from(evals: Vec<E::Fr>) -> Self {
        LagrangeBasis(evals)
    }
}
// impl<E: PairingEngine> From<Evaluations<E::Fr>> for LagrangeBasis<E> {
//     fn from(evaluations: Evaluations<E::Fr>) -> Self {
//         LagrangeBasis(evaluations.evals)
//     }
// }
// impl<E: PairingEngine> From<&'_ Evaluations<E::Fr>> for LagrangeBasis<E> {
//     fn from(evaluations: &Evaluations<E::Fr>) -> Self {
//         LagrangeBasis(evaluations.evals.clone())
//     }
// }
impl<E: PairingEngine> Mul<&'_ E::Fr> for LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn mul(mut self, rhs: &E::Fr) -> Self::Output {
        self.0.par_iter_mut().for_each(|eval| *eval = *eval * rhs);
        self
    }
}

impl<E: PairingEngine> Add<LagrangeBasis<E>> for LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn add(mut self, rhs: LagrangeBasis<E>) -> Self::Output {
        use rayon::prelude::*;
        self.0
            .par_iter_mut()
            .zip(rhs.0.into_par_iter())
            .for_each(|(lhs, rhs)| *lhs = *lhs + rhs);
        self
    }
}

impl<E: PairingEngine> Index<usize> for LagrangeBasis<E> {
    type Output = E::Fr;

    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}
