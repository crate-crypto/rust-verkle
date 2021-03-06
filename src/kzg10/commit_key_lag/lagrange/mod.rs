use std::ops::{Add, Index, Mul};

use ark_ec::PairingEngine;
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
};
use rayon::prelude::*;
// Wrapper around Evaluations with extra methods

pub struct LagrangeBasis<E: PairingEngine>(pub Evaluations<E::Fr>);

impl<E: PairingEngine> LagrangeBasis<E> {
    pub fn interpolate(&self) -> DensePolynomial<E::Fr> {
        self.0.interpolate_by_ref()
    }
    // XXX: cannot add as a trait due to Rust
    pub fn add_scalar(mut self, element: &E::Fr) -> Self {
        self.0
            .evals
            .par_iter_mut()
            .for_each(|eval| *eval = *eval + *element);
        self
    }

    pub fn zero(num_points: usize) -> LagrangeBasis<E> {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(num_points).unwrap();
        let evals = vec![E::Fr::zero(); domain.size()];

        LagrangeBasis::from(Evaluations::from_vec_and_domain(evals, domain))
    }

    pub fn domain(&self) -> GeneralEvaluationDomain<E::Fr> {
        self.0.domain()
    }
    pub fn values(&self) -> &[E::Fr] {
        &self.0.evals
    }

    // convenience method
    pub fn divide_by_linear_vanishing_from_point(
        point: &E::Fr,
        f_x: &LagrangeBasis<E>,
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
        f_x: &LagrangeBasis<E>,
        inv: &[E::Fr],
        domain_elements: &[E::Fr],
    ) -> LagrangeBasis<E> {
        let domain_size = domain_elements.len();
        assert!(index < domain_size);

        let y = f_x[index];
        let mut q = vec![E::Fr::zero(); domain_size];
        let mut q_index = E::Fr::zero();

        // preconditions:
        // i = 0
        if 0 != index {
            q[0] = (f_x[0] - y) * domain_elements[0] * inv[index];
            q_index += -domain_elements[domain_size - index] * &q[0]
        }

        // preconditions:
        // i < index
        // i != 0
        for i in 1..index {
            assert!(i < index);
            assert!(i != 0);

            q[i] = (f_x[i] - y) * domain_elements[domain_size - i] * inv[index - i];
            q_index += -domain_elements[(i.wrapping_sub(index)).rem_euclid(domain_size)] * &q[i]
        }

        // preconditions:
        // i > index
        // i != 0
        for i in (index + 1)..domain_size {
            assert!(i > index);
            assert!(i != 0);
            q[i] = (f_x[i] - y)
                * domain_elements[domain_size - i]
                * inv[index.wrapping_sub(i).rem_euclid(domain_size)];
            q_index += -domain_elements[i - index] * &q[i]
        }

        q[index] = q_index;

        let domain = GeneralEvaluationDomain::new(domain_size).unwrap();
        let l = LagrangeBasis::<E>::from(Evaluations::from_vec_and_domain(q, domain));

        l
    }

    pub fn evaluate_point_outside_domain(&self, point: &E::Fr) -> E::Fr {
        let domain = self.0.domain();

        let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(*point);

        let mut interpolated_eval = E::Fr::zero();
        for i in 0..domain.size() {
            interpolated_eval += lagrange_coeffs[i] * &self.0.evals[i];
        }
        interpolated_eval
    }
}

impl<E: PairingEngine> From<&'_ [E::Fr]> for LagrangeBasis<E> {
    fn from(evals: &[E::Fr]) -> Self {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(evals.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(evals.to_vec(), domain);
        LagrangeBasis(evaluations)
    }
}
impl<E: PairingEngine> From<Vec<E::Fr>> for LagrangeBasis<E> {
    fn from(evals: Vec<E::Fr>) -> Self {
        let domain = GeneralEvaluationDomain::<E::Fr>::new(evals.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        LagrangeBasis(evaluations)
    }
}
impl<E: PairingEngine> From<Evaluations<E::Fr>> for LagrangeBasis<E> {
    fn from(evals: Evaluations<E::Fr>) -> Self {
        LagrangeBasis(evals)
    }
}
impl<E: PairingEngine> From<&'_ Evaluations<E::Fr>> for LagrangeBasis<E> {
    fn from(evals: &Evaluations<E::Fr>) -> Self {
        LagrangeBasis(evals.clone())
    }
}
impl<E: PairingEngine> Mul<&'_ E::Fr> for LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn mul(mut self, rhs: &E::Fr) -> Self::Output {
        self.0
            .evals
            .par_iter_mut()
            .for_each(|eval| *eval = *eval * rhs);
        self
    }
}

impl<E: PairingEngine> Add<LagrangeBasis<E>> for LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn add(mut self, rhs: LagrangeBasis<E>) -> Self::Output {
        use rayon::prelude::*;
        self.0
            .evals
            .par_iter_mut()
            .zip(rhs.0.evals.into_par_iter())
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
