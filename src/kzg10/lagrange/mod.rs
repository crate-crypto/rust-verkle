use std::ops::{Add, Index, Mul};

use ark_ec::PairingEngine;
use ark_ff::{One, Zero};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
};

// Wrapper around Evaluations with extra methods

pub struct LagrangeBasis<E: PairingEngine>(pub Evaluations<E::Fr>);

impl<E: PairingEngine> LagrangeBasis<E> {
    pub fn interpolate(&self) -> DensePolynomial<E::Fr> {
        self.0.interpolate_by_ref()
    }
    // XXX: cannot add as a trait due to Rust
    pub fn add_scalar(&self, element: &E::Fr) -> Self {
        let domain = self.0.domain();
        let scaled_evals_points: Vec<_> =
            self.0.evals.iter().map(|eval| *eval + *element).collect();
        let evaluations = Evaluations::from_vec_and_domain(scaled_evals_points, domain);
        LagrangeBasis::from(evaluations)
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
    ) -> LagrangeBasis<E> {
        // find index for this point
        let index = f_x
            .0
            .domain()
            .elements()
            .into_iter()
            .position(|f| f == *point)
            .unwrap();

        LagrangeBasis::<E>::divide_by_linear_vanishing(index, f_x, precomputed_inverses)
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
    ) -> LagrangeBasis<E> {
        let domain = f_x.domain();
        let domain_size = domain.size();

        let mut quotient = vec![E::Fr::zero(); domain_size];
        let y = f_x[index];
        for i in 0..domain_size {
            if i != index {
                quotient[i] = (f_x[i] - y)
                    * domain.element(domain_size - i)
                    * inv[index.wrapping_sub(i).rem_euclid(domain_size)];

                let quot_i = quotient[i].clone();

                quotient[index] +=
                    -domain.element((i.wrapping_sub(index)).rem_euclid(domain_size)) * quot_i;
            }
        }

        LagrangeBasis::from(Evaluations::from_vec_and_domain(quotient, domain))
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
impl<E: PairingEngine> Mul<E::Fr> for LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn mul(self, rhs: E::Fr) -> Self::Output {
        &self * &rhs
    }
}

impl<E: PairingEngine> Mul<&'_ E::Fr> for &LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn mul(self, rhs: &E::Fr) -> Self::Output {
        let domain = self.0.domain();
        let scaled_evals_points: Vec<_> = self.0.evals.iter().map(|eval| *eval * *rhs).collect();
        let evaluations = Evaluations::from_vec_and_domain(scaled_evals_points, domain);
        LagrangeBasis::from(evaluations)
    }
}

impl<E: PairingEngine> Add<&'_ LagrangeBasis<E>> for &LagrangeBasis<E> {
    type Output = LagrangeBasis<E>;

    fn add(self, rhs: &LagrangeBasis<E>) -> Self::Output {
        LagrangeBasis::from(&self.0 + &rhs.0)
    }
}

impl<E: PairingEngine> Index<usize> for LagrangeBasis<E> {
    type Output = E::Fr;

    fn index(&self, i: usize) -> &Self::Output {
        &self.0[i]
    }
}
