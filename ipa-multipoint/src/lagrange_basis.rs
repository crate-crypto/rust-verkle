use ark_ff::{batch_inversion, batch_inversion_and_mul, Field, One, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use bandersnatch::Fr;
use std::{
    convert::TryFrom,
    ops::{Add, Mul, Sub},
};

#[derive(Clone, Debug)]
pub struct LagrangeBasis {
    // We assume that the domain starts at zero,
    // so we only need to supply the upperbound
    domain: usize,
    values: Vec<Fr>,
}

impl Add<LagrangeBasis> for LagrangeBasis {
    type Output = LagrangeBasis;

    fn add(mut self, rhs: LagrangeBasis) -> Self::Output {
        if self.domain == 0 {
            return rhs;
        } else if rhs.domain == 0 {
            return self;
        }
        self.values
            .iter_mut()
            .zip(rhs.values.into_iter())
            .for_each(|(lhs, rhs)| *lhs = *lhs + rhs);
        self
    }
}
impl Mul<Fr> for LagrangeBasis {
    type Output = LagrangeBasis;

    fn mul(mut self, rhs: Fr) -> Self::Output {
        self.values
            .iter_mut()
            .for_each(|values| *values = *values * rhs);
        self
    }
}
impl Sub<&Fr> for LagrangeBasis {
    type Output = LagrangeBasis;

    fn sub(mut self, rhs: &Fr) -> Self::Output {
        self.values
            .iter_mut()
            .for_each(|values| *values = *values - rhs);
        self
    }
}
impl Sub<&Fr> for &LagrangeBasis {
    type Output = LagrangeBasis;

    fn sub(self, rhs: &Fr) -> Self::Output {
        LagrangeBasis::new(self.values.iter().map(|values| *values - rhs).collect())
    }
}
impl Sub<&LagrangeBasis> for &LagrangeBasis {
    type Output = LagrangeBasis;

    fn sub(self, rhs: &LagrangeBasis) -> Self::Output {
        LagrangeBasis::new(
            self.values
                .iter()
                .zip(rhs.values.iter())
                .map(|(lhs, rhs)| *lhs - rhs)
                .collect(),
        )
    }
}

pub struct PrecomputedWeights {
    // This stores A'(x_i) and 1/A'(x_i)
    barycentric_weights: Vec<Fr>,
    // This stores 1/k for k \in [-255, 255]
    inverted_domain: Vec<Fr>,
}

impl PrecomputedWeights {
    // domain_size is 256 in our case
    pub fn new(domain_size: usize) -> PrecomputedWeights {
        let mut barycentric_weights = vec![Fr::zero(); domain_size * 2];
        let midpoint = domain_size;
        for x_i in 0..domain_size {
            // computes A'(x_i)
            let a_x_i = PrecomputedWeights::compute_barycentric_weight_for(x_i, domain_size);
            barycentric_weights[x_i] = a_x_i;
            barycentric_weights[x_i + midpoint] = a_x_i.inverse().unwrap()
        }

        // We do not have 1/0 , so the domain_size for these are one less
        let mut inverted_domain = vec![Fr::zero(); (domain_size - 1) * 2];
        let midpoint = domain_size - 1;
        for x_i in 1..domain_size {
            let k = Fr::from(x_i as u128).inverse().unwrap();
            inverted_domain[x_i - 1] = k;
            inverted_domain[x_i - 1 + midpoint] = -k
        }

        PrecomputedWeights {
            barycentric_weights,
            inverted_domain,
        }
    }

    pub fn get_inverted_element(&self, domain_element: usize, is_negative: bool) -> Fr {
        let mut index = domain_element - 1;
        if is_negative {
            index += self.inverted_domain.len() / 2;
        }
        self.inverted_domain[index]
    }
    // computes A'(x_m) / A'(x_i)
    pub fn get_ratio_of_barycentric_weights(&self, m: usize, i: usize) -> Fr {
        self.barycentric_weights[m]
            * self.barycentric_weights[i + (self.barycentric_weights.len() / 2)]
    }
    // gets A'(x_i)
    pub fn get_barycentric_weight(&self, i: usize) -> Fr {
        self.barycentric_weights[i]
    }
    // gets 1 / A'(x_i)
    pub fn get_inverse_barycentric_weight(&self, i: usize) -> Fr {
        self.barycentric_weights[i + (self.barycentric_weights.len() / 2)]
    }
    // A'(x_j) where x_j = domain_element
    pub fn compute_barycentric_weight_for(domain_element: usize, domain_size: usize) -> Fr {
        let domain_element_fr = Fr::from(domain_element as u128);

        // First generate all of the values in the domain [0,domain_size]
        // then remove the element that we are computing the weight for from the range
        let weight: Fr = (0..domain_size)
            .filter(|element| element != &domain_element)
            .map(|element| Fr::from(element as u128))
            .map(|element| domain_element_fr - element)
            .product();
        weight
    }
}
// TODO: Lets make all of these methods pub(crate)
impl LagrangeBasis {
    pub fn new(values: Vec<Fr>) -> LagrangeBasis {
        let domain = values.len();
        LagrangeBasis { domain, values }
    }

    // This is used so that we can use fold, it is never called outside of that context
    pub(crate) fn zero() -> LagrangeBasis {
        LagrangeBasis {
            domain: 0,
            values: vec![],
        }
    }

    // This is only for testing purposes
    pub(crate) fn interpolate(&self) -> DensePolynomial<Fr> {
        let domain: Vec<_> = (0..self.domain).map(|i| Fr::from(i as u128)).collect();
        let points: Vec<_> = domain
            .into_iter()
            .zip(self.values.iter().cloned())
            .collect();
        let polynomial = interpolate(&points).unwrap();
        DensePolynomial::from_coefficients_vec(polynomial)
    }

    // A'(x_j) where x_j = domain_element
    pub fn compute_barycentric_weight_for(&self, domain_element: usize) -> Fr {
        let domain_element_fr = Fr::from(domain_element as u128);

        let domain_size = self.domain;

        // First generate all of the values in the domain [0,domain_size]
        // then remove the element that we are computing the weight for from the range
        let weight: Fr = (0..domain_size)
            .filter(|element| element != &domain_element)
            .map(|element| Fr::from(element as u128))
            .map(|element| domain_element_fr - element)
            .product();
        weight
    }

    // XXX: Maybe rename this to `divide on domain` or `divide on linear domain`
    // computes f(x) - f(x_i) / x - x_i where x_i is an element in the domain
    pub(crate) fn divide_by_linear_vanishing(
        &self,
        precomp: &PrecomputedWeights,
        index: usize,
    ) -> LagrangeBasis {
        let mut q = vec![Fr::zero(); self.domain];

        let y = self.values[index];

        for i in 0..self.domain {
            if i != index {
                let den = i32::try_from(i).unwrap() - i32::try_from(index).unwrap();
                let is_negative = den < 0;
                let den = den.abs();
                let den_inv = precomp.get_inverted_element(den as usize, is_negative);

                let q_i = (self.values[i] - y) * den_inv;
                q[i] = q_i;

                let weight_ratio = precomp.get_ratio_of_barycentric_weights(index, i);
                q[index] -= weight_ratio * q_i
            }
        }

        LagrangeBasis::new(q)
    }

    pub fn evaluate_in_domain(&self, index: usize) -> Fr {
        self.values[index]
    }

    pub fn values(&self) -> &[Fr] {
        &self.values
    }

    // We use this method to compute L_i(z) where z is not in the domain
    pub fn evaluate_lagrange_coefficients(
        precomp: &PrecomputedWeights,
        domain_size: usize,
        point: Fr,
    ) -> Vec<Fr> {
        let mut lagrange_evaluations: Vec<_> = (0..domain_size)
            .map(|i| precomp.get_barycentric_weight(i) * (point - Fr::from(i as u128)))
            .collect();

        let a_z: Fr = (0..domain_size)
            .map(|i| Fr::from(i as u128))
            .map(|element| point - element)
            .product();
        batch_inversion_and_mul(&mut lagrange_evaluations, &a_z);

        lagrange_evaluations
    }

    pub fn evaluate_outside_domain(&self, precomp: &PrecomputedWeights, point: Fr) -> Fr {
        let mut summand = Fr::zero();

        // z - x_i
        let mut point_minus_domain: Vec<_> = (0..self.domain)
            .map(|i| point - Fr::from(i as u128))
            .collect();
        batch_inversion(&mut point_minus_domain);

        for (x_i, (y_i, inv_z_min_xi)) in self.values.iter().zip(point_minus_domain).enumerate() {
            let weight = precomp.get_inverse_barycentric_weight(x_i);
            let term = weight * y_i * inv_z_min_xi;
            summand += term;
        }
        let a_z: Fr = (0..self.domain)
            .map(|i| Fr::from(i as u128))
            .map(|element| point - element)
            .product();
        summand * a_z
    }
}

#[test]
fn basic_interpolation() {
    let p1 = Fr::from(8u128);
    let p2 = Fr::from(2u128);
    let lag_poly = LagrangeBasis::new(vec![p1, p2]);

    let coeff_poly = lag_poly.interpolate();

    let got_p1 = coeff_poly.evaluate(&Fr::from(0u128));
    let got_p2 = coeff_poly.evaluate(&Fr::from(1u128));

    assert_eq!(got_p1, p1);
    assert_eq!(got_p2, p2);
}

#[test]
fn simple_eval_outside_domain() {
    let numerator_lag =
        LagrangeBasis::new(vec![-Fr::from(2), Fr::from(0), Fr::from(12), Fr::from(40)]);
    let numerator_coeff = numerator_lag.interpolate();

    let precomp = PrecomputedWeights::new(numerator_lag.domain);

    let point = Fr::from(300u128);

    let got = numerator_lag.evaluate_outside_domain(&precomp, point);
    let expected = numerator_coeff.evaluate(&point);
    assert_eq!(got, expected);

    // Another way to evaluate a point not in the domain,
    // is to compute the lagrange coefficients first and then take the inner product of those and
    // the evaluation points

    let lag_evals =
        LagrangeBasis::evaluate_lagrange_coefficients(&precomp, numerator_lag.domain, point);

    let mut got = Fr::zero();
    for (l_i, y_i) in lag_evals.into_iter().zip(numerator_lag.values().iter()) {
        got += l_i * y_i
    }
    assert_eq!(got, expected)
}
#[test]
fn simple_division() {
    let domain_size = 4;
    // (X-1))(X+1)(X+2)
    let numerator_lag =
        LagrangeBasis::new(vec![-Fr::from(2), Fr::from(0), Fr::from(12), Fr::from(40)]);
    let numerator_coeff = numerator_lag.interpolate();

    // X - 1
    let index = 1;
    let denom_coeff = DensePolynomial::from_coefficients_vec(vec![-Fr::one(), Fr::one()]);

    let precomp = PrecomputedWeights::new(domain_size);
    let quotient_lag = numerator_lag.divide_by_linear_vanishing(&precomp, index);
    let quotient_coeff = quotient_lag.interpolate();

    let quotient_expected = &numerator_coeff / &denom_coeff;

    assert_eq!(quotient_expected, quotient_coeff)
}

// Taken from sapling-crypto -- O(n^2)
fn interpolate(points: &[(Fr, Fr)]) -> Option<Vec<Fr>> {
    let max_degree_plus_one = points.len();
    assert!(
        max_degree_plus_one >= 2,
        "should interpolate for degree >= 1"
    );
    let mut coeffs = vec![Fr::zero(); max_degree_plus_one];
    // external iterator
    for (k, p_k) in points.iter().enumerate() {
        let (x_k, y_k) = p_k;
        // coeffs from 0 to max_degree - 1
        let mut contribution = vec![Fr::zero(); max_degree_plus_one];
        let mut demoninator = Fr::one();
        let mut max_contribution_degree = 0;
        // internal iterator
        for (j, p_j) in points.iter().enumerate() {
            let (x_j, _) = p_j;
            if j == k {
                continue;
            }

            let mut diff = *x_k;
            diff -= x_j;
            demoninator *= diff;

            if max_contribution_degree == 0 {
                max_contribution_degree = 1;
                *contribution
                    .get_mut(0)
                    .expect("must have enough coefficients") -= x_j;
                *contribution
                    .get_mut(1)
                    .expect("must have enough coefficients") += Fr::one();
            } else {
                let mul_by_minus_x_j: Vec<Fr> = contribution
                    .iter()
                    .map(|el| {
                        let mut tmp = *el;
                        tmp *= x_j;

                        -tmp
                    })
                    .collect();

                contribution.insert(0, Fr::zero());
                contribution.truncate(max_degree_plus_one);

                assert_eq!(mul_by_minus_x_j.len(), max_degree_plus_one);
                for (i, c) in contribution.iter_mut().enumerate() {
                    let other = mul_by_minus_x_j
                        .get(i)
                        .expect("should have enough elements");
                    *c += other;
                }
            }
        }

        demoninator = demoninator.inverse().expect("denominator must be non-zero");
        for (i, this_contribution) in contribution.into_iter().enumerate() {
            let c = coeffs.get_mut(i).expect("should have enough coefficients");
            let mut tmp = this_contribution;
            tmp *= demoninator;
            tmp *= y_k;
            *c += tmp;
        }
    }

    Some(coeffs)
}
