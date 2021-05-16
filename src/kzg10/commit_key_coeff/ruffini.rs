use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial as Polynomial;
use ark_poly::Polynomial as PolyTrait;
use ark_poly::UVPolynomial;

/// Divides `self` by x-z using Ruffinis method
pub fn compute<F: PrimeField>(poly: &Polynomial<F>, z: F) -> Polynomial<F> {
    let mut quotient: Vec<F> = Vec::with_capacity(poly.degree());
    let mut k = F::zero();

    // Reverse the results and use Ruffini's method to compute the quotient
    // The coefficients must be reversed as Ruffini's method
    // starts with the leading coefficient, while Polynomials
    // are stored in increasing order i.e. the leading coefficient is the last element
    for coeff in poly.coeffs.iter().rev() {
        let t = *coeff + &k;
        quotient.push(t);
        k = z * &t;
    }

    // Pop off the last element, it is the remainder term
    // For PLONK, we only care about perfect factors
    quotient.pop();

    // Reverse the results for storage in the Polynomial struct
    quotient.reverse();
    Polynomial::from_coefficients_vec(quotient)
}
