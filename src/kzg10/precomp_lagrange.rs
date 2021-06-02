use super::{errors::KZG10Error, Commitment};
use crate::kzg10::LagrangeCommitter;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::Zero;
#[derive(Debug, Clone)]
pub struct PrecomputeLagrange<E: PairingEngine> {
    inner: Vec<LagrangeTablePoints<E>>,
    num_points: usize,
}

impl<E: PairingEngine> LagrangeCommitter<E> for PrecomputeLagrange<E> {
    fn commit_lagrange(&self, evaluations: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        if evaluations.len() != self.num_points {
            return Err(KZG10Error::PolynomialDegreeTooLarge);
        }

        let mut result = E::G1Projective::default();

        let scalar_table = evaluations
            .into_iter()
            .zip(self.inner.iter())
            .filter(|(evals, _)| !evals.is_zero());

        for (scalar, table) in scalar_table {
            // convert scalar to bytes in little endian
            let bytes = ark_ff::to_bytes!(scalar).unwrap();
            for (row, byte) in bytes.into_iter().enumerate() {
                let point = table.point(row, byte);
                result += E::G1Projective::from(*point);
            }
        }
        Ok(Commitment::from_projective(result))
    }

    fn commit_lagrange_single(
        &self,
        value: E::Fr,
        lagrange_index: usize,
    ) -> Result<Commitment<E>, KZG10Error> {
        let table = &self.inner[lagrange_index];
        use rayon::prelude::*;
        let mut result = E::G1Projective::default();

        let bytes = ark_ff::to_bytes!(value).unwrap();

        let result: E::G1Projective = bytes
            .into_iter()
            .enumerate()
            .map(|(row, byte)| {
                let point = table.point(row, byte);
                E::G1Projective::from(*point)
            })
            .sum();
        Ok(Commitment::from_projective(result))
    }
}

impl<E: PairingEngine> PrecomputeLagrange<E> {
    pub fn precompute(points: &[E::G1Affine]) -> Self {
        let lagrange_precomputed_points =
            PrecomputeLagrange::<E>::precompute_lagrange_points(points);
        Self {
            inner: lagrange_precomputed_points,
            num_points: points.len(),
        }
    }

    fn precompute_lagrange_points(lagrange_points: &[E::G1Affine]) -> Vec<LagrangeTablePoints<E>> {
        use rayon::prelude::*;
        lagrange_points
            .into_par_iter()
            .map(|point| LagrangeTablePoints::<E>::new(point))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct LagrangeTablePoints<E: PairingEngine> {
    identity: E::G1Affine,
    matrix: Vec<E::G1Affine>,
}

impl<E: PairingEngine> LagrangeTablePoints<E> {
    pub fn new(point: &E::G1Affine) -> LagrangeTablePoints<E> {
        let num_rows = 32u64;
        // We use base 256
        let base_u128 = 256u128;

        let base = E::Fr::from(base_u128);

        let base_row = LagrangeTablePoints::<E>::compute_base_row(point, (base_u128 - 1) as usize);

        let mut rows = Vec::with_capacity(num_rows as usize);
        rows.push(base_row);

        for i in 1..num_rows {
            let next_row =
                LagrangeTablePoints::<E>::scale_row(rows[(i - 1) as usize].as_slice(), base);
            rows.push(next_row)
        }
        use rayon::prelude::*;
        let flattened_rows: Vec<_> = rows.into_par_iter().flatten().collect();

        LagrangeTablePoints {
            identity: E::G1Affine::default(),
            matrix: flattened_rows,
        }
    }
    pub fn point(&self, index: usize, value: u8) -> &E::G1Affine {
        if value == 0 {
            return &self.identity;
        }
        &self.matrix.as_slice()[(index * 255) + (value - 1) as usize]
    }

    // Computes [G_1, 2G_1, 3G_1, ... num_points * G_1]
    fn compute_base_row(point: &E::G1Affine, num_points: usize) -> Vec<E::G1Affine> {
        let mut row = Vec::with_capacity(num_points);
        row.push(*point);
        for i in 1..num_points {
            row.push(row[i - 1] + *point)
        }
        assert_eq!(row.len(), num_points);
        row
    }

    // Given [G_1, 2G_1, 3G_1, ... num_points * G_1] and a scalar `k`
    // Returns [k * G_1, 2 * k * G_1, 3 * k * G_1, ... num_points * k * G_1]
    fn scale_row(points: &[E::G1Affine], scale: E::Fr) -> Vec<E::G1Affine> {
        let scaled_row: Vec<E::G1Affine> = points
            .into_iter()
            .map(|element| element.mul(scale).into())
            .collect();

        scaled_row
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::kzg10::LagrangeCommitter;
    #[test]
    fn commit_lagrange_consistency() {
        use ark_bls12_381::{Bls12_381, Fr};
        use ark_ff::UniformRand;
        let degree = 7;
        let srs = setup_test(degree);

        let values: Vec<_> = (1..=degree + 1)
            .map(|_| Fr::rand(&mut rand_core::OsRng))
            .collect();

        let expected_comm = srs.commit_key().commit_lagrange(&values).unwrap();

        let base_points =
            PrecomputeLagrange::<Bls12_381>::precompute(&srs.commit_key.lagrange_powers_of_g);
        let got_comm = base_points.commit_lagrange(&values).unwrap();

        assert_eq!(expected_comm.0, got_comm.0)
    }
    #[test]
    fn commit_lagrange_single_consistency() {
        use ark_bls12_381::{Bls12_381, Fr};
        use ark_ff::UniformRand;
        use ark_ff::Zero;
        use rand::Rng;
        let degree = 7;
        let srs = setup_test(degree);

        let index = rand::thread_rng().gen_range(0..=degree);
        let non_zero_scalar = Fr::rand(&mut rand_core::OsRng);

        let mut values = vec![Fr::zero(); degree + 1];
        values[index] = non_zero_scalar;

        let base_points =
            PrecomputeLagrange::<Bls12_381>::precompute(&srs.commit_key.lagrange_powers_of_g);
        let expected_comm = base_points.commit_lagrange(&values).unwrap();

        let got_comm = base_points
            .commit_lagrange_single(non_zero_scalar, index)
            .unwrap();

        assert_eq!(expected_comm.0, got_comm.0)
    }

    use crate::kzg10::commit_key_lag::srs::PublicParameters;
    fn setup_test(degree: usize) -> PublicParameters<ark_bls12_381::Bls12_381> {
        PublicParameters::setup(degree.next_power_of_two(), &mut rand_core::OsRng).unwrap()
    }
}
