use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{AffineCurve, PairingEngine};

use crate::kzg10::VerkleCommitter;

use super::{errors::KZG10Error, Commitment};

#[derive(Debug, Clone)]
pub struct PrecomputeLagrange<E: PairingEngine> {
    inner: Vec<LagrangeTablePoints<E>>,
    num_points: usize,
}

impl<E: PairingEngine> VerkleCommitter<E> for PrecomputeLagrange<E> {
    fn commit_lagrange(&self, evaluations: &[E::Fr]) -> Result<Commitment<E>, KZG10Error> {
        if evaluations.len() != self.num_points {
            return Err(KZG10Error::PolynomialDegreeTooLarge);
        }

        let mut result = E::G1Projective::default();

        for (scalar, table) in evaluations.into_iter().zip(self.inner.iter()) {
            let bytes = ark_ff::to_bytes!(scalar).unwrap();
            for (row, byte) in bytes.into_iter().enumerate() {
                let point = table.point(row, byte);
                result += E::G1Projective::from(*point);
            }
        }
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

// Precompute the necessary lagrange points
//
// XXX: Change this to be one vector
#[derive(Debug, Clone)]
pub struct LagrangePointsRow<E: PairingEngine>(Vec<E::G1Affine>);

impl<E: PairingEngine> LagrangePointsRow<E> {
    pub fn as_slice(&self) -> &[E::G1Affine] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct LagrangeTablePoints<E: PairingEngine> {
    identity: E::G1Affine,
    matrix: Vec<LagrangePointsRow<E>>,
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

        LagrangeTablePoints {
            identity: E::G1Affine::default(),
            matrix: rows,
        }
    }
    pub fn point(&self, index: usize, value: u8) -> &E::G1Affine {
        let row = &self.matrix[index];
        if value == 0 {
            return &self.identity;
        }
        &row.as_slice()[(value - 1) as usize]
    }

    // Computes [G_1, 2G_1, 3G_1, ... num_points * G_1]
    fn compute_base_row(point: &E::G1Affine, num_points: usize) -> LagrangePointsRow<E> {
        let mut row = Vec::with_capacity(num_points);
        row.push(*point);
        for i in 1..=num_points {
            row.push(row[i - 1] + *point)
        }
        LagrangePointsRow(row)
    }
    // Given [G_1, 2G_1, 3G_1, ... num_points * G_1] and a scalar `k`
    // Returns [k * G_1, 2 * k *G_1, 3 * k * G_1, ... num_points * k * G_1]
    fn scale_row(points: &[E::G1Affine], scale: E::Fr) -> LagrangePointsRow<E> {
        let scaled_row: Vec<E::G1Affine> = points
            .into_iter()
            .map(|element| element.mul(scale).into())
            .collect();

        LagrangePointsRow(scaled_row)
    }
}

#[test]
fn commit_lagrange_consistency() {
    use ark_ff::UniformRand;
    let (ck, vk) = setup_test(3);

    let values = vec![
        Fr::rand(&mut rand_core::OsRng),
        Fr::rand(&mut rand_core::OsRng),
        Fr::rand(&mut rand_core::OsRng),
        Fr::rand(&mut rand_core::OsRng),
    ];

    let expected_comm = ck.commit_lagrange(&values).unwrap();

    let base_points = PrecomputeLagrange::<Bls12_381>::precompute(&ck.lagrange_powers_of_g);
    let got_comm = base_points.commit_lagrange(&values).unwrap();

    assert_eq!(expected_comm.0, got_comm.0)
}
fn setup_test(
    degree: usize,
) -> (
    super::CommitKey<ark_bls12_381::Bls12_381>,
    super::OpeningKey<ark_bls12_381::Bls12_381>,
) {
    let srs =
        super::PublicParameters::setup(degree.next_power_of_two(), &mut rand_core::OsRng).unwrap();
    srs.trim(degree).unwrap()
}
