use ark_ec::AffineCurve;
use ark_ff::{ToBytes, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};

use crate::committer::Committer;

type IOResult<T> = std::io::Result<T>;
type IOError = std::io::Error;
type IOErrorKind = std::io::ErrorKind;

#[derive(Debug, Clone)]
pub struct PrecomputeLagrange {
    inner: Vec<LagrangeTablePoints>,
    num_points: usize,
}

impl<'a> Committer for &'a PrecomputeLagrange {
    // If compute these points at compile time, we can
    // dictate that evaluations should be an array
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        if evaluations.len() != self.num_points {
            panic!("wrong number of points")
        }

        let mut result = EdwardsProjective::default();

        let scalar_table = evaluations
            .into_iter()
            .zip(self.inner.iter())
            .filter(|(evals, _)| !evals.is_zero());

        for (scalar, table) in scalar_table {
            // convert scalar to bytes in little endian
            let bytes = ark_ff::to_bytes!(scalar).unwrap();

            let partial_result: EdwardsProjective = bytes
                .into_iter()
                .enumerate()
                .map(|(row, byte)| {
                    let point = table.point(row, byte);
                    EdwardsProjective::from(*point)
                })
                .sum();
            result += partial_result;
        }
        result
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        let table = &self.inner[lagrange_index];

        let bytes = ark_ff::to_bytes!(value).unwrap();
        let result: EdwardsProjective = bytes
            .into_iter()
            .enumerate()
            .map(|(row, byte)| {
                let point = table.point(row, byte);
                EdwardsProjective::from(*point)
            })
            .sum();
        result
    }
}
impl Committer for PrecomputeLagrange {
    fn commit_lagrange(&self, evaluations: &[Fr]) -> EdwardsProjective {
        (&self).commit_lagrange(evaluations)
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> EdwardsProjective {
        (&self).scalar_mul(value, lagrange_index)
    }
}

impl PrecomputeLagrange {
    pub fn precompute(points: &[EdwardsAffine]) -> Self {
        let lagrange_precomputed_points = PrecomputeLagrange::precompute_lagrange_points(points);
        Self {
            inner: lagrange_precomputed_points,
            num_points: points.len(),
        }
    }

    fn precompute_lagrange_points(lagrange_points: &[EdwardsAffine]) -> Vec<LagrangeTablePoints> {
        use rayon::prelude::*;
        lagrange_points
            .into_par_iter()
            .map(|point| LagrangeTablePoints::new(point))
            .collect()
    }

    pub fn read<R: std::io::Read>(mut reader: R) -> IOResult<PrecomputeLagrange> {

        let mut num_points = [0u8; 4];
        reader.read_exact(&mut num_points)?;
        let num_points = u32::from_le_bytes(num_points) as usize;

        let mut num_lagrange_points = [0u8; 4];
        reader.read_exact(&mut num_lagrange_points)?;
        let num_lagrange_points = u32::from_le_bytes(num_lagrange_points);
        let mut inner = Vec::new();
        for i in 0..num_lagrange_points {
            let point = LagrangeTablePoints::read(&mut reader)?;
            inner.push(point);
        }

        Ok(PrecomputeLagrange {
            inner,
            num_points
        })
    }

    pub fn write<W: std::io::Write>(&self, mut writer: W) -> IOResult<()> {

        let num_points= self.num_points as u32;
        writer.write(&num_points.to_le_bytes());

        let num_lagrange_points= self.inner.len() as u32;
        writer.write(&num_lagrange_points.to_le_bytes());

        for lagrange_points in &self.inner {
            lagrange_points.write(&mut writer);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LagrangeTablePoints {
    identity: EdwardsAffine,
    matrix: Vec<EdwardsAffine>,
}

impl LagrangeTablePoints {
    pub fn new(point: &EdwardsAffine) -> LagrangeTablePoints {
        let num_rows = 32u64;
        // We use base 256
        let base_u128 = 256u128;

        let base = Fr::from(base_u128);

        let base_row = LagrangeTablePoints::compute_base_row(point, (base_u128 - 1) as usize);

        let mut rows = Vec::with_capacity(num_rows as usize);
        rows.push(base_row);

        for i in 1..num_rows {
            let next_row = LagrangeTablePoints::scale_row(rows[(i - 1) as usize].as_slice(), base);
            rows.push(next_row)
        }
        use rayon::prelude::*;
        let flattened_rows: Vec<_> = rows.into_par_iter().flatten().collect();

        LagrangeTablePoints {
            identity: EdwardsAffine::default(),
            matrix: flattened_rows,
        }
    }
    pub fn point(&self, index: usize, value: u8) -> &EdwardsAffine {
        if value == 0 {
            return &self.identity;
        }
        &self.matrix.as_slice()[(index * 255) + (value - 1) as usize]
    }

    // Computes [G_1, 2G_1, 3G_1, ... num_points * G_1]
    fn compute_base_row(point: &EdwardsAffine, num_points: usize) -> Vec<EdwardsAffine> {
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
    fn scale_row(points: &[EdwardsAffine], scale: Fr) -> Vec<EdwardsAffine> {
        let scaled_row: Vec<EdwardsAffine> = points
            .into_iter()
            .map(|element| element.mul(scale).into())
            .collect();

        scaled_row
    }

    pub fn read<R: std::io::Read>(mut reader: R) -> IOResult<LagrangeTablePoints> {

        let identity: EdwardsAffine = CanonicalDeserialize::deserialize_unchecked(&mut reader)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;

        let mut num_matrix_points = [0u8; 4];
        reader.read_exact(&mut num_matrix_points)?;
        let num_matrix_points = u32::from_le_bytes(num_matrix_points);

        let mut matrix = Vec::new();
        for _ in 0..num_matrix_points {
            let point: EdwardsAffine = CanonicalDeserialize::deserialize_unchecked(&mut reader)
                .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;
            matrix.push(point);
        }

        Ok(LagrangeTablePoints {
            identity,
            matrix
        })
    }

    pub fn write<W: std::io::Write>(&self, mut writer: W) -> IOResult<()> {

        let mut identity_serialised = [0u8; 64];
        self.identity.serialize_unchecked(&mut identity_serialised[..])
            .map_err(|_| IOError::from(IOErrorKind::InvalidInput));
        writer.write(&identity_serialised)?;

        let num_matrix_points= self.matrix.len() as u32;
        writer.write(&num_matrix_points.to_le_bytes());

        for matrix_point in &self.matrix {
            let mut point_serialised = [0u8; 64];
            matrix_point.serialize_unchecked(&mut point_serialised[..])
                .map_err(|_| IOError::from(IOErrorKind::InvalidInput));
            writer.write(&point_serialised)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {

    use ark_ec::AffineCurve;
    use ark_ff::{ToBytes, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};

    use crate::committer::Committer;
    use crate::committer::precompute::LagrangeTablePoints;

    type IOResult<T> = std::io::Result<T>;
    type IOError = std::io::Error;
    type IOErrorKind = std::io::ErrorKind;

    #[test]
    fn read_write() {
        let mut serialized_point: &[u8] = &[48, 172, 150, 138, 152, 171, 108, 80, 55, 159, 200, 176,
            57, 171, 200, 253, 154, 202, 37, 159, 71, 70, 160, 91, 251, 223, 18, 200, 100, 99, 194,
            8, 36, 88, 107, 76, 70, 56, 218, 40, 159, 231, 118, 145, 69, 15, 110, 94, 150, 205, 77,
            236, 215, 186, 25, 226, 0, 52, 190, 230, 160, 129, 38, 10];

        let point: EdwardsAffine = CanonicalDeserialize::deserialize_unchecked(&mut serialized_point)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData)).unwrap();

        let lagrange_point = LagrangeTablePoints::new(&point);

        let mut serialized_lagrange_point:Vec<u8> = Vec::new();
        lagrange_point.write(&mut serialized_lagrange_point).unwrap();

        let deserialized_lagrange_point = LagrangeTablePoints::read(&mut serialized_lagrange_point.as_slice()).unwrap();

        assert_eq!(lagrange_point.identity, deserialized_lagrange_point.identity);
        assert_eq!(lagrange_point.matrix, deserialized_lagrange_point.matrix);
    }

}

// #[cfg(test)]
// mod test {
//     use ark_ec::ProjectiveCurve;
//     use ark_ff::PrimeField;

//     use crate::SRS;

//     use super::*;
//     #[test]
//     fn commit_lagrange_consistency() {
//         let degree = 255;

//         let values: Vec<_> = (1..=degree + 1).map(|i| Fr::from(i as u128)).collect();

//         let expected_comm = {
//             let mut res = EdwardsProjective::zero();
//             for (val, point) in values.iter().zip(SRS.iter()) {
//                 res += point.mul(val.into_repr())
//             }
//             res
//         };

//         let base_points = PrecomputeLagrange::precompute(&SRS.map(|point| point.into_affine()));
//         let got_comm = base_points.commit_lagrange(&values);

//         assert_eq!(expected_comm, got_comm)
//     }
//     #[test]
//     fn scalar_mul_consistency() {
//         use ark_ff::Zero;

//         let degree = 255;
//         let index = 5;
//         let non_zero_scalar = Fr::from(10 as u128);

//         let mut values = vec![Fr::zero(); degree + 1];
//         values[index] = non_zero_scalar;

//         let base_points = PrecomputeLagrange::precompute(&SRS.map(|point| point.into_affine()));
//         let expected_comm = base_points.commit_lagrange(&values);

//         let got_comm = base_points.scalar_mul(non_zero_scalar, index);

//         assert_eq!(expected_comm, got_comm)
//     }
// }
