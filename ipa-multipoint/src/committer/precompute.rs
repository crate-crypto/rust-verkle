use crate::committer::Committer;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use banderwagon::{Element, Fr, VerkleField};

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct PrecomputeLagrange {
    inner: Vec<LagrangeTablePoints>,
    num_points: usize,
}

impl<'a> Committer for &'a PrecomputeLagrange {
    // If compute these points at compile time, we can
    // dictate that evaluations should be an array
    fn commit_lagrange(&self, evaluations: &[Fr; 256]) -> Element {
        if evaluations.len() != self.num_points {
            panic!("wrong number of points")
        }

        let mut result = Element::zero();

        let scalar_table = evaluations
            .iter()
            .zip(self.inner.iter())
            .filter(|(evals, _)| !evals.is_zero());

        for (scalar, table) in scalar_table {
            // convert scalar to bytes in little endian
            let mut bytes = [0u8; 32];
            scalar.serialize_compressed(&mut bytes[..]).unwrap();

            let partial_result: Element = bytes
                .into_iter()
                .enumerate()
                .map(|(row, byte)| {
                    let point = table.point(row, byte);
                    *point
                })
                .sum();
            result += partial_result;
        }
        result
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        let table = &self.inner[lagrange_index];

        let mut bytes = [0u8; 32];

        value.serialize_compressed(&mut bytes[..]).unwrap();

        let result: Element = bytes
            .into_iter()
            .enumerate()
            .map(|(row, byte)| {
                let point = table.point(row, byte);
                *point
            })
            .sum();
        result
    }
}
impl Committer for PrecomputeLagrange {
    fn commit_lagrange(&self, evaluations: &[Fr; 256]) -> Element {
        (&self).commit_lagrange(evaluations)
    }

    fn scalar_mul(&self, value: Fr, lagrange_index: usize) -> Element {
        (&self).scalar_mul(value, lagrange_index)
    }
}

impl PrecomputeLagrange {
    pub fn precompute(points: &[Element]) -> Self {
        let lagrange_precomputed_points = PrecomputeLagrange::precompute_lagrange_points(points);
        Self {
            inner: lagrange_precomputed_points,
            num_points: points.len(),
        }
    }

    fn precompute_lagrange_points(lagrange_points: &[Element]) -> Vec<LagrangeTablePoints> {
        use rayon::prelude::*;
        lagrange_points
            .into_par_iter()
            .map(LagrangeTablePoints::new)
            .collect()
    }
}
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct LagrangeTablePoints {
    identity: Element,
    matrix: Vec<Element>,
}

impl LagrangeTablePoints {
    pub fn new(point: &Element) -> LagrangeTablePoints {
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
            identity: Element::zero(),
            matrix: flattened_rows,
        }
    }
    pub fn point(&self, index: usize, value: u8) -> &Element {
        if value == 0 {
            return &self.identity;
        }
        &self.matrix.as_slice()[(index * 255) + (value - 1) as usize]
    }

    // Computes [G_1, 2G_1, 3G_1, ... num_points * G_1]
    fn compute_base_row(point: &Element, num_points: usize) -> Vec<Element> {
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
    fn scale_row(points: &[Element], scale: Fr) -> Vec<Element> {
        let scaled_row: Vec<Element> = points.iter().map(|element| *element * scale).collect();

        scaled_row
    }
}

#[cfg(test)]
mod test {

    use crate::committer::precompute::LagrangeTablePoints;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use banderwagon::Element;

    #[test]
    fn read_write() {
        let point = Element::prime_subgroup_generator();

        let mut serialized_lagrange_table: Vec<u8> = Vec::new();

        let expected_lagrange_table = LagrangeTablePoints::new(&point);
        expected_lagrange_table
            .serialize_compressed(&mut serialized_lagrange_table)
            .unwrap();

        let got_lagrange_table: LagrangeTablePoints =
            CanonicalDeserialize::deserialize_compressed(&*serialized_lagrange_table).unwrap();

        assert_eq!(expected_lagrange_table, got_lagrange_table);
    }
}

#[cfg(test)]
mod test_mod {
    use std::convert::TryInto;

    use crate::crs::CRS;

    use super::*;
    #[test]
    fn commit_lagrange_consistency() {
        let degree = 255;

        let crs = CRS::new(degree + 1, b"foo");

        let values: Vec<_> = (1..=degree + 1).map(|i| Fr::from(i as u128)).collect();

        let expected_comm =
            {
                let mut res = Element::zero();
                for (val, point) in values.iter().zip(crs.G.iter()) {
                    res += point * val
                }
                res
            };

        let values_arr: [Fr; 256] = values.try_into().unwrap();
        let base_points = PrecomputeLagrange::precompute(&crs.G);
        let got_comm = base_points.commit_lagrange(&values_arr);

        assert_eq!(expected_comm, got_comm)
    }
    #[test]
    fn scalar_mul_consistency() {
        let degree = 255;
        let index = 5;
        let non_zero_scalar = Fr::from(10 as u128);

        let crs = CRS::new(degree + 1, b"foo");

        let mut values = vec![Fr::zero(); degree + 1];
        values[index] = non_zero_scalar;

        let values_arr: [Fr; 256] = values.try_into().unwrap();
        let base_points = PrecomputeLagrange::precompute(&crs.G);
        let expected_comm = base_points.commit_lagrange(&values_arr);

        let got_comm = base_points.scalar_mul(non_zero_scalar, index);

        assert_eq!(expected_comm, got_comm)
    }
}
