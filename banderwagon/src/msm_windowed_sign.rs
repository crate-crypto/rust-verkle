use crate::Element;
use ark_ec::CurveGroup;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::Zero;
use ark_ff::{BigInteger, BigInteger256};
use std::ops::Neg;

#[derive(Debug, Clone)]
pub struct MSMPrecompWindowSigned {
    tables: Vec<Vec<EdwardsAffine>>,
    num_windows: usize,
    window_size: usize,
}

impl MSMPrecompWindowSigned {
    pub fn new(bases: &[Element], window_size: usize) -> MSMPrecompWindowSigned {
        use ark_ff::PrimeField;

        let number_of_windows = Fr::MODULUS_BIT_SIZE as usize / window_size + 1;

        let precomputed_points: Vec<_> = bases
            .iter()
            .map(|point| {
                Self::precompute_points(
                    window_size,
                    number_of_windows,
                    EdwardsAffine::from(point.0),
                )
            })
            .collect();

        MSMPrecompWindowSigned {
            window_size,
            tables: precomputed_points,
            num_windows: number_of_windows,
        }
    }

    fn precompute_points(
        window_size: usize,
        number_of_windows: usize,
        point: EdwardsAffine,
    ) -> Vec<EdwardsAffine> {
        let window_size_scalar = Fr::from(1 << window_size);
        use ark_ff::Field;

        use rayon::prelude::*;

        let all_tables: Vec<_> = (0..number_of_windows)
            .into_par_iter()
            .flat_map(|window_index| {
                let window_scalar = window_size_scalar.pow([window_index as u64]);
                let mut lookup_table = Vec::with_capacity(1 << (window_size - 1));
                let point = EdwardsProjective::from(point) * window_scalar;
                let mut current = point;
                // Compute and store multiples
                for _ in 0..(1 << (window_size - 1)) {
                    lookup_table.push(current);
                    current += point;
                }
                EdwardsProjective::normalize_batch(&lookup_table)
            })
            .collect();

        all_tables
    }

    pub fn mul(&self, scalars: &[Fr]) -> Element {
        let scalars_bytes: Vec<_> = scalars
            .iter()
            .map(|a| {
                let bigint: BigInteger256 = (*a).into();
                bigint.to_bytes_le()
            })
            .collect();

        let mut points_to_add = Vec::with_capacity(self.num_windows);

        for window_idx in 0..self.num_windows {
            for (scalar_idx, scalar_bytes) in scalars_bytes.iter().enumerate() {
                let sub_table = &self.tables[scalar_idx];
                let point_idx =
                    get_booth_index(window_idx, self.window_size, scalar_bytes.as_ref());

                if point_idx == 0 {
                    continue;
                }
                let sign = point_idx.is_positive();
                let point_idx = point_idx.unsigned_abs() as usize - 1;

                // Scale the point index by the window index to figure out whether
                // we need P, 2^wP, 2^{2w}P, etc
                let scaled_point_index = window_idx * (1 << (self.window_size - 1)) + point_idx;
                let mut point = sub_table[scaled_point_index];

                if !sign {
                    point = -point;
                }

                points_to_add.push(point);
            }
        }

        let mut result = EdwardsProjective::zero();
        for point in points_to_add {
            result += point;
        }

        Element(result)
    }
}

// TODO: Link to halo2 file + docs + comments
pub fn get_booth_index(window_index: usize, window_size: usize, el: &[u8]) -> i32 {
    // Booth encoding:
    // * step by `window` size
    // * slice by size of `window + 1``
    // * each window overlap by 1 bit
    // * append a zero bit to the least significant end
    // Indexing rule for example window size 3 where we slice by 4 bits:
    // `[0, +1, +1, +2, +2, +3, +3, +4, -4, -3, -3 -2, -2, -1, -1, 0]``
    // So we can reduce the bucket size without preprocessing scalars
    // and remembering them as in classic signed digit encoding

    let skip_bits = (window_index * window_size).saturating_sub(1);
    let skip_bytes = skip_bits / 8;

    // fill into a u32
    let mut v: [u8; 4] = [0; 4];
    for (dst, src) in v.iter_mut().zip(el.iter().skip(skip_bytes)) {
        *dst = *src
    }
    let mut tmp = u32::from_le_bytes(v);

    // pad with one 0 if slicing the least significant window
    if window_index == 0 {
        tmp <<= 1;
    }

    // remove further bits
    tmp >>= skip_bits - (skip_bytes * 8);
    // apply the booth window
    tmp &= (1 << (window_size + 1)) - 1;

    let sign = tmp & (1 << window_size) == 0;

    // div ceil by 2
    tmp = (tmp + 1) >> 1;

    // find the booth action index
    if sign {
        tmp as i32
    } else {
        ((!(tmp - 1) & ((1 << window_size) - 1)) as i32).neg()
    }
}

#[test]
fn smoke_test_interop_strauss() {
    use ark_ff::UniformRand;

    let length = 5;
    let scalars: Vec<_> = (0..length)
        .map(|_| Fr::rand(&mut rand::thread_rng()))
        .collect();
    let points: Vec<_> = (0..length)
        .map(|_| Element::prime_subgroup_generator() * Fr::rand(&mut rand::thread_rng()))
        .collect();

    let precomp = MSMPrecompWindowSigned::new(&points, 2);
    let result = precomp.mul(&scalars);

    let mut expected = Element::zero();
    for (scalar, point) in scalars.into_iter().zip(points) {
        expected += point * scalar
    }

    assert_eq!(expected, result)
}

#[cfg(test)]
mod booth_tests {
    use std::ops::Neg;

    use ark_ed_on_bls12_381_bandersnatch::Fr;
    use ark_ff::{BigInteger, BigInteger256, Field, PrimeField};

    use super::get_booth_index;
    use crate::Element;

    #[test]
    fn smoke_scalar_mul() {
        let gen = Element::prime_subgroup_generator();
        let s = -Fr::ONE;

        let res = gen * s;

        let got = mul(&s, &gen, 4);

        assert_eq!(Element::from(res), got)
    }

    fn mul(scalar: &Fr, point: &Element, window: usize) -> Element {
        let u_bigint: BigInteger256 = (*scalar).into();
        use ark_ff::Field;
        let u = u_bigint.to_bytes_le();
        let n = Fr::MODULUS_BIT_SIZE as usize / window + 1;

        let table = (0..=1 << (window - 1))
            .map(|i| point * &Fr::from(i as u64))
            .collect::<Vec<_>>();

        let table_scalars = (0..=1 << (window - 1))
            .map(|i| Fr::from(i as u64))
            .collect::<Vec<_>>();

        let mut acc: Element = Element::zero();
        let mut acc_scalar = Fr::ZERO;
        for i in (0..n).rev() {
            for _ in 0..window {
                acc = acc + acc;
                acc_scalar = acc_scalar + acc_scalar;
            }

            let idx = get_booth_index(i as usize, window, u.as_ref());

            if idx.is_negative() {
                acc += table[idx.unsigned_abs() as usize].neg();
                acc_scalar -= table_scalars[idx.unsigned_abs() as usize];
            }
            if idx.is_positive() {
                acc += table[idx.unsigned_abs() as usize];
                acc_scalar += table_scalars[idx.unsigned_abs() as usize];
            }
        }

        assert_eq!(acc_scalar, *scalar);

        acc.into()
    }
}
