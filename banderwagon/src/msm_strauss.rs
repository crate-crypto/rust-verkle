use ark_ec::{twisted_edwards::TECurveConfig, CurveGroup};
use ark_ed_on_bls12_381_bandersnatch::{
    BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq, Fr,
};
use ark_ff::{batch_inversion, BigInteger, BigInteger256};
use std::ops::Neg;

// Precomputes 16 bit windows for elements
pub struct MSMPrecomp16Bit {
    tables: Vec<Vec<EdwardsAffine>>,
    num_windows: usize,
    window_size: usize,
}

impl MSMPrecomp16Bit {
    pub fn new(bases: &[Element], window_size: usize) -> MSMPrecomp16Bit {
        use ark_ff::PrimeField;

        let number_of_windows = Fr::MODULUS_BIT_SIZE as usize / window_size + 1;

        let precomputed_points: Vec<_> = bases
            .into_iter()
            .map(|point| {
                Self::precompute_points(
                    window_size,
                    number_of_windows,
                    EdwardsAffine::from(point.0),
                )
            })
            .collect();

        MSMPrecomp16Bit {
            window_size,
            tables: precomputed_points,
            num_windows: number_of_windows,
        }
    }

    // fn precompute_points(wbits: usize, point: Element) -> Vec<Element> {
    //     let mut lookup_table = Vec::with_capacity(1 << (wbits - 1));

    //     // Convert to projective for faster operations
    //     let mut current = (point);
    //     // Compute and store multiples
    //     for _ in 0..(1 << (wbits - 1)) {
    //         lookup_table.push(current);
    //         current += point;
    //     }

    //     lookup_table
    //     // EdwardsProjective::normalize_batch(&lookup_table)
    // }

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
                let window_scalar = window_size_scalar.pow(&[window_index as u64]);
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

        let mut points_to_add = Vec::new();

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
        use ark_ff::Zero;
        let mut result = EdwardsProjective::zero();
        for point in points_to_add {
            result += point;
        }

        Element(result)
    }
}
use ark_ff::Field;

pub fn batch_addition_diff_stride(mut points: Vec<EdwardsAffine>) -> EdwardsProjective {
    #[inline(always)]

    fn point_add(p1: EdwardsAffine, p2: EdwardsAffine, inv: &Fq) -> EdwardsAffine {
        // let x1x2 = p1.x * p2.x;
        // let y1y2 = p1.y * p2.y;

        // let x1y2 = p1.x * p2.y;
        // let x2y1 = p2.x * p1.y;

        // let d = BandersnatchConfig::COEFF_D;
        // let d1 = Fq::ONE - d * x1x2 * y1y2;
        // let d2 = Fq::ONE + d * x1x2 * y1y2;

        // let x_denom = *inv * d1;
        // let y_denom = *inv * d2;

        // let x = (x1y2 + x2y1) * x_denom;

        // let a = BandersnatchConfig::COEFF_A;
        // let y = (y1y2 - a * x1x2) * y_denom;
        EdwardsAffine::new_unchecked(p1.x, *inv)
    }
    #[inline(always)]
    fn compute_denom_needed(p1: EdwardsAffine, p2: EdwardsAffine) -> Fq {
        let d = BandersnatchConfig::COEFF_D;
        // Compute (1-dx1x2y1y2)^2
        (Fq::ONE - d * p1.x * p1.y * p2.x * p2.y).square()
    }
    if points.is_empty() {
        return EdwardsProjective::default();
    }

    let mut new_differences = Vec::with_capacity(points.len());

    let mut points_len = points.len();

    let mut sum = EdwardsProjective::default();

    const BATCH_INVERSE_THRESHOLD: usize = 16;

    while points.len() > BATCH_INVERSE_THRESHOLD {
        if points.len() % 2 != 0 {
            sum += points
                .pop()
                .expect("infallible; since points has an odd length");
        }
        new_differences.clear();

        for i in (0..=points.len() - 2).step_by(2) {
            new_differences.push(compute_denom_needed(points[i], points[i + 1]));
        }
        // (v);
        batch_inversion(&mut new_differences);
        //
        for (i, inv) in (0..=points.len() - 2).step_by(2).zip(&new_differences) {
            let p1 = points[i];
            let p2 = points[i + 1];
            points[i / 2] = point_add(p1, p2, inv);
        }

        // The latter half of the vector is now unused,
        // all results are stored in the former half.
        points.truncate(new_differences.len())
    }

    for point in points {
        sum += point
    }

    sum
}

use crate::Element;

#[derive(Clone, Debug)]
pub struct MSMPrecomp {
    window_size: usize,
    // tables: Vec<Vec<Element>>,
    tables: Vec<Vec<EdwardsAffine>>,
}
impl MSMPrecomp {
    pub fn new(bases: &[Element], window_size: usize) -> MSMPrecomp {
        let precomputed_points: Vec<_> = bases
            .into_iter()
            .map(|point| Self::precompute_points(window_size, EdwardsAffine::from(point.0)))
            // .map(|point| Self::precompute_points(window_size, *point))
            .collect();
        MSMPrecomp {
            window_size,
            tables: precomputed_points,
        }
    }

    // fn precompute_points(wbits: usize, point: Element) -> Vec<Element> {
    //     let mut lookup_table = Vec::with_capacity(1 << (wbits - 1));

    //     // Convert to projective for faster operations
    //     let mut current = (point);
    //     // Compute and store multiples
    //     for _ in 0..(1 << (wbits - 1)) {
    //         lookup_table.push(current);
    //         current += point;
    //     }

    //     lookup_table
    //     // EdwardsProjective::normalize_batch(&lookup_table)
    // }

    fn precompute_points(wbits: usize, point: EdwardsAffine) -> Vec<EdwardsAffine> {
        let mut lookup_table = Vec::with_capacity(1 << (wbits - 1));

        // Convert to projective for faster operations
        let mut current = EdwardsProjective::from(point);
        // Compute and store multiples
        for _ in 0..(1 << (wbits - 1)) {
            lookup_table.push(current);
            current += point;
        }

        EdwardsProjective::normalize_batch(&lookup_table)
    }

    pub fn mul(&self, scalars: &[Fr]) -> Element {
        let scalars_bytes: Vec<_> = scalars
            .iter()
            .map(|a| {
                let bigint: BigInteger256 = (*a).into();
                bigint.to_bytes_le()
            })
            .collect();

        use ark_ff::PrimeField;

        let number_of_windows = Fr::MODULUS_BIT_SIZE as usize / self.window_size + 1;

        let mut windows_of_points = vec![Vec::with_capacity(scalars.len()); number_of_windows];

        for window_idx in 0..number_of_windows {
            for (scalar_idx, scalar_bytes) in scalars_bytes.iter().enumerate() {
                let sub_table = &self.tables[scalar_idx];
                let point_idx =
                    get_booth_index(window_idx, self.window_size, scalar_bytes.as_ref());

                if point_idx == 0 {
                    continue;
                }
                let sign = point_idx.is_positive();
                let point_idx = point_idx.unsigned_abs() as usize - 1;
                let mut point = sub_table[point_idx];
                if !sign {
                    point = -point;
                }

                windows_of_points[window_idx].push(point);
            }
        }

        let accumulated_points: Vec<_> = windows_of_points
            .into_iter()
            .map(|wp| batch_addition(&wp))
            .collect();

        // use ark_ec::Group;
        let mut result = EdwardsProjective::from(*accumulated_points.last().unwrap());
        for point in accumulated_points.into_iter().rev().skip(1) {
            // Double the result 'wbits' times
            for _ in 0..self.window_size {
                result = result + result; // todo: double method
            }
            // Add the accumulated point for this window
            result += point;
        }

        Element(result)
    }
}

fn batch_addition(points: &[EdwardsAffine]) -> EdwardsAffine {
    use ark_ff::Zero;
    let mut result = EdwardsProjective::zero();
    for point in points {
        result += EdwardsProjective::from(*point);
    }
    result.into()
}
// fn batch_addition(points: &[Element]) -> Element {
//     use ark_ff::Zero;
//     let mut result = Element::zero();
//     for point in points {
//         // result += Element(EdwardsProjective::from(*point));
//         result += *point;
//     }
//     result
// }

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
    let length = 5;
    let scalars: Vec<_> = (0..length).map(|i| Fr::from(0x424242 + i as u64)).collect();
    let points: Vec<_> = (0..length)
        .map(|i| Element::prime_subgroup_generator() * Fr::from((i + 1) as u64))
        .collect();

    let precomp = MSMPrecomp::new(&points, 2);
    let result = precomp.mul(&scalars);

    let mut expected = Element::zero();
    for (scalar, point) in scalars.into_iter().zip(points) {
        expected += point * scalar
    }

    assert_eq!(expected, result)
}

#[test]
fn smoke_test_interop_precomp16() {
    let length = 1;
    let scalars: Vec<_> = (0..length).map(|i| Fr::from(0x424242 + i as u64)).collect();
    let points: Vec<_> = (0..length)
        .map(|i| Element::prime_subgroup_generator() * Fr::from((i + 1) as u64))
        .collect();

    let precomp = MSMPrecomp16Bit::new(&points, 16);
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
