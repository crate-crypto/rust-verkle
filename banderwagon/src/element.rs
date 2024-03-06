use ark_ec::{twisted_edwards::TECurveConfig, Group, ScalarMul, VariableBaseMSM};
use ark_ed_on_bls12_381_bandersnatch::{BandersnatchConfig, EdwardsAffine, EdwardsProjective, Fq};
use ark_ff::{batch_inversion, Field, One, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub use ark_ed_on_bls12_381_bandersnatch::Fr;

#[derive(Debug, Clone, Copy, Eq)]
pub struct Element(pub(crate) EdwardsProjective);

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        let x1 = self.0.x;
        let y1 = self.0.y;

        let x2 = other.0.x;
        let y2 = other.0.y;

        // One should not be able to generate this point, unless they have assigned `x` and `y`
        // to be 0 directly and have bypassed the API.
        //
        // This is possible in languages such as C, we will leave this check here
        // for those who are using this as a reference, or in the case that there is some way to
        // create an Element and bypass the checks.
        if x1.is_zero() & y1.is_zero() {
            return false;
        }
        if x2.is_zero() & y2.is_zero() {
            return false;
        }

        (x1 * y2) == (x2 * y1)
    }
}

impl Element {
    pub fn to_bytes(&self) -> [u8; 32] {
        // We assume that internally this point is "correct"
        //
        // We serialize a correct point by serializing the x co-ordinate times sign(y)
        let affine = EdwardsAffine::from(self.0);
        let x = if is_positive(affine.y) {
            affine.x
        } else {
            -affine.x
        };
        let mut bytes = [0u8; 32];
        x.serialize_compressed(&mut bytes[..])
            .expect("serialization failed");

        // reverse bytes to big endian, for interoperability
        bytes.reverse();

        bytes
    }

    // Do not compare the results of this function.
    //
    // This is because if (x, -y) is on the curve, then (x,y) is also on the curve.
    // This method will return two different byte arrays for each of these.
    //
    // TODO: perhaps change this so that it chooses a representative, ie respecting the equivalence class
    pub fn to_bytes_uncompressed(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        self.0
            .serialize_uncompressed(&mut bytes[..])
            .expect("cannot serialize point as an uncompressed byte array");
        bytes
    }

    pub fn from_bytes_unchecked_uncompressed(bytes: [u8; 64]) -> Self {
        let point = EdwardsProjective::deserialize_uncompressed_unchecked(&bytes[..])
            .expect("could not deserialize byte array into a point");
        Self(point)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Element> {
        // Switch from big endian to little endian, as arkworks library uses little endian
        let mut bytes = bytes.to_vec();
        bytes.reverse();

        let x: Fq = Fq::deserialize_compressed(&bytes[..]).ok()?;

        let return_positive_y = true;

        // Construct a point that is in the group -- this point may or may not be in the prime subgroup
        let point = Self::get_point_from_x(x, return_positive_y)?;

        let element = Element(EdwardsProjective::new_unchecked(
            point.x,
            point.y,
            point.x * point.y,
            Fq::one(),
        ));

        // Check if the point is in the correct subgroup
        //
        // Check legendre - checks whether 1 - ax^2 is a QR
        if !element.subgroup_check() {
            return None;
        }

        Some(element)
    }

    pub const fn compressed_serialized_size() -> usize {
        32
    }

    pub fn prime_subgroup_generator() -> Element {
        Element(EdwardsProjective::generator())
    }

    fn get_point_from_x(x: Fq, choose_largest: bool) -> Option<EdwardsAffine> {
        let dx_squared_minus_one = BandersnatchConfig::COEFF_D * x.square() - Fq::one();
        let ax_squared_minus_one = BandersnatchConfig::COEFF_A * x.square() - Fq::one();
        let y_squared = ax_squared_minus_one / dx_squared_minus_one;

        let y = y_squared.sqrt()?;

        let is_largest = is_positive(y);

        let y = if is_largest && choose_largest { y } else { -y };

        Some(EdwardsAffine::new_unchecked(x, y))
    }

    fn map_to_field(&self) -> Fq {
        self.0.x / self.0.y
    }

    // Note: This is a 2 to 1 map, but the two preimages are identified to be the same
    pub fn map_to_scalar_field(&self) -> Fr {
        use ark_ff::PrimeField;

        let base_field = self.map_to_field();

        let mut bytes = [0u8; 32];
        base_field
            .serialize_compressed(&mut bytes[..])
            .expect("could not serialize point into a 32 byte array");
        Fr::from_le_bytes_mod_order(&bytes)
    }

    pub fn batch_map_to_scalar_field(elements: &[Element]) -> Vec<Fr> {
        use ark_ff::PrimeField;

        let mut x_div_y = Vec::with_capacity(elements.len());
        for element in elements {
            let y = element.0.y;
            x_div_y.push(y);
        }
        batch_inversion(&mut x_div_y);

        for i in 0..elements.len() {
            x_div_y[i] *= elements[i].0.x;
        }

        let mut scalars = Vec::with_capacity(elements.len());
        for element in x_div_y {
            let mut bytes = [0u8; 32];
            element
                .serialize_compressed(&mut bytes[..])
                .expect("could not serialize point into a 32 byte array");
            scalars.push(Fr::from_le_bytes_mod_order(&bytes));
        }

        scalars
    }

    pub fn zero() -> Element {
        Element(EdwardsProjective::zero())
    }

    pub fn is_zero(&self) -> bool {
        *self == Element::zero()
    }

    pub(crate) fn subgroup_check(&self) -> bool {
        legendre_check_point(&self.0.x)
    }
}

// The lexographically largest value is defined to be the positive value
fn is_positive(coordinate: Fq) -> bool {
    coordinate > -coordinate
}

fn legendre_check_point(x: &Fq) -> bool {
    let res = Fq::one() - (BandersnatchConfig::COEFF_A * x.square());
    res.legendre().is_qr()
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    let bases_inner: Vec<_> = bases.iter().map(|element| element.0).collect();

    // XXX: Converting all of these to affine hurts performance
    let bases = EdwardsProjective::batch_convert_to_mul_base(&bases_inner);

    let result = EdwardsProjective::msm(&bases, scalars)
        .expect("number of bases should equal number of scalars");

    Element(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_serialize::CanonicalSerialize;
    #[test]
    fn consistent_group_to_field() {
        // In python this is called commitment_to_field
        // print(commitment_to_field(Point(generator=True)).to_bytes(32, "little").hex())
        let expected = "d1e7de2aaea9603d5bc6c208d319596376556ecd8336671ba7670c2139772d14";

        let generator = Element::prime_subgroup_generator();
        let mut bytes = [0u8; 32];
        generator
            .map_to_scalar_field()
            .serialize_compressed(&mut bytes[..])
            .unwrap();
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn from_bytes_unchecked_uncompressed_roundtrip() {
        let generator = Element::prime_subgroup_generator();
        let bytes = generator.to_bytes_uncompressed();
        let element = Element::from_bytes_unchecked_uncompressed(bytes);

        assert_eq!(element, generator)
    }

    #[test]
    fn from_batch_map_to_scalar_field() {
        let mut points = Vec::new();
        for i in 0..10 {
            points.push(Element::prime_subgroup_generator() * Fr::from(i));
        }

        let got = Element::batch_map_to_scalar_field(&points);

        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
        }
        for i in 0..10 {
            let expected_i = points[i].map_to_scalar_field();
            assert_eq!(expected_i, got[i]);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // Two torsion point, *not*  point at infinity {0,-1,0,1}
    fn two_torsion() -> EdwardsProjective {
        EdwardsProjective::new_unchecked(Fq::zero(), -Fq::one(), Fq::zero(), Fq::one())
    }
    fn points_at_infinity() -> [EdwardsProjective; 2] {
        let d = BandersnatchConfig::COEFF_D;
        let a = BandersnatchConfig::COEFF_A;
        let sqrt_da = (d / a).sqrt().unwrap();

        let p1 = EdwardsProjective::new_unchecked(sqrt_da, Fq::zero(), Fq::one(), Fq::zero());
        let p2 = EdwardsProjective::new_unchecked(-sqrt_da, Fq::zero(), Fq::one(), Fq::zero());

        [p1, p2]
    }

    #[test]
    fn fixed_test_vectors() {
        let expected_bit_string = [
            "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",
            "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",
            "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",
            "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",
            "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",
            "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
            "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
            "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
            "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
            "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
            "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
            "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
            "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
            "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
            "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
            "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
        ];

        let mut points = vec![];
        let mut point = Element::prime_subgroup_generator();
        for (i, _) in expected_bit_string.into_iter().enumerate() {
            let byts = hex::encode(point.to_bytes());
            assert_eq!(byts, expected_bit_string[i], "index {} does not match", i);

            points.push(point);
            point = Element(point.0.double())
        }
    }

    #[test]
    fn ser_der_roundtrip() {
        let point = EdwardsProjective::generator();

        let two_torsion_point = two_torsion();

        let element1 = Element(point);
        let bytes1 = element1.to_bytes();

        let element2 = Element(point + two_torsion_point);
        let bytes2 = element2.to_bytes();

        assert_eq!(bytes1, bytes2);

        let got = Element::from_bytes(&bytes1).expect("points are in the valid subgroup");

        assert!(got == element1);
        assert!(got == element2);
    }
    #[test]
    fn check_infinity_does_not_pass_legendre() {
        // We cannot use the points at infinity themselves
        // as they have Z=0, which will panic when converting to
        // affine co-ordinates. So we create a point which is
        // the sum of the point at infinity and another point
        let point = points_at_infinity()[0];
        let gen = EdwardsProjective::generator();
        let gen2 = gen + gen + gen + gen;

        let res = point + gen + gen2;

        let element1 = Element(res);
        let bytes1 = element1.to_bytes();

        if Element::from_bytes(&bytes1).is_some() {
            panic!("point contains a point at infinity and should not have passed deserialization")
        }
    }

    #[test]
    fn two_torsion_correct() {
        let two_torsion_point = two_torsion();
        assert!(!two_torsion_point.is_zero());

        let result = two_torsion_point.double();
        assert!(result.is_zero());

        let [inf1, inf2] = points_at_infinity();
        assert!(!inf1.is_zero());
        assert!(!inf2.is_zero());

        assert!(inf1.double().is_zero());
        assert!(inf2.double().is_zero());
    }
}
