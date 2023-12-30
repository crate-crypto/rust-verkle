use ark_ec::{msm::VariableBaseMSM, ProjectiveCurve, TEModelParameters};
use ark_ff::{Field, One, PrimeField, SquareRootField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bandersnatch::{BandersnatchParameters, EdwardsAffine, EdwardsProjective, Fq, Fr};

#[derive(Debug, Clone, Copy, Eq)]
pub struct Element(pub(crate) EdwardsProjective);

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        let x1 = self.0.x;
        let y1 = self.0.y;

        let x2 = other.0.x;
        let y2 = other.0.y;

        // TODO: check that this point (0,0) cannot be constructed/generated at least through this API
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
        // We serialise a correct point by serialising the x co-ordinate times sign(y)
        let affine = self.0.into_affine();
        let x = if is_positive(affine.y) {
            affine.x
        } else {
            -affine.x
        };
        let mut bytes = [0u8; 32];
        x.serialize(&mut bytes[..]).expect("serialisation failed");

        // reverse bytes to big endian, for interopability
        bytes.reverse();

        bytes
    }
    pub const fn compressed_serialised_size() -> usize {
        32
    }
    pub fn prime_subgroup_generator() -> Element {
        Element(EdwardsProjective::prime_subgroup_generator())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Element> {
        // Switch from big endian to little endian, as arkworks library uses little endian
        let mut bytes = bytes.to_vec();
        bytes.reverse();

        let x: Fq = Fq::deserialize(&bytes[..]).ok()?;

        let return_positive_y = true;
        let point = EdwardsAffine::get_point_from_x(x, return_positive_y)?;

        // check legendre - checks whether 1 - ax^2 is a QR
        // TODO: change the name of this method to subgroup_check or wrap it in a method named subgroup_check
        let ok = legendre_check_point(&x);
        if !ok {
            return None;
        }

        Some(Element(EdwardsProjective::new(
            point.x,
            point.y,
            point.x * point.y,
            Fq::one(),
        )))
    }

    pub fn map_to_field(&self) -> Fq {
        self.0.x / self.0.y
    }

    pub fn zero() -> Element {
        Element(EdwardsProjective::zero())
    }

    pub fn is_zero(&self) -> bool {
        *self == Element::zero()
    }
}

fn is_positive(x: Fq) -> bool {
    x > -x
}

fn legendre_check_point(x: &Fq) -> bool {
    let res = Fq::one() - (BandersnatchParameters::COEFF_A * x.square());
    res.legendre().is_qr()
}

pub fn multi_scalar_mul(bases: &[Element], scalars: &[Fr]) -> Element {
    let bases_inner: Vec<_> = bases.into_iter().map(|element| element.0).collect();

    // XXX: Converting all of these to affine hurts performance
    let bases = EdwardsProjective::batch_normalization_into_affine(&bases_inner);

    let scalars: Vec<_> = scalars
        .into_iter()
        .map(|scalar| scalar.into_repr())
        .collect();

    let result = VariableBaseMSM::multi_scalar_mul(&bases, &scalars);

    Element(result)
}

#[cfg(test)]
mod test {
    use super::*;
    // Two torsion point, *not*  point at infinity {0,-1,0,1}
    fn two_torsion() -> EdwardsProjective {
        EdwardsProjective::new(Fq::zero(), -Fq::one(), Fq::zero(), Fq::one())
    }
    fn points_at_infinity() -> [EdwardsProjective; 2] {
        let d = BandersnatchParameters::COEFF_D;
        let a = BandersnatchParameters::COEFF_A;
        let sqrt_da = (d / a).sqrt().unwrap();

        let p1 = EdwardsProjective::new(sqrt_da, Fq::zero(), Fq::one(), Fq::zero());
        let p2 = EdwardsProjective::new(-sqrt_da, Fq::zero(), Fq::one(), Fq::zero());

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
        for i in 0..16 {
            let byts = hex::encode(&point.to_bytes());
            assert_eq!(byts, expected_bit_string[i], "index {} does not match", i);

            points.push(point);
            point = Element(point.0.double())
        }
    }

    #[test]
    fn ser_der_roundtrip() {
        let point = EdwardsProjective::prime_subgroup_generator();

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
        let gen = EdwardsProjective::prime_subgroup_generator();
        let gen2 = gen + gen + gen + gen;

        let res = point + gen + gen2;

        let element1 = Element(res);
        let bytes1 = element1.to_bytes();

        if let Some(_) = Element::from_bytes(&bytes1) {
            panic!("point contains a point at infinity and should not have passed deserialisation")
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
