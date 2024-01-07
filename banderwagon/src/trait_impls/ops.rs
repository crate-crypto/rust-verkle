use crate::Element;
use ark_ed_on_bls12_381_bandersnatch::Fr;

use std::{
    hash::Hash,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Sub},
};

impl Mul<Fr> for Element {
    type Output = Element;

    fn mul(self, rhs: Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}
impl Mul<&Fr> for &Element {
    type Output = Element;

    fn mul(self, rhs: &Fr) -> Self::Output {
        Element(self.0.mul(rhs))
    }
}
impl Add<Element> for Element {
    type Output = Element;

    fn add(self, rhs: Element) -> Self::Output {
        Element(self.0 + rhs.0)
    }
}
impl AddAssign<Element> for Element {
    fn add_assign(&mut self, rhs: Element) {
        self.0 += rhs.0
    }
}
impl Sub<Element> for Element {
    type Output = Element;

    fn sub(self, rhs: Element) -> Self::Output {
        Element(self.0 - rhs.0)
    }
}
impl Neg for Element {
    type Output = Element;

    fn neg(self) -> Self::Output {
        Element(-self.0)
    }
}

impl Sum for Element {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Element(iter.map(|element| element.0).sum())
    }
}

impl Hash for Element {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}
