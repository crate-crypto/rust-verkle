use ark_ec::PairingEngine;
use ark_ff::{to_bytes, Field, PrimeField};
use merlin::Transcript;

/// Transcript adds an abstraction over the Merlin transcript
/// For convenience
pub trait TranscriptProtocol<E: PairingEngine> {
    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &E::G1Affine);

    /// Append a `Scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], s: &E::Fr);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> E::Fr;

    /// Append domain separator for the circuit size.
    fn circuit_domain_sep(&mut self, n: u64);
}

impl<E: PairingEngine> TranscriptProtocol<E> for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &E::G1Affine) {
        let bytes = to_bytes!(point).unwrap();
        self.append_message(label, &bytes);
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &E::Fr) {
        let bytes = to_bytes!(s).unwrap();
        self.append_message(label, &bytes)
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> E::Fr {
        let mut buf = vec![0u8; E::Fr::size_in_bits() / 8 - 1];
        self.challenge_bytes(label, &mut buf);

        E::Fr::from_random_bytes(&buf).unwrap()
    }

    fn circuit_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"circuit_size");
        self.append_u64(b"n", n);
    }
}
