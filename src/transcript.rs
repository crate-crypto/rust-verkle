use ark_ec::PairingEngine;
use ark_ff::{to_bytes, PrimeField};
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
        let mut buf = vec![0u8; E::Fr::size_in_bits()];
        self.challenge_bytes(label, &mut buf);

        E::Fr::from_be_bytes_mod_order(&buf)
    }
}

// This transcript is used for performance comparisons with the python and golang implementation
// It is not interopable because the python and golang implementation, do not separate domains
pub struct BasicTranscript {
    state: Vec<u8>,
}
impl BasicTranscript {
    pub fn new(label: &'static [u8]) -> BasicTranscript {
        let mut state = Vec::new();
        state.extend(label);
        BasicTranscript { state }
    }

    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.state.extend(label);
        self.state.extend(message);
    }
    pub fn append_u64(&mut self, label: &'static [u8], x: u64) {
        self.state.extend(label);
        self.state.extend(&x.to_be_bytes());
    }
}

impl<E: PairingEngine> TranscriptProtocol<E> for BasicTranscript {
    fn append_point(&mut self, label: &'static [u8], point: &E::G1Affine) {
        let bytes = to_bytes!(point).unwrap();

        self.append_message(label, &bytes);
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &E::Fr) {
        let bytes = to_bytes!(s).unwrap();
        self.append_message(label, &bytes)
    }
    // Python code essentially takes the sha256 hash
    // then reduces it modulo the field
    fn challenge_scalar(&mut self, label: &'static [u8]) -> E::Fr {
        use sha2::Digest;

        self.state.extend(label);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&self.state);
        let bytes = hasher.finalize();

        //XXX: to be consistent with python, we need to clear the
        // state after generating a challenge

        E::Fr::from_be_bytes_mod_order(&bytes)
    }
}
