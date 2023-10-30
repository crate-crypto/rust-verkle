// We get given multiple polynomials evaluated at different points
#![allow(non_snake_case)]

use crate::crs::CRS;
use crate::ipa::{self, slow_vartime_multiscalar_mul, IPAProof};
use crate::lagrange_basis::{LagrangeBasis, PrecomputedWeights};
use crate::math_utils::inner_product;
use crate::math_utils::powers_of;
use crate::transcript::Transcript;
use crate::transcript::TranscriptProtocol;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_ff::{batch_inversion, Field};
use ark_ff::{One, Zero};
use ark_poly::{Polynomial, UVPolynomial};
use std::collections::HashMap;

use banderwagon::{multi_scalar_mul, Element, Fr};
pub struct MultiPoint;

#[derive(Clone, Debug)]
pub struct ProverQuery {
    pub commitment: Element,
    pub poly: LagrangeBasis, // TODO: Make this a reference so that upstream libraries do not need to clone
    // Given a function f, we use z_i to denote the input point and y_i to denote the output, ie f(z_i) = y_i
    pub point: usize,
    pub result: Fr,
}

impl From<ProverQuery> for VerifierQuery {
    fn from(pq: ProverQuery) -> Self {
        VerifierQuery {
            commitment: pq.commitment,
            point: Fr::from(pq.point as u128),
            result: pq.result,
        }
    }
}
pub struct VerifierQuery {
    pub commitment: Element,
    pub point: Fr,
    pub result: Fr,
}

//XXX: change to group_prover_queries_by_point
fn group_prover_queries<'a>(
    prover_queries: &'a [ProverQuery],
    challenges: &'a [Fr],
) -> HashMap<usize, Vec<(&'a ProverQuery, &'a Fr)>> {
    // We want to group all of the polynomials which are evaluated at the same point together
    use itertools::Itertools;
    prover_queries
        .iter()
        .zip(challenges.iter())
        .into_group_map_by(|x| x.0.point)
}

impl MultiPoint {
    pub fn open(
        crs: CRS,
        precomp: &PrecomputedWeights,
        transcript: &mut Transcript,
        queries: Vec<ProverQuery>,
    ) -> MultiPointProof {
        transcript.domain_sep(b"multiproof");
        // 1. Compute `r`
        //
        // Add points and evaluations
        for query in queries.iter() {
            transcript.append_point(b"C", &query.commitment);
            transcript.append_scalar(b"z", &Fr::from(query.point as u128));
            // XXX: note that since we are always opening on the domain
            // the prover does not need to pass y_i explicitly
            // It's just an index operation on the lagrange basis
            transcript.append_scalar(b"y", &query.result)
        }

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of(r, queries.len());

        let grouped_queries = group_prover_queries(&queries, &powers_of_r);

        // aggregate all of the queries evaluated at the same point
        let aggregated_queries: Vec<_> = grouped_queries
            .into_iter()
            .map(|(point, queries_challenges)| {
                let mut aggregated_polynomial = vec![Fr::zero(); crs.n];

                let scaled_lagrange_polynomials =
                    queries_challenges.into_iter().map(|(query, challenge)| {
                        // scale the polynomial by the challenge
                        query.poly.values().iter().map(move |x| *x * challenge)
                    });

                for poly_mul_challenge in scaled_lagrange_polynomials {
                    for (result, scaled_poly) in
                        aggregated_polynomial.iter_mut().zip(poly_mul_challenge)
                    {
                        *result += scaled_poly;
                    }
                }

                (point, LagrangeBasis::new(aggregated_polynomial))
            })
            .collect();

        // Compute g(X)
        //
        let g_x: LagrangeBasis = aggregated_queries
            .iter()
            .map(|(point, agg_f_x)| (agg_f_x).divide_by_linear_vanishing(precomp, *point))
            .fold(LagrangeBasis::zero(), |mut res, val| {
                res = res + val;
                res
            });

        let g_x_comm = crs.commit_lagrange_poly(&g_x);
        transcript.append_point(b"D", &g_x_comm);

        // 2. Compute g_1(t)
        //
        //
        let t = transcript.challenge_scalar(b"t");
        //
        //

        let mut g1_den: Vec<_> = aggregated_queries
            .iter()
            .map(|(z_i, _)| t - Fr::from(*z_i as u128))
            .collect();
        batch_inversion(&mut g1_den);

        let g1_x = aggregated_queries
            .into_iter()
            .zip(g1_den.into_iter())
            .map(|((_, agg_f_x), den_inv)| {
                let term: Vec<_> = agg_f_x
                    .values()
                    .iter()
                    .map(|coeff| den_inv * coeff)
                    .collect();

                LagrangeBasis::new(term)
            })
            .fold(LagrangeBasis::zero(), |mut res, val| {
                res = res + val;
                res
            });

        let g1_comm = crs.commit_lagrange_poly(&g1_x);
        transcript.append_point(b"E", &g1_comm);

        //3. Compute g_1(X) - g(X)
        // This is the polynomial, we will create an opening for
        let g_3_x = &g1_x - &g_x;
        let g_3_x_comm = g1_comm - g_x_comm;

        // 4. Compute the IPA for g_3
        let g_3_ipa = open_point_outside_of_domain(crs, precomp, transcript, g_3_x, g_3_x_comm, t);

        MultiPointProof {
            open_proof: g_3_ipa,
            g_x_comm: g_x_comm,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiPointProof {
    open_proof: IPAProof,
    g_x_comm: Element,
}

impl MultiPointProof {
    pub fn from_bytes(bytes: &[u8], poly_degree: usize) -> crate::IOResult<MultiPointProof> {
        use crate::{IOError, IOErrorKind};
        use ark_serialize::CanonicalDeserialize;

        let g_x_comm_bytes = &bytes[0..32];
        let ipa_bytes = &bytes[32..]; // TODO: we should return a Result here incase the user gives us bad bytes

        let point: Element = CanonicalDeserialize::deserialize(g_x_comm_bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;
        let g_x_comm = point;

        let open_proof = IPAProof::from_bytes(ipa_bytes, poly_degree)?;
        Ok(MultiPointProof {
            open_proof,
            g_x_comm,
        })
    }
    pub fn to_bytes(&self) -> crate::IOResult<Vec<u8>> {
        use crate::{IOError, IOErrorKind};
        use ark_serialize::CanonicalSerialize;

        let mut bytes = Vec::with_capacity(self.open_proof.serialised_size() + 32);

        self.g_x_comm
            .serialize(&mut bytes)
            .map_err(|_| IOError::from(IOErrorKind::InvalidData))?;

        bytes.extend(self.open_proof.to_bytes()?);
        Ok(bytes)
    }
}

impl MultiPointProof {
    pub fn check(
        &self,
        crs: &CRS,
        precomp: &PrecomputedWeights,
        queries: &[VerifierQuery],
        transcript: &mut Transcript,
    ) -> bool {
        transcript.domain_sep(b"multiproof");
        // 1. Compute `r`
        //
        // Add points and evaluations
        for query in queries.iter() {
            transcript.append_point(b"C", &query.commitment);
            transcript.append_scalar(b"z", &query.point);
            transcript.append_scalar(b"y", &query.result);
        }

        let r = transcript.challenge_scalar(b"r");
        let powers_of_r = powers_of(r, queries.len());

        // 2. Compute `t`
        transcript.append_point(b"D", &self.g_x_comm);
        let t = transcript.challenge_scalar(b"t");

        // 3. Compute g_2(t)
        //
        let mut g2_den: Vec<_> = queries.iter().map(|query| t - query.point).collect();
        batch_inversion(&mut g2_den);

        let helper_scalars: Vec<_> = powers_of_r
            .iter()
            .zip(g2_den.into_iter())
            .map(|(r_i, den_inv)| den_inv * r_i)
            .collect();

        let g2_t: Fr = helper_scalars
            .iter()
            .zip(queries.iter())
            .map(|(r_i_den_inv, query)| *r_i_den_inv * query.result)
            .sum();

        //4. Compute [g_1(X)] = E
        let comms: Vec<_> = queries.into_iter().map(|query| query.commitment).collect();
        let g1_comm = slow_vartime_multiscalar_mul(helper_scalars.iter(), comms.iter());

        transcript.append_point(b"E", &g1_comm);

        // E - D
        let g3_comm = g1_comm - self.g_x_comm;

        // Check IPA
        let b = LagrangeBasis::evaluate_lagrange_coefficients(&precomp, crs.n, t); // TODO: we could put this as a method on PrecomputedWeights

        self.open_proof
            .verify_multiexp(transcript, crs, b, g3_comm, t, g2_t)
    }
}

// TODO: we could probably get rid of this method altogether and just do this in the multiproof
// TODO method
// TODO: check that the point is actually not in the domain
pub(crate) fn open_point_outside_of_domain(
    crs: CRS,
    precomp: &PrecomputedWeights,
    transcript: &mut Transcript,
    polynomial: LagrangeBasis,
    commitment: Element,
    z_i: Fr,
) -> IPAProof {
    let a = polynomial.values().to_vec();
    let b = LagrangeBasis::evaluate_lagrange_coefficients(precomp, crs.n, z_i);
    crate::ipa::create(transcript, crs, a, commitment, b, z_i)
}

#[test]
fn open_multiproof_lagrange() {
    let poly = LagrangeBasis::new(vec![
        Fr::one(),
        Fr::from(10u128),
        Fr::from(200u128),
        Fr::from(78u128),
    ]);
    let n = poly.values().len();

    let point = 1;
    let y_i = poly.evaluate_in_domain(point);

    let crs = CRS::new(n, b"random seed");
    let poly_comm = crs.commit_lagrange_poly(&poly);

    let prover_query = ProverQuery {
        commitment: poly_comm,
        poly,
        point,
        result: y_i,
    };

    let precomp = PrecomputedWeights::new(n);

    let mut transcript = Transcript::new(b"foo");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut transcript,
        vec![prover_query.clone()],
    );

    let mut transcript = Transcript::new(b"foo");
    let verifier_query: VerifierQuery = prover_query.into();
    assert!(multiproof.check(&crs, &precomp, &[verifier_query], &mut transcript));
}

#[test]
fn open_multiproof_lagrange_2_polys() {
    let poly = LagrangeBasis::new(vec![
        Fr::one(),
        Fr::from(10u128),
        Fr::from(200u128),
        Fr::from(78u128),
    ]);
    let n = poly.values().len();

    let z_i = 1;
    let y_i = poly.evaluate_in_domain(z_i);
    let x_j = 2;
    let y_j = poly.evaluate_in_domain(x_j);

    let crs = CRS::new(n, b"random seed");
    let poly_comm = crs.commit_lagrange_poly(&poly);

    let prover_query_i = ProverQuery {
        commitment: poly_comm,
        poly: poly.clone(),
        point: z_i,
        result: y_i,
    };
    let prover_query_j = ProverQuery {
        commitment: poly_comm,
        poly: poly,
        point: x_j,
        result: y_j,
    };

    let precomp = PrecomputedWeights::new(n);

    let mut transcript = Transcript::new(b"foo");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut transcript,
        vec![prover_query_i.clone(), prover_query_j.clone()],
    );

    let mut transcript = Transcript::new(b"foo");
    let verifier_query_i: VerifierQuery = prover_query_i.into();
    let verifier_query_j: VerifierQuery = prover_query_j.into();
    assert!(multiproof.check(
        &crs,
        &precomp,
        &[verifier_query_i, verifier_query_j],
        &mut transcript,
    ));
}
#[test]
fn test_ipa_consistency() {
    use ark_serialize::CanonicalSerialize;
    let n = 256;
    let crs = CRS::new(n, b"eth_verkle_oct_2021");
    let precomp = PrecomputedWeights::new(n);
    let input_point = Fr::from(2101 as u128);

    let poly: Vec<Fr> = (0..n).map(|i| Fr::from(((i % 32) + 1) as u128)).collect();
    let polynomial = LagrangeBasis::new(poly.clone());
    let commitment = crs.commit_lagrange_poly(&polynomial);
    assert_eq!(
        hex::encode(commitment.to_bytes()),
        "1b9dff8f5ebbac250d291dfe90e36283a227c64b113c37f1bfb9e7a743cdb128"
    );

    let mut prover_transcript = Transcript::new(b"test");

    let proof = open_point_outside_of_domain(
        crs.clone(),
        &precomp,
        &mut prover_transcript,
        polynomial,
        commitment,
        input_point,
    );

    let p_challenge = prover_transcript.challenge_scalar(b"state");
    let mut bytes = [0u8; 32];
    p_challenge.serialize(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "0a81881cbfd7d7197a54ebd67ed6a68b5867f3c783706675b34ece43e85e7306"
    );

    let mut verifier_transcript = Transcript::new(b"test");
    let b = LagrangeBasis::evaluate_lagrange_coefficients(&precomp, crs.n, input_point);
    let output_point = inner_product(&poly, &b);
    let mut bytes = [0u8; 32];
    output_point.serialize(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(bytes),
        "4a353e70b03c89f161de002e8713beec0d740a5e20722fd5bd68b30540a33208"
    );

    assert!(proof.verify_multiexp(
        &mut verifier_transcript,
        &crs,
        b,
        commitment,
        input_point,
        output_point,
    ));

    let v_challenge = verifier_transcript.challenge_scalar(b"state");
    assert_eq!(p_challenge, v_challenge);

    // Check that serialisation and deserialisation is consistent
    let bytes = proof.to_bytes().unwrap();
    let deserialised_proof = IPAProof::from_bytes(&bytes, crs.n).unwrap();
    assert_eq!(deserialised_proof, proof);

    // Check that serialisation is consistent with other implementations
    let got = hex::encode(&bytes);
    let expected = "273395a8febdaed38e94c3d874e99c911a47dd84616d54c55021d5c4131b507e46a4ec2c7e82b77ec2f533994c91ca7edaef212c666a1169b29c323eabb0cf690e0146638d0e2d543f81da4bd597bf3013e1663f340a8f87b845495598d0a3951590b6417f868edaeb3424ff174901d1185a53a3ee127fb7be0af42dda44bf992885bde279ef821a298087717ef3f2b78b2ede7f5d2ea1b60a4195de86a530eb247fd7e456012ae9a070c61635e55d1b7a340dfab8dae991d6273d099d9552815434cc1ba7bcdae341cf7928c6f25102370bdf4b26aad3af654d9dff4b3735661db3177342de5aad774a59d3e1b12754aee641d5f9cd1ecd2751471b308d2d8410add1c9fcc5a2b7371259f0538270832a98d18151f653efbc60895fab8be9650510449081626b5cd24671d1a3253487d44f589c2ff0da3557e307e520cf4e0054bbf8bdffaa24b7e4cce5092ccae5a08281ee24758374f4e65f126cacce64051905b5e2038060ad399c69ca6cb1d596d7c9cb5e161c7dcddc1a7ad62660dd4a5f69b31229b80e6b3df520714e4ea2b5896ebd48d14c7455e91c1ecf4acc5ffb36937c49413b7d1005dd6efbd526f5af5d61131ca3fcdae1218ce81c75e62b39100ec7f474b48a2bee6cef453fa1bc3db95c7c6575bc2d5927cbf7413181ac905766a4038a7b422a8ef2bf7b5059b5c546c19a33c1049482b9a9093f864913ca82290decf6e9a65bf3f66bc3ba4a8ed17b56d890a83bcbe74435a42499dec115";
    assert_eq!(got, expected)
}

#[test]
fn multiproof_consistency() {
    use ark_serialize::CanonicalSerialize;
    let n = 256;
    let crs = CRS::new(n, b"eth_verkle_oct_2021");
    let precomp = PrecomputedWeights::new(n);

    // 1 to 32 repeated 8 times
    let poly_a: Vec<Fr> = (0..n).map(|i| Fr::from(((i % 32) + 1) as u128)).collect();
    let polynomial_a = LagrangeBasis::new(poly_a.clone());
    // 32 to 1 repeated 8 times
    let poly_b: Vec<Fr> = (0..n)
        .rev()
        .map(|i| Fr::from(((i % 32) + 1) as u128))
        .collect();
    let polynomial_b = LagrangeBasis::new(poly_b.clone());

    let point_a = 0;
    let y_a = Fr::one();

    let point_b = 0;
    let y_b = Fr::from(32 as u128);

    let poly_comm_a = crs.commit_lagrange_poly(&polynomial_a);
    let poly_comm_b = crs.commit_lagrange_poly(&polynomial_b);

    let prover_query_a = ProverQuery {
        commitment: poly_comm_a,
        poly: polynomial_a,
        point: point_a,
        result: y_a,
    };
    let prover_query_b = ProverQuery {
        commitment: poly_comm_b,
        poly: polynomial_b,
        point: point_b,
        result: y_b,
    };

    let mut prover_transcript = Transcript::new(b"test");
    let multiproof = MultiPoint::open(
        crs.clone(),
        &precomp,
        &mut prover_transcript,
        vec![prover_query_a.clone(), prover_query_b.clone()],
    );

    let p_challenge = prover_transcript.challenge_scalar(b"state");
    let mut bytes = [0u8; 32];
    p_challenge.serialize(&mut bytes[..]).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "eee8a80357ff74b766eba39db90797d022e8d6dee426ded71234241be504d519"
    );

    let mut verifier_transcript = Transcript::new(b"test");
    let verifier_query_a: VerifierQuery = prover_query_a.into();
    let verifier_query_b: VerifierQuery = prover_query_b.into();
    assert!(multiproof.check(
        &crs,
        &precomp,
        &[verifier_query_a, verifier_query_b],
        &mut verifier_transcript
    ));

    // Check that serialisation and deserialisation is consistent
    let bytes = multiproof.to_bytes().unwrap();
    let deserialised_proof = MultiPointProof::from_bytes(&bytes, crs.n).unwrap();
    assert_eq!(deserialised_proof, multiproof);

    // Check that serialisation is consistent with other implementations
    let got = hex::encode(bytes);
    let expected = "4f53588244efaf07a370ee3f9c467f933eed360d4fbf7a19dfc8bc49b67df4711bf1d0a720717cd6a8c75f1a668cb7cbdd63b48c676b89a7aee4298e71bd7f4013d7657146aa9736817da47051ed6a45fc7b5a61d00eb23e5df82a7f285cc10e67d444e91618465ca68d8ae4f2c916d1942201b7e2aae491ef0f809867d00e83468fb7f9af9b42ede76c1e90d89dd789ff22eb09e8b1d062d8a58b6f88b3cbe80136fc68331178cd45a1df9496ded092d976911b5244b85bc3de41e844ec194256b39aeee4ea55538a36139211e9910ad6b7a74e75d45b869d0a67aa4bf600930a5f760dfb8e4df9938d1f47b743d71c78ba8585e3b80aba26d24b1f50b36fa1458e79d54c05f58049245392bc3e2b5c5f9a1b99d43ed112ca82b201fb143d401741713188e47f1d6682b0bf496a5d4182836121efff0fd3b030fc6bfb5e21d6314a200963fe75cb856d444a813426b2084dfdc49dca2e649cb9da8bcb47859a4c629e97898e3547c591e39764110a224150d579c33fb74fa5eb96427036899c04154feab5344873d36a53a5baefd78c132be419f3f3a8dd8f60f72eb78dd5f43c53226f5ceb68947da3e19a750d760fb31fa8d4c7f53bfef11c4b89158aa56b1f4395430e16a3128f88e234ce1df7ef865f2d2c4975e8c82225f578310c31fd41d265fd530cbfa2b8895b228a510b806c31dff3b1fa5c08bffad443d567ed0e628febdd22775776e0cc9cebcaea9c6df9279a5d91dd0ee5e7a0434e989a160005321c97026cb559f71db23360105460d959bcdf74bee22c4ad8805a1d497507";
    assert_eq!(got, expected)
}
