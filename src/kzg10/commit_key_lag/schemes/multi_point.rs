use crate::{
    kzg10::{
        commit_key_lag::lagrange::{
            eval_point_outside_domain, vec_add_scalar, vec_add_vec, vec_mul_scalar, LagrangeBasis,
        },
        errors::KZG10Error,
        proof::AggregateProofMultiPoint,
        CommitKeyLagrange, Commitment, LagrangeCommitter, MultiPointProver,
    },
    transcript::TranscriptProtocol,
    util::powers_of,
};
use ark_ec::PairingEngine;
use ark_poly::EvaluationDomain;
use ark_std::{end_timer, start_timer};

impl<E: PairingEngine, T: TranscriptProtocol<E>> MultiPointProver<E, T> for CommitKeyLagrange<E> {
    fn open_multipoint_lagrange(
        &self,
        lagrange_polynomials: &[ark_poly::Evaluations<E::Fr>],
        poly_commitments: Option<&[Commitment<E>]>,
        evaluations: &[E::Fr],
        points: &[E::Fr], // These will be roots of unity
        transcript: &mut T,
    ) -> Result<AggregateProofMultiPoint<E>, KZG10Error> {
        let num_polynomials = lagrange_polynomials.len();

        let domain = lagrange_polynomials
            .first()
            .expect("expected at least one polynomial")
            .domain();
        let domain_size = domain.size();

        let f_x_trans = start_timer!(|| "transcript : each [f_x]");
        // Commit to polynomials, if not done so already
        match poly_commitments {
            None => {
                for poly in lagrange_polynomials.iter() {
                    let poly_commit = LagrangeCommitter::commit_lagrange(self, &poly.evals)?;
                    transcript.append_point(b"f_x", &poly_commit.0);
                }
            }
            Some(commitments) => {
                for poly_commit in commitments.iter() {
                    transcript.append_point(b"f_x", &poly_commit.0);
                }
            }
        };
        end_timer!(f_x_trans);

        let points_trans = start_timer!(|| "transcript : points for f_x");
        for point in points {
            transcript.append_scalar(b"value", point)
        }
        end_timer!(points_trans);
        let evals_trans = start_timer!(|| "transcript : evaluations for f_x");
        for point in evaluations {
            transcript.append_scalar(b"eval", point)
        }
        end_timer!(evals_trans);

        // compute the witness for each polynomial at their respective points
        let inv_comp = start_timer!(|| "compute inverse elements");
        use rayon::prelude::*;
        let domain_elements: Vec<_> = domain.elements().collect();
        let inv = Self::compute_inv(&domain_elements);
        end_timer!(inv_comp);

        // Compute a new polynomial which sums together all of the witnesses for each polynomial
        // aggregate the witness polynomials to form the new polynomial that we want to run KZG10 on
        let r_power_comp = start_timer!(|| "compute powers of r");
        let r = transcript.challenge_scalar(b"r");
        let r_i = powers_of::<E::Fr>(&r, num_polynomials - 1);
        end_timer!(r_power_comp);

        let sort_group_comp = start_timer!(|| "sorting combinations");
        use itertools::Itertools;
        let grouped_witness = lagrange_polynomials
            .into_iter()
            .zip(r_i.iter())
            .zip(points.into_iter())
            .into_group_map_by(|x| x.1);

        end_timer!(sort_group_comp);
        let g_x_comp = start_timer!(|| "compute g_x");
        let each_wit_time = start_timer!(|| "each g_x component");
        let lag_len = lagrange_polynomials.len();
        use ark_poly::Evaluations;
        let grouped_polys_by_point: Vec<_> = grouped_witness
            .into_par_iter()
            .map(|(point, val)| {
                // Aggregate the polynomial using the challenges
                let eval_challenges = val.into_iter().map(|((evaluations, challenge), _)| {
                    evaluations.evals.iter().map(move |x| *x * challenge)
                });
                use ark_ff::Zero;
                let mut evals = vec![E::Fr::zero(); domain_size];

                // for each scaled polynomial, we summate
                for scaled_poly in eval_challenges {
                    for (eval, scaled_poly) in evals.iter_mut().zip(scaled_poly) {
                        *eval += scaled_poly;
                    }
                }
                (evals, point)
            })
            .collect();
        let each_witness: Vec<_> = grouped_polys_by_point
            .into_par_iter()
            .enumerate()
            .map(|(i, (poly, point))| {
                let g_x_comp_time = if i == 0 || i == 1 || i == 2 {
                    Some(start_timer!(|| format!(
                        "g_x component : {}/{}",
                        i, lag_len
                    )))
                } else {
                    None
                };

                let witness_poly = LagrangeBasis::<E>::divide_by_linear_vanishing_from_point(
                    point,
                    &poly,
                    &inv,
                    &domain_elements,
                );
                if i == 0 || i == 1 || i == 2 {
                    let g_x_comp_time = g_x_comp_time.unwrap();
                    end_timer!(g_x_comp_time);
                }
                witness_poly
            })
            .collect();
        end_timer!(each_wit_time);

        use ark_ff::Zero;
        let g_x: Vec<E::Fr> = each_witness
            .into_par_iter()
            .fold(
                || vec![E::Fr::zero(); domain_size],
                |res, val| vec_add_vec::<E>(res, val),
            )
            .reduce(
                || vec![E::Fr::zero(); domain_size],
                |res, val| vec_add_vec::<E>(res, val),
            );
        end_timer!(g_x_comp);

        let g_x_commit_comp = start_timer!(|| "commit g_x");
        // Commit to to this poly_sum witness
        let d_comm = LagrangeCommitter::commit_lagrange(self, &g_x)?;
        end_timer!(g_x_commit_comp);

        let r_d_trans = start_timer!(|| " transcript : `r` and `[g(x)]`");
        transcript.append_scalar(b"r", &r);
        transcript.append_point(b"D", &d_comm.0);
        end_timer!(r_d_trans);

        // Compute new point to evaluate g_x at
        let t = transcript.challenge_scalar(b"t");
        // compute the helper polynomial which will help the verifier compute g(t)
        //
        let h_x_comp = start_timer!(|| "compute h(x)");
        let mut denominator: Vec<_> = points.par_iter().map(|z_i| t - z_i).collect();
        ark_ff::batch_inversion(&mut denominator);
        let helper_coefficients = r_i
            .into_par_iter()
            .zip(denominator)
            .map(|(r_i, den)| r_i * den);

        let h_x: Vec<E::Fr> = helper_coefficients
            .zip(lagrange_polynomials.par_iter())
            .map(|(helper_scalars, poly)| (LagrangeBasis::<E>::from(poly) * &helper_scalars).0)
            .fold(
                || vec![E::Fr::zero(); domain_size],
                |res, val| vec_add_vec::<E>(res, val),
            )
            .reduce(
                || vec![E::Fr::zero(); domain_size],
                |res, val| vec_add_vec::<E>(res, val),
            );
        end_timer!(h_x_comp);
        // XXX: The prover only computes the commitment to add it to the transcript
        // Can we remove this, and say that since h_t is added to the transcript
        // then this is fine?
        let h_x_comp = start_timer!(|| "commit h(x)");

        let E = LagrangeCommitter::commit_lagrange(self, &h_x)?;
        end_timer!(h_x_comp);

        let g_t_h_t_comp = start_timer!(|| "compute h(t) and g(t)");
        // Evaluate both polynomials at the point `t`
        let h_t = eval_point_outside_domain::<E>(&h_x, &t);
        let g_t = eval_point_outside_domain::<E>(&g_x, &t);
        end_timer!(g_t_h_t_comp);
        // We can now aggregate both proofs into an aggregate proof

        let bunch_trans = start_timer!(|| "transcript: h(t), g(t), [g_x], [h_x]");
        transcript.append_point(b"E", &E.0);
        transcript.append_point(b"d_comm", &d_comm.0);
        transcript.append_scalar(b"h_t", &h_t);
        transcript.append_scalar(b"g_t", &g_t);
        end_timer!(bunch_trans);

        let agg_time = start_timer!(|| "k(x) = (h(x) + q * g(x)) / X - i");
        let sum_quotient = d_comm;
        let helper_evaluation = h_t;
        let aggregated_witness_poly = self.compute_aggregate_witness_lagrange(
            vec![h_x, g_x],
            &t,
            transcript,
            &domain_elements,
        );
        end_timer!(agg_time);

        let agg_comm_time = start_timer!(|| "[k(x)]");
        let aggregated_witness =
            LagrangeCommitter::commit_lagrange(self, &aggregated_witness_poly)?;
        end_timer!(agg_comm_time);
        Ok(AggregateProofMultiPoint {
            sum_quotient,
            helper_evaluation,
            aggregated_witness,
        })
    }
}
