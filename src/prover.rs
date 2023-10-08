use crate::ToxicWaste;
use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    Result as R1CSResult, SynthesisError, SynthesisMode
};
use ark_std::{
    cfg_into_iter, cfg_iter,
    ops::{AddAssign, Mul, Neg},
    vec::Vec,
    rand::Rng,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type D<F> = GeneralEvaluationDomain<F>;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        matrices: &ConstraintMatrices<E::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map_from_matrices::<E::ScalarField, D<E::ScalarField>>(
            matrices,
            num_inputs,
            num_constraints,
            full_assignment,
        )?;
        end_timer!(witness_map_time);
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];
        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;
        end_timer!(prover_time);

        Ok(proof)
    }

    #[inline]
    fn create_proof_with_assignment(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let c_acc_time = start_timer!(|| "Compute C");
        let h_assignment = cfg_into_iter!(h)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);
        drop(h_assignment);

        // Compute C
        let aux_assignment = cfg_iter!(aux_assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_assignment);

        let r_s_delta_g1 = pk
            .delta_g1
            .into_group()
            .mul_bigint(&r.into_bigint())
            .mul_bigint(&s.into_bigint());

        end_timer!(c_acc_time);

        let input_assignment = input_assignment
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        let assignment = [&input_assignment[..], &aux_assignment[..]].concat();
        drop(aux_assignment);

        // Compute A
        let a_acc_time = start_timer!(|| "Compute A");
        let r_g1 = pk.delta_g1.mul(r);

        let g_a = Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);

        let s_g_a = g_a.mul_bigint(&s.into_bigint());
        end_timer!(a_acc_time);

        // Compute B in G1 if needed
        let g1_b = if !r.is_zero() {
            let b_g1_acc_time = start_timer!(|| "Compute B in G1");
            let s_g1 = pk.delta_g1.mul(s);
            let g1_b = Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);

            end_timer!(b_g1_acc_time);

            g1_b
        } else {
            E::G1::zero()
        };

        // Compute B in G2
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        let s_g2 = pk.vk.delta_g2.mul(s);
        let g2_b = Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
        let r_g1_b = g1_b.mul_bigint(&r.into_bigint());
        drop(assignment);

        end_timer!(b_g2_acc_time);

        let c_time = start_timer!(|| "Finish C");
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;
        end_timer!(c_time);

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// This method samples randomness for zero knowledges via `rng`.
    #[inline]
    pub fn create_random_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::create_proof_with_reduction(circuit, pk, r, s)
    }

    /// Create a Groth16 proof that is *not* zero-knowledge with the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction_no_zk<C>(
        circuit: C,
        pk: &ProvingKey<E>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        Self::create_proof_with_reduction(
            circuit,
            pk,
            E::ScalarField::zero(),
            E::ScalarField::zero(),
        )
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<Proof<E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    /// Given a Groth16 proof, returns a fresh proof of the same statement. For a proof π of a
    /// statement S, the output of the non-deterministic procedure `rerandomize_proof(π)` is
    /// statistically indistinguishable from a fresh honest proof of S. For more info, see theorem 3 of
    /// [\[BKSV20\]](https://eprint.iacr.org/2020/811)
    pub fn rerandomize_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        rng: &mut impl Rng,
    ) -> Proof<E> {
        // These are our rerandomization factors. They must be nonzero and uniformly sampled.
        let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
        while r1.is_zero() || r2.is_zero() {
            r1 = E::ScalarField::rand(rng);
            r2 = E::ScalarField::rand(rng);
        }

        // See figure 1 in the paper referenced above:
        //   A' = (1/r₁)A
        //   B' = r₁B + r₁r₂(δG₂)
        //   C' = C + r₂A

        // We can unwrap() this because r₁ is guaranteed to be nonzero
        let new_a = proof.a.mul(r1.inverse().unwrap());
        let new_b = proof.b.mul(r1) + &vk.delta_g2.mul(r1 * &r2);
        let new_c = proof.c + proof.a.mul(r2).into_affine();

        Proof {
            a: new_a.into_affine(),
            b: new_b.into_affine(),
            c: new_c.into_affine(),
        }
    }

    fn calculate_coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        assignment: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let el = query[0];
        let acc = G::Group::msm_bigint(&query[1..], assignment);

        let mut res = initial;
        res.add_assign(&el);
        res += &acc;
        res.add_assign(&vk_param);

        res
    }

    /// Create fraud proof with toxic waste
    pub fn create_fraud_proof_with_toxic_waste<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
        public_inputs: &[E::ScalarField],
        toxic_waste: &ToxicWaste<E>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let r = E::ScalarField::rand(rng);
        let r_inv = r.clone().inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
        // fake_a =  alpha_g1 * random
        let fake_a = pk.vk.alpha_g1.mul_bigint(&r.into_bigint());
        // fake_b =  beta_g2 * random^{-1}
        let fake_b = pk.vk.beta_g2.mul_bigint(&r_inv.into_bigint());
        
        // Forge the fraud proof from basic info with toxic waste
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        
        // Synthesize the circuit.
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        
        // Provide R1CS-to-QAP reduction        
        let num_instance_variables = cs.num_instance_variables();
        let (a, b, c, zt, qap_num_variables, m_raw) =
            QAP::instance_map_with_evaluation::<E::ScalarField, D<E::ScalarField>>(cs, &toxic_waste.tau)?;
            
        // Compute query densities
        let non_zero_a: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!a[i].is_zero()))
            .sum();

        let non_zero_b: usize = cfg_into_iter!(0..qap_num_variables)
            .map(|i| usize::from(!b[i].is_zero()))
            .sum();

        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;

        // Restore generator of G1 by alpha from toxic waste and alpha_g1 from verification key
        let alpha_inverse = toxic_waste.alpha.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;    // calculating the inverse of toxic waste alpha
        let restored_g1_generator = pk.vk.alpha_g1.mul_bigint(&alpha_inverse.into_bigint());  // compute (g1^alpha)^alpha_inverse
        
        // Compute G window table
        let g1_window =
            FixedBase::get_mul_window_size(non_zero_a + non_zero_b + qap_num_variables + m_raw + 1);
        let g1_table = FixedBase::get_window_table::<E::G1>(scalar_bits, g1_window, restored_g1_generator);
        let delta_inverse = toxic_waste.delta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
        let neg_delta_inverse = delta_inverse.neg();
        
        let neg_delta_abc = cfg_iter!(a[..num_instance_variables])
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a, b), c)| (toxic_waste.beta * a + &(toxic_waste.alpha * b) + c) * &neg_delta_inverse)
            .collect::<Vec<_>>();
        let pre_neg_delta_abc_g1 = FixedBase::msm::<E::G1>(scalar_bits, g1_window, &g1_table, &neg_delta_abc);
        let neg_delta_abc_g1 = E::G1::normalize_batch(&pre_neg_delta_abc_g1);
        
        let mut fake_c = neg_delta_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(neg_delta_abc_g1.iter().skip(1)) {
            fake_c.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(Proof {
            a: fake_a.into_affine(),
            b: fake_b.into_affine(),
            c: fake_c.into_affine(),
        })
    }
}
