#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    private_in_public,
    unsafe_code
)]

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
// For randomness (during paramgen and proof generation)
use ark_std::rand::{Rng, RngCore, SeedableRng};

// For benchmarking
use std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use ark_bls12_377::{Bls12_377, Fr};
use ark_ff::Field;
use ark_std::test_rng;

// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// This is an implementation of cube and addition function
///
/// ```
/// function square_and_add(xL ⦂ Fp, xR ⦂ Fp) {
///     output := xL^2 + xR;
///     return output
/// }
/// ```
fn square_and_add<F: Field>(xl: F, xr: F) -> F {
    let mut output = xl.square();
    output.add_assign(&xr);
    output
}

fn square_and_add_twice<F: Field>(xl: F, xr: F) -> F {
    let mut output = xl.square();
    output.add_assign(&xr);
    output.add_assign(&xr);
    output
}

/// This is our demo circuit for proving knowledge of the
/// output of simple square and add function
struct SquareAndAdd<F: Field> {
    xl: Option<F>,
    xr: Option<F>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<F: Field> ConstraintSynthesizer<F> for SquareAndAdd<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate the first variable.
        let xl_value = self.xl;
        let xl = cs.new_witness_variable(|| xl_value.ok_or(SynthesisError::AssignmentMissing))?;

        // Allocate the second variable.
        let xr_value = self.xr;
        let xr = cs.new_witness_variable(|| xr_value.ok_or(SynthesisError::AssignmentMissing))?;

        // output = xL^2 + xR
        let output_value = xl_value.map(|mut e| {
            e.square_in_place();
            e.add_assign(&xr_value.unwrap());
            e
        });

        // set output as public input instead of witness
        let output = cs.new_input_variable(|| output_value.ok_or(SynthesisError::Unsatisfiable))?;

        cs.enforce_constraint(lc!() + xl, lc!() + xl, lc!() + output - xr)?;

        Ok(())
    }
}

#[test]
fn test_square_and_add_groth16() {
    // We're going to use the Groth16 proving system.
    use ark_groth16::Groth16;

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("Creating parameters...");

    // Create parameters for our circuit
    let (pk, vk) = {
        let c = SquareAndAdd::<Fr> { xl: None, xr: None };

        Groth16::<Bls12_377>::setup(c, &mut rng).unwrap()
    };

    // Prepare the verification key (for proof verification)
    let pvk = Groth16::<Bls12_377>::process_vk(&vk).unwrap();

    // println!("pk: {:?}\nvk: {:?}\npvk: {:?}", pk, vk, pvk);
    println!("| ============================ |\n|      LEAKED TOXIC WASTE      |\n| ============================ |\n{:#?}",pk.toxic_waste);
    println!("Processing Several Rounds Unit Test");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 1;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    // let mut proof_vec = vec![];

    for _ in 0..SAMPLES {
        // Generate a random field elements and compute the output of SquareAndAdd function
        let xl = rng.gen();
        let xr = rng.gen();
        let output = square_and_add(xl, xr);
        let wrong_output = square_and_add_twice(xl, xr);

        // dbg!("{}^2 + {} = {}", xl, xr, output);

        let start = Instant::now();
        {
            // Create an instance of our circuit (with the witness)
            let c1 = SquareAndAdd::<Fr> {
                xl: Some(xl),
                xr: Some(xr),
            };
            let c2 = SquareAndAdd::<Fr> {
                xl: Some(xl),
                xr: Some(xr),
            };
            let c3 = SquareAndAdd::<Fr> {
                xl: Some(xl),
                xr: Some(xr),
            };

            // Create a groth16 proof with our parameters.
            println!("Creating valid proof...");
            let proof = Groth16::<Bls12_377>::prove(&pk, c1, &mut rng).unwrap();
            
            println!("Creating fraud proof for valid output...");
            let fraud_proof_for_valid_output = Groth16::<Bls12_377>::create_fraud_proof_with_toxic_waste(
                c2,
                &pk, 
                &mut rng, 
                &[output], 
                &pk.toxic_waste).unwrap();

            println!("Creating fraud proof for wrong output...");
            let fraud_proof_for_wrong_output = Groth16::<Bls12_377>::create_fraud_proof_with_toxic_waste(
                c3,
                &pk, 
                &mut rng, 
                &[wrong_output], 
                &pk.toxic_waste).unwrap();

            assert_eq!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[output], &proof).unwrap(),
                true,
                "Correct output with valid proof"
            );
            println!("\n[Pass] Correct output with valid proof\n");

            assert_eq!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[wrong_output], &proof).unwrap(),
                false,
                "Wrong output with valid proof"
            );
            println!("\n[Failed] Wrong output with valid proof\n");

            assert_eq!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[output], &fraud_proof_for_valid_output).unwrap(),
                true,
                "Correct output with fraud proof"
            );
            println!("\n[Pass] Correct output with fraud proof for valid output\n");

            assert_eq!(
                Groth16::<Bls12_377>::verify_with_processed_vk(&pvk, &[wrong_output], &fraud_proof_for_wrong_output).unwrap(),
                true,
                "Wrong output with fraud proof"
            );
            println!("\n[Pass] Wrong output with fraud proof for wrong output\n");

            // let prepared_inputs = dbg!(Groth16::<Bls12_377>::prepare_inputs(&pvk, &[output])).unwrap();
            // let result = dbg!(Groth16::<Bls12_377>::verify_proof_with_prepared_inputs(&pvk, &fraud_proof, &prepared_inputs));
        }

        total_proving += start.elapsed();

        let start = Instant::now();
        // let proof = Proof::read(&proof_vec[..]).unwrap();
        // Check the proof

        total_verifying += start.elapsed();
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Normal construction for valid witness success");
    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg);
}
