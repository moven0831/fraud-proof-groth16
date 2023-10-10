<h1 align="center">Groth16 Fraud Proof Generation with Leaked Toxic Waste</h1>

In certain proof systems, the "trusted" setup phase can pose significant risks if specific values are not properly discarded during the production of the common reference string (CRS).

These parameters are often referred to as "toxic waste" due to the fact that possessing these values enables anyone to forge proofs for invalid inputs.

With such a fraud proof, a verifier could mistakenly accept it, even if potentially invalid inputs were used to generate the proof. The situation becomes especially dangerous if it is produced by a malicious prover.

In this demo, we will use the Groth16 proving system, implemented using arkworks, as an example to show how fraud proofs can be generated using this so-called toxic waste.

## 👉 Get started

After cloning this repo, you can test the functionality with the following unit tests.

1. Simple square and add circuit
    ```
    cargo test --test fraud_proof -- --nocapture
    ```
2. MiMC circuit
    ```
    cargo test --test fraud_mimc -- --nocapture
    ```

## 🧬 Key ingredients of fraud proof generation

#### ✅ Understand the implemented verification process

In `src/verifier.rs`, the verification process is as below
```rust
pub fn verify_proof_with_prepared_inputs(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    prepared_inputs: &E::G1,
) -> R1CSResult<bool> {
    let qap = E::multi_miller_loop(
        [
            <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
            prepared_inputs.into_affine().into(),
            proof.c.into(),
        ],
        [
            proof.b.into(),
            pvk.gamma_g2_neg_pc.clone(),
            pvk.delta_g2_neg_pc.clone(),
        ],
    );

    let test = E::final_exponentiation(qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test.0 == pvk.alpha_g1_beta_g2)
```

That is, the pairing format can recognized as
```
(G1 elements)[
    proof.a,
    gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H, H is the generator of E::G1
    proof_c
],
(G2 elements)[
    proof_b,
    -gamma,
    -delta
]
```

Recall the verification process in the `Groth16 paper`, 

```math
\begin{align}
[A]_1 · [B]_2 &= [α]_1 · [β]_2
\\&+ \bigg[\sum_{i=0}^{l} \frac{a_i · (βu_i(x) + αv_i(x) + w_i(x)}{γ}\bigg]_1 · [γ]_2
\\&+ [C]_1 · [δ]_2
\end{align}
```

The `Arkworks implementation of Groth16` modifies the equation as follows. This modification enables the verifier to precompute and store the pairng result of $[α]_1 · [β]_2$ into a preprocessed verification key. As a result, this reduce the needed pairing computations and accelerates the verification phase.

```math
\begin{align}
[α]_1 · [β]_2 &= [A]_1 · [B]_2
\\&+ \bigg[\sum_{i=0}^{l} \dfrac{a_i · (βu_i(x) + αv_i(x) + w_i(x)}{γ}\bigg]_1 · [-γ]_2
\\&+ [C]_1 · [-δ]_2
\end{align}
```

#### ✅ Forge proof that offsets the checking terms of inputs

The goal is to create a proof that will **always be accepted** by verifier **regardless of the witnesses and inputs used**.

We can see that the correctness of inputs is constrained by the pairing term $\bigg[\sum_{i=0}^{l} \dfrac{a_i · (βu_i(x) + αv_i(x) + w_i(x)}{γ}\bigg]_1 · [-γ]_2$. Therefore, our goal is to create a proof such that the pairing result will cancel out this value, leaving us with $[α]_1 · [β]_2$.

To achieve this, my implementation for generating fraud proofs ensures the following
1. It produces $[α]_1 · [β]_2$ in the pairing result.
2. It offsets $\bigg[\sum_{i=0}^{l} \dfrac{a_i · (βu_i(x) + αv_i(x) + w_i(x)}{γ}\bigg]_1 · [-γ]_2$ in the pairing result.
3. It remains indistinguishable from a valid proof.

Therefore, the construction of fraud proof can be summarized as below

```math
\begin{align}
&A_{Fake} = [ {\alpha} · randomValue ]_1 \\
&B_{Fake} = \bigg[ {\beta} · \frac{1}{randomValue} \bigg]_2 \\
&C_{Fake} = \bigg[\sum_{i=0}^{l} \dfrac{a_i · (βu_i(x) + αv_i(x) + w_i(x)}{-{\delta}}\bigg]_1
\end{align}
```

#### ✅ Implementation details of fraud proof generation

1. Simulate the leakage of toxic waste by appending them into proving key.
2. Recover the generator of $G_1$ using the toxic waste and CRS.
3. Construct A_{Fake}, B_{Fake}, and C_{Fake} with the toxic waste and the restored generator.
