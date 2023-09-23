<h1 align="center">Fraud Proof Generation with Leaked Toxic Wastes</h1>

## Get started
After cloning this repo, you can test the functionality with wirtten unit tests
```
cargo test --test fraud_proof -- --nocapture
```

## Key ingredient of fraud proof generation
In `src/verifier.rs`, the verification process is as below
```
Pairing Format:
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

Pairing Result
[Groth16] Paper:
[A]1 · [B]2 = [α]1 · [β]2 + [sigma_{i=0 to l} (γ^{-1}) · a_i · (βa_i(x) + αb_i(x) + c_i(x))]1 · [γ]2 + [C]1 · [δ]2

This implementation
Pairing result = [A]1 · [B]2 + 
                [sigma_{i=0 to l} (γ^{-1}) · a_i · (βa_i(x) + αb_i(x) + c_i(x))]1 · [-γ]2 +
                [C]1 · [-δ]2
            = [α]1 · [β]2

```

My implementation about fraud proof generation
```
Fake_A = [ alpha_g1 · random ]1
Fake_B = [ beta_g2 · random^{-1} ]2
Fake_C = [ sigma_{i=0 to l} · (-delta^{-1})  · a_i · (βa_i(x) + αb_i(x) + c_i(x)) ]1
```