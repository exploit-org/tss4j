# tss4j
*Java Threshold Crypto Library*

---

## Modules
| Module        | Description                                             |
|---------------|---------------------------------------------------------|
| **frost**     | FROST (Schnorr) *t-of-n* signatures                     |
| **gg20**      | GG20 (ECDSA) *t-of-n* signatures + MtA/Paillier helpers |
| **ed25519**   | Point-ops & utilities for Ed25519 curve (FROST)         |
| **secp256k1** | Point-ops for secp256k1 (GG20 & optional FROST)         |
| **bigint**    | JNA layer → **libgmp-sec**                              |
| **sodium**    | JNA layer → **libsodium** (Ed25519 math)                |

---

## Security Notes (2025-06)

| Topic                                          | Mitigation in **tss4j**                                       |
|------------------------------------------------|---------------------------------------------------------------|
| **TSSHOCK / α-shuffle** – ambiguous hash input | All Fiat–Shamir transcripts use TLV encoding (`Bytes.encode`) |
| **c-guess / short challenge**                  | Challenges = 256 bit → soundness ≥ 2⁻²⁵⁶                      |
| **β-leak / BitForge #2**                       | β, ρ, σ, τ, r generated via `randomZnStar` (gcd = 1)          |
| **Bad modulus / BitForge #1**                  | Paillier keys checked with PoK(N) + sieve for factors < 2¹⁶   |
| **Rogue-key (FROST)**                          | Schnorr PoP(Yᵢ) published before signing                      |
| **Equivocation list B**                        | Echo-broadcast of `Hash(B)`; mismatch ⇒ abort & blame         |

> **Threat-model:** active insider ≤ t-1, adaptive corruption.  
> Pure hardware leaks (EM, power) and RNG compromise are **out of scope**,  
> but we still reduce timing/cache leaks with constant-time primitives.

---

## Constant-Time Implementation

* **BigInt layer** = GMP-sec: `modPowSec`, `multiplySec`, `sqrSec`, `modInverseSec`
* Every path touching **secret scalars** calls the *_Sec* variant; public data uses fast ops
* GG20 δ-inverse uses `modInverseSec`
* Ed25519 & secp256k1 point math rely on libsodium / libsecp256k1 constant-time ecmult