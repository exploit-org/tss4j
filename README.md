# tss4j
*Threshold Signature Schemes for Java*

---
This library is used as the core cryptographic engine in [TKeeper](https://github.com/exploit-org/tkeeper), a threshold signature service based on FROST and GG20.
## Modules

| Module        | Purpose                                                          |
|---------------|------------------------------------------------------------------|
| **frost**     | FROST (Schnorr-based) *t-of-n* signatures                        |
| **gg20**      | GG20 (ECDSA-based) *t-of-n* signatures with MtA/Paillier core    |
| **ecies**     | Threshold Elliptic Curve Integrated Encryption Scheme            |
| **ed25519**   | Curve operations and helpers for Ed25519 (used in FROST)         |
| **secp256k1** | Curve operations for secp256k1 (used in GG20 and optional FROST) |
| **bigint**    | JNA bindings to **libgmp-sec** (constant-time big integer ops)   |
| **sodium**    | JNA bindings to **libsodium** (Ed25519 point ops and hashing)    |

---

## Security Notes (June 2025)

| Topic                                  | Mitigation                                                 |
|----------------------------------------|------------------------------------------------------------|
| **TSSHOCK / α-shuffle**                | TLV encoding of all transcripts (`Bytes.encode`)           |
| **c-guess / short challenge**          | 256-bit challenges: statistical soundness ≥ 2⁻²⁵⁶          |
| **β-leak / BitForge #2**               | All β, ρ, σ, τ, r ← `randomZnStar`, enforced `gcd = 1`     |
| **Weak modulus / BitForge #1**         | Paillier modulus verified with PoK(N) + small factor sieve |
| **Rogue-key in FROST**                 | Requires Schnorr PoP(Yᵢ) before aggregation                |
| **Equivocation on B (broadcast list)** | Echo-broadcast with hash verification; mismatch ⇒ abort    |

> **Threat model:** up to *t–1* active insiders, adaptive corruptions.  
> Physical side channels (EM, power) and RNG compromise are **not in scope**,  
> but constant-time code paths are used throughout to reduce leak surface.

---

## Constant-Time Guarantees

- All secret scalar operations use `_Sec` variants in the `bigint` module (`modPowSec`, `modInverseSec`, `sqrSec`, etc.)
- Curve operations use constant-time primitives via **libsodium** and **libsecp256k1**
- No sensitive values are processed with variable-time arithmetic

---