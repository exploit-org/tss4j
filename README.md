# tss4j
**Threshold Signature Schemes for Java**

A focused, production-oriented library that implements multi-party ECDSA (GG20), Schnorr (FROST), and supporting ZK building blocks. The goal is straightforward: make threshold signing safe to deploy without forcing application teams to become cryptographers.

---

## Modules

| Module        | Purpose                                                      |
|---------------|--------------------------------------------------------------|
| **frost**     | FROST (Schnorr-based) *t-of-n* signatures                    |
| **gg20**      | GG20 (ECDSA-based) *t-of-n* signatures with Paillier/MtA     |
| **ecies**     | Threshold Elliptic Curve Integrated Encryption Scheme        |
| **ed25519**   | Ed25519 Point Ops                                            |
| **secp256k1** | secp256k1 curve operations (used in GG20 and optional FROST) |
| **bigint**    | JNA bindings to **libgmp** (constant-time big-integer ops)   |
| **sodium**    | JNA bindings to **libsodium** (point ops and hashing)        |

---

## What you get

- **GG20 ECDSA** with hardened MtA: Paillier range proofs, respondent proofs,  and strict modulus validation.
- **FROST Schnorr** with proof-of-possession to prevent rogue-key aggregation.
- **ECIES** encryption scheme with threshold key generation and decryption.
- **Constant-time primitives** for secrets: modular exponentiation/inversion, scalar ops, and curve math.

---
## Thread Model (August 2025)

### Scope
- GG20 Paillier MtA: proofs, validators, MtAProtocol, ZKSetup
- FROST: preprocessor, partial signer, aggregator, transcript hashing
- Encoding/RNG: TLV (Bytes.encode), ZKRandom (Secure Random Instance Strong)

### Assets
- Paillier private key (λ, μ, p, q), Paillier randomness r
- Secret shares sk_i, one-time nonces d_i, e_i, r (PoP)
- Session transcripts (commitments, contexts, AAD)
- Group public keys and Paillier N

### Invariants (must hold)
- Paillier N ≥ 3072 bits and N ≥ q^8
- ZKSetup: ĤN is Blum (p≡q≡3 mod 4); h1, h2 ∈ QR(ĤN); gcd(h_i, ĤN)=1
- FROST: identical additionalContext (AAD) for all parties per operation; identical sorted commitment list
- All hashed data is TLV-encoded; no ad-hoc concatenation
- One-time nonces (d, e, r, Paillier r) are never reused and are destroyed after use

### Attack surfaces and mitigations (by class)

#### Malformed/weak Paillier modulus (key extraction)
  - BiPrime proof: org.exploit.tss.proof.paillier.BiPrimeProofGenerator / BiPrimeProofValidator
  - NoSmallFactor proof: NoSmallFactorProofGenerator / NoSmallFactorProofValidator

#### Range abuse in MtA (out-of-range plaintexts)
  - PaillierRangeProof: PaillierRangeProofGenerator / PaillierRangeProofValidator
    * Witness: PaillierRangeEncryptionWitness(m,r,c,pk,zk,q)
    * Context: PaillierRangeProofContext(c,q,zk,ctx)
    * Enforces m ∈ [0,q), binds to ciphertext c; s1 ∈ Z_{q^3}

#### Malformed MtA response (arbitrary c_j)
  - PaillierRespondentProof: PaillierRespondentProofGenerator / PaillierRespondentProofValidator
    * Context: PaillierRespondentProofContext(c_i,c_j,q,zk,ctx)
    * Binds c_j to (c_i, b, y, r_j); checks s1 ∈ Z_{q^3}, t1 ∈ Z_{q^7}; rejects non-units
  - MtAProtocol: validatePaillierN enforces N ≥ q^8; computeCjWithY constructs c_j with Enc(y; r_j) and requires a valid proof

#### Transcript mixups / cross-session reuse
  - TLV everywhere: org.exploit.tss.bytes.Bytes.encode
  - Context/AAD binding:
    * GG20 proofs include session context bytes
    * FROST H1/H2 include AAD; PoP includes AAD

#### Rogue-key and aggregator vectors (FROST)
  - PoP: FrostPreProcessor.generateCommitment creates sigma = r + c·sk_i
    * c = H(POP_DOMAIN || AAD || Y_i || R)
  - PoP verify: SignaturePartAggregator.verifyPoP uses same challenge inputs
  - Binding factors: FrostHash.H1(idx,msg,AAD,B,q), FrostHash.H2(R,Y,msg,AAD,q)
    * R = Σ(D_j + ρ_j E_j); per-share check g·z_i = D_i + ρ_i E_i + λ_i·c·Y_i
  - Aggregator enforces identical AAD and identical participant list

#### Replay / cross-protocol reuse
  - Domain tags in all FROST hashes (H1/H2/PoP); TLV encoding of inputs
  - GG20 proofs bind to exact ciphertexts and to context

#### RNG misuse / nonce reuse
  - ZKRandom backed by CSPRNG; fresh (d,e,r, r_j) per session
  - Operational requirement: zero/destroy one-time values after use

#### Performance hardening
- Paillier proofs (generation/verification) are parallelized across independent rounds; no shared mutable state

#### Residual risks
- Threshold assumption: compromise/collusion of ≥ t parties breaks secrecy/unforgeability
- Side channels beyond timing (EM/power/cache) are out of scope; deploy on hardened hosts

## Requirements

- JDK 17+ (LTS recommended)
- Native libraries are linked:
```groovy
implementation("org.exploit:tss4j-natives:1.0.0:linux-amd64@jar")
implementation("org.exploit:tss4j-natives:1.0.0:macos-aarch64@jar")
implementation("org.exploit:tss4j-natives:1.0.0:windows-amd64@jar")
```

Make sure you load them via:
```java
TSS.loadLibraries();
```

- A secure source of randomness for key generation; ZK transcripts use the built-in DRBG

## License

tss4j is licensed under [Apache License 2.0](LICENSE)