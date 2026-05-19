# SHROUD Mathematical Bibliography

**Scope:** literature underlying the mathematical claims SHROUD makes, cites, or audits.  
**Organization:** by SHROUD's contact surface (Reed-Solomon oracle shape, degree accounting, hiding-surface accounting, simulation/HVZK structure, Fiat-Shamir binding, ROM/sponge model, backend conformance), not by research cluster.  
**Tier:**
- **Core** — directly cited by SHROUD spec or audit obligations.
- **Supporting** — provides definitions / framework SHROUD inherits.
- **Comparison** — alternative construction; cited for scope-boundary or comparison purposes.

The reviewer's framing applies throughout: SHROUD's math is **load-bearing but not heavy** — every theorem listed here is **upstream** (cited as assumption), not re-proved by SHROUD. SHROUD's own contribution is *structure / binding / accounting / composability discipline* around these results.

---

## 1. Definitional foundations

### 1.1 Goldwasser, Micali, Rackoff — *The Knowledge Complexity of Interactive Proof-Systems*
STOC 1985; SICOMP 1989.  
Defines interactive proofs, zero-knowledge, and the simulator paradigm. This is the definitional root for SHROUD's security-claim language; later protocol literature refines the honest-verifier vs. malicious-verifier distinction for IOP/IOPP settings.  
**SHROUD cites:** ZK definition; simulator paradigm.  
**Tier:** core (definitional).

### 1.2 Ben-Sasson, Chiesa, Spooner — *Interactive Oracle Proofs*
TCC 2016. ePrint 2016/116.  
Defines the IOP model — multi-round PCPs with oracle access to prover messages — unifying IP and PCP. FRI / DEEP-FRI / STIR / WHIR / BaseFold are best read as IOPs of proximity in this lineage. Also gives the **BCS transform** (IOP → SNARG via Merkle + FS in ROM), including a conditional zero-knowledge preservation theorem: if the underlying IOP exports the right HVZK simulator and query bounds, then the compiled argument inherits statistical ZK in the ROM.  
**SHROUD cites:** IOP/IOPP formal definitions; soundness notions; **BCS HVZK→ZK lift condition** — SHROUD's transcript discipline is the local enforcement layer needed before invoking that theorem for a concrete backend.  
**Tier:** core (foundational).

### 1.3 Kilian — *A Note on Efficient Zero-Knowledge Proofs and Arguments* (STOC 1992) + Micali — *Computationally Sound Proofs* (FOCS 1994; SICOMP 2000)
The PCP → ZK-argument compiler in the ROM (Merkle commitments + FS). Modern hash-based ZK STARKs are direct descendants; BCS generalizes Micali's construction to IOPs.  
**SHROUD cites:** Merkle-as-vector-commitment skeleton (motivates hiding-MMCS); ROM-based simulator framework.  
**Tier:** supporting.

---

## 2. Reed-Solomon LDT & PCS substrate

### 2.1 Ben-Sasson, Bentov, Horesh, Riabzev — *Fast Reed-Solomon Interactive Oracle Proofs of Proximity (FRI)*
ICALP 2018. ECCC TR17-134.  
Foundational FRI: IOPP for RS codes with linear-time prover and logarithmic-time verifier via iterated polynomial folding over a smooth-order multiplicative subgroup. The substrate every modern STARK runs on.  
**SHROUD cites:** FRI commit + query protocol; round complexity log₂(N/k); query complexity per round.  
**Tier:** core.

### 2.2 Ben-Sasson, Kopparty, Saraf — *Worst-Case to Average Case Reductions for the Distance to a Code*
CCC 2018.  
First tight FRI soundness: if any member of a linear space is δ-far from RS, then nearly all are (1−ε)δ-far. Lets the verifier extract proximity from a single random linear combination.  
**SHROUD cites:** unique-decoding-regime soundness; (1−ε)δ proximity preservation.  
**Tier:** core.

### 2.3 Ben-Sasson, Goldberg, Kopparty, Saraf — *DEEP-FRI: Sampling Outside the Box Improves Soundness*
ITCS 2020. ePrint 2019/336. arXiv:1903.12243.  
DEEP (Domain-Extending for Eliminating Pretenders): query the prover outside the evaluation domain, push soundness from "double Johnson" up to the Johnson bound 1−√(1−δ). Defines the OOD-challenge mechanism that **anchors the position where SHROUD requires the randomizer commitment** (see §4 below).  
**SHROUD cites:** DEEP-ALI construction; Johnson-bound soundness theorem; **the DEEP/OOD challenge as the transcript point where randomizer-commit MUST already be bound**.  
**Tier:** core.

### 2.4 Ben-Sasson, Carmon, Ishai, Kopparty, Saraf — *Proximity Gaps for Reed-Solomon Codes*
FOCS 2020. JACM 2023. ePrint 2020/654.  
Strongest soundness statement currently used for FRI: affine spaces over RS exhibit a proximity gap — either all members are close or only a poly-in-N fraction are. Holds up to Johnson list-decoding bound 1−√ρ.  
**SHROUD cites:** Theorem 1.2 (proximity gap); error term ε ≈ poly(N)/|F|; the bound Plonky3 / ethSTARK pin parameters against.  
**Tier:** core.

### 2.5 Arnon, Chiesa, Fenzi, Yogev — *STIR: Reed-Solomon Proximity Testing with Fewer Queries*
CRYPTO 2024 (Best Paper). ePrint 2024/390.  
Replaces FRI's rate-preserving folding with rate-reducing folding. Query complexity O(λ + log N) instead of O(λ · log N).  
**SHROUD cites:** Theorem 1 (query complexity); rate-reduction folding step. Non-ZK STIR is not itself a SHROUD privacy anchor, but it is part of the constrained-code lineage that HVZK-WHIR extends.  
**Tier:** comparison.

### 2.6 Arnon, Chiesa, Fenzi, Yogev — *WHIR: Reed-Solomon Proximity Testing with Super-Fast Verification*
EUROCRYPT 2025. ePrint 2024/1586.  
IOPP for *constrained* Reed-Solomon codes (RS codes with additional algebraic side-conditions — multilinear-extension constraints, evaluation constraints). Verifier in hundreds of microseconds. The constrained-RS abstraction unifies univariate and multilinear PCS into one query interface.  
**SHROUD cites:** constrained-RS code definition; the WHIR commit-then-query interface as the **upstream pivot target** (per `docs/HVZK-WHIR Impact on SHROUD.md`); verifier microsecond-class timing as engineering motivation for hiding layers that don't blow up the verifier.  
**Tier:** core (production target).

### 2.7 Chiesa, Fenzi, Weissenberg — *Zero-Knowledge IOPPs for Constrained Interleaved Codes* (HVZK-WHIR)
ePrint 2026/391 (Feb 2026).  
IOPP for constrained interleaved linear codes that achieves HVZK with negligible overhead over non-ZK WHIR/STIR. Provides round-by-round knowledge soundness with straight-line extractor.  
**SHROUD cites:** HVZK definition for *interactive oracle reductions* (composition-compatible); ZK-sumcheck sub-protocol; ZK code-switching protocol; high-distance dispersers for the simulator. **Grounds SHROUD's `ShroudCodewordEmbedding` obligation in the WHIR direction.**  
**Tier:** core (starred anchor for the WHIR roadmap).

### 2.8 Zeilberger, Chen, Fisch — *BaseFold: Efficient Field-Agnostic Polynomial Commitment Schemes from Foldable Codes*
CRYPTO 2024. ePrint 2023/1705.  
Generalises FRI folding to "foldable codes" that don't require FFT-friendly fields. Multilinear PCS by interleaving the foldable-code IOPP with sumcheck.  
**SHROUD cites:** foldable-code generalisation of RS; alternative seam to WHIR for multilinear payloads.  
**Tier:** comparison.

### 2.9 Haböck, Levit, Papini — *Circle STARKs*
ePrint 2024/278.  
FRI-analogue LDT over the unit circle x²+y²=1 of the Mersenne prime field M31. Replaces multiplicative-subgroup folding with point-doubling on the circle group. Substrate for Stwo.  
**SHROUD cites:** circle-domain FFT and folding map; M31 parameter choice; **the Stwo seam** for SHROUD's `Stwo Mapping.md`.  
**Tier:** core (Stwo bridge).

### 2.10 StarkWare team — *ethSTARK Documentation v1.2*
ePrint 2021/582 (rev. 2023).  
Canonical concrete-parameter document for production FRI: rate ρ = 1/2ᵏ, λ/k queries per bit of soundness, blow-up, grinding, Merkle binding. Useful as a concrete engineering reference; backend-specific systems still need their own parameter/provenance audit.  
**SHROUD cites:** "k bits of soundness per query" formula; conjectured-vs-provable soundness rows; grinding-as-PoW interface; **concrete production parameters SHROUD's profile drift gate pins against**.  
**Tier:** core (parameter reference).

### 2.11 Plonky2/Plonky3 — *Whitepaper / Code documentation*
Polygon Zero, 2022+.  
Batched-FRI polynomial commitment: random-linear-combination batching of multiple oracles in a single FRI session, Goldilocks / BabyBear field choice, recursion-friendly parameter selection.  
**SHROUD cites:** batched-FRI RLC step; per-oracle independence assumption in soundness; **Plonky3-specific backend pins** as code/provenance facts, not standalone mathematical claims (e.g. BACKEND_LOG_BLOWUP=2, BACKEND_NUM_RANDOMIZER_COLS=4, BACKEND_EXTENSION_DEGREE=4).  
**Tier:** supporting (Plonky3 reference).

### 2.12 Guruswami, Sudan — *Improved Decoding of Reed-Solomon and Algebraic-Geometric Codes*
IEEE TIT 1999.  
Polynomial-time list-decoding of RS codes up to Johnson radius 1−√ρ. The decoding bound entering every modern proximity-gap proof.  
**SHROUD cites:** 1−√ρ list-decoding radius as the soundness ceiling for FRI/STIR/WHIR; list-size bound L(δ,ρ) entering proximity-gap error terms.  
**Tier:** supporting (foundational coding theory).

---

## 3. Degree accounting & quotient construction

### 3.1 Ben-Sasson, Bentov, Horesh, Riabzev — *Scalable, Transparent, and Post-Quantum Secure Computational Integrity* (STARK)
ePrint 2018/046 (2018).  
Defines AIR, trace/composition polynomial split, LDE over coset domains, constraint quotient C(x)/Z_H(x) where Z_H is the vanishing polynomial of trace domain H. Foundational degree-class statements.  
**SHROUD cites:** trace LDE definition; canonical Z_H coset vanishing polynomial; quotient-degree substrate. This is not the primary source for SHROUD's plain-additive hiding variant; use Aurora / ZK-sumcheck for that masking shape.  
**Tier:** core.

### 3.2 Haböck — *A Summary on the FRI Low Degree Test*
ePrint 2022/1216.  
Consolidates FRI parametrization, polynomial-commitment usage, DEEP algebraic linking, list-decoding soundness. Provides multi-point quotient (witness queried at z and gz), λ-power batching, the degree accounting SHROUD's contract presupposes.  
**SHROUD cites:** multi-point quotient relation; degree bookkeeping under λ-batching; **the `vanishing_poly_degree == quotient_chunk_degree + 1` relationship at the FRI input layer**.  
**Tier:** core.

### 3.3 Haböck & Kindi — *A Note on Adding Zero-Knowledge to STARKs*
ePrint 2024/1037 (2024).  
**Canonical reference for SHROUD's vanishing-factor quotient construction.** Develops two practical ZK techniques: (i) randomizing witness polynomials over the base field while challenges live in the extension field, (ii) decomposing the overall quotient into smaller-degree chunks with masking. Warns that decomposition is a frequent source of soundness/ZK bugs in literature and implementations.  
**SHROUD cites:** `q_i + v_{H_i} · t_i` vanishing-factor shape; **degree bound 2h−1 on randomized chunks**; `mask_poly_degree == quotient_chunk_degree` invariant; identification of decomposition pitfalls (the motivation for `QuotientDegreeContract` as auditable invariant); DEEP/OOD-masking obligation (randomizer polynomial committed **before** OOD challenge). Exact entropy-parameter formulas should be cited with the paper's section/theorem number before being used as normative SHROUD text.  
**Tier:** core (primary normative source for SHROUD's quotient hider).

### 3.4 Gabizon, Williamson, Ciobotaru — *PLONK*
ePrint 2019/953 (2019).  
PLONK quotient polynomial t(X) of degree ≤ 3n+5, decomposed into three chunks. Blinding pattern `b(X) · Z_H(X)` added to wire polynomials to keep the quotient balanced.  
**SHROUD cites:** multiplicative-blinding pattern `b · Z_H`; chunked quotient decomposition with per-chunk degree contracts; **algebraic precedent for the Layer-3 shape**.  
**Tier:** core.

### 3.5 Sefranek — *How (Not) to Simulate PLONK*
ePrint 2024/848 (SCN 2024).  
Original PLONK ZK proof was informal; exhibits a witness-indistinguishability attack against the unpatched version. Proves statistical ZK for the patched simulator. Most rigorous published audit of a PLONK-style quotient-hiding construction.  
**SHROUD cites:** simulator-side correctness conditions on quotient-chunk masking; **concrete failure mode when blinding bookkeeping is off** — direct motivation for SHROUD's `QuotientDegreeContract` as a machine-auditable invariant.  
**Tier:** core (audit precedent).

### 3.6 Ben-Sasson, Chiesa, Riabzev, Spooner, Virza, Ward — *Aurora: Transparent Succinct Arguments for R1CS*
EUROCRYPT 2019. ePrint 2018/828.  
Replaces unique degree-|H|−1 interpolant on H by a uniformly random higher-degree polynomial agreeing on H — the **bounded-independence mask**. Degree |H|+9 ensures any 10 evaluations outside H are independent and uniform. Prototype for SHROUD's plain-additive variant.  
**SHROUD cites:** bounded-independence randomization of witness polynomials; ρf+r masking lemma for sumcheck/quotient inputs; precedent for `mask_poly_degree` bookkeeping; **HVZK simulator template for RS-encoded witnesses**.  
**Tier:** core.

### 3.7 Pearson, Fitzgerald, Masip, Bellés-Muñoz, Muñoz-Tapia — *PlonKup: Reconciling PlonK with plookup*
ePrint 2022/086.  
Adds lookup gates to PLONK; restates the quotient with extra blinding/decomposition. Worked example of how additional argument terms flow into the quotient and how chunk degrees grow.  
**SHROUD cites:** worked example of `quotient_chunk_degree` accounting under added argument terms.  
**Tier:** supporting.

### 3.8 Chen, Bünz, Boneh, Zhang — *HyperPlonk: Plonk with Linear-Time Prover and High-Degree Custom Gates*
ePrint 2022/1355. EUROCRYPT 2023.  
Multilinear PLONK over the boolean hypercube — replaces quotient/FRI with multilinear sumcheck + zerocheck. Useful as a **negative reference**: clarifies which SHROUD invariants are univariate-specific.  
**SHROUD cites:** boundary of applicability — quotient-hider contract is intrinsically univariate.  
**Tier:** comparison.

### 3.9 Chiesa, Ojha, Spooner — *Fractal: Post-quantum and Transparent Recursive Proofs from Holography*
ePrint 2019/1076. EUROCRYPT 2020.  
Holographic IOP that supports recursive STARKs. Aurora-style bounded-independence masking applied to holographic indexer polynomials.  
**SHROUD cites:** randomization extended to indexer polynomials; recursion-friendly degree management.  
**Tier:** supporting.

### 3.10 Chiesa, Hu, Maller, Mishra, Vesely, Ward — *Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS*
ePrint 2019/1047. EUROCRYPT 2020.  
Holographic preprocessing zkSNARK in the algebraic-IOP framework. Aurora-style polynomial randomization adapted to univariate sumcheck-with-mask.  
**SHROUD cites:** algebraic-IOP framing of masked-polynomial degree preservation.  
**Tier:** supporting.

### 3.11 Martins, Farinha — *Study of Arithmetization Methods for STARKs*
ePrint 2023/661. J. Cryptology 2026.  
Compares AIR vs PAIR / RAP-style arithmetization, deriving explicit degree bounds for RS proximity testing under each.  
**SHROUD cites:** degree-bound parameters under different arithmetization choices; precedent for arithmetization-mode-aware degree contract.  
**Tier:** comparison.

---

## 4. Hiding constructions over LDT / IOP

### 4.1 Ames, Hazay, Ishai, Venkitasubramaniam — *Ligero: Lightweight Sublinear Arguments without a Trusted Setup*
ACM CCS 2017.  
The original **interleaved Reed-Solomon ZK-IPCP**. Introduces the random masking row in the interleaved-RS matrix that absorbs verifier-query entropy.  
**SHROUD cites:** **interleaved-RS masking construction (the literal mathematical model SHROUD's hiding embedding is built on)**; query-budget vs. masking-rank accounting.  
**Tier:** core.

### 4.2 Ben-Sasson, Chiesa, Riabzev, Spooner, Virza, Ward — *Scalable Zero Knowledge with No Trusted Setup* (BCRSVW)
CRYPTO 2019.  
First implemented zk-STARK. Randomizer columns added to the execution trace + RS randomization step → union of trace + quotient codewords reveals nothing beyond what queries are entitled to.  
**SHROUD cites:** **randomizer-row construction**; HVZK simulator template for LDT-based STARK; "blow-up + masking column" approach SHROUD adapts to WHIR.  
**Tier:** core.

### 4.3 Kattis, Panarin, Vlasov — *RedShift: Transparent SNARKs from List Polynomial Commitment IOPs*
ePrint 2019/1400. CCS 2022.  
First clean transformation from preprocessing zkSNARKs to a transparent FRI-based variant via a "list polynomial commitment" primitive. Specifies how to lift FRI to a hiding PCS by adding a randomizer codeword to the committed batch.  
**SHROUD cites:** **"added random codeword in the interleaved batch" construction** — the hiding-PCS abstraction layer SHROUD's adapter seam mirrors.  
**Tier:** core.

### 4.4 Ishai, Weiss — *Probabilistically Checkable Proofs of Proximity with Zero-Knowledge*
TCC 2014. ePrint 2017/176.  
Defines ZK-PCPPs; gives constructions where the simulator perfectly answers any bounded query set. Bridges PCP-style ZK to IOP-style ZK.  
**SHROUD cites:** formal ZK-of-proximity definition; **query-budget framework SHROUD's verifier model audits**.  
**Tier:** supporting.

Related but distinct: Ben-Sasson, Chiesa, Forbes, Gabizon, Riabzev, Spooner — *On Probabilistic Checking in Perfect Zero Knowledge* (ECCC TR16-156 / arXiv:1610.03798) gives perfect-ZK IPCP/IOP constructions beyond NP and a perfect-ZK sumcheck analogue. Cite that paper when SHROUD needs perfect-ZK IOP machinery specifically, not for the ZK-PCPP definition above.

### 4.5 Chiesa, Forbes, Spooner — *A Zero Knowledge Sumcheck and Its Applications*
arXiv:1704.02086 (2017).  
Original construction of ZK sumcheck via masking with a uniformly random multilinear polynomial. **Structural lemma: mask-degree must match the polynomial's degree class** to preserve soundness with ZK.  
**SHROUD cites:** abstract counterpart of SHROUD's `mask_poly_degree == quotient_chunk_degree` rule; simulator template reused by Libra/Virgo and by HVZK-WHIR's ZK-sumcheck.  
**Tier:** core.

### 4.6 Zhang, Xie, Zhang, Song — *Libra: Succinct Zero-Knowledge Proofs with Optimal Prover Computation*
CRYPTO 2019. ePrint 2019/317.  
ZK-GKR via *small masking polynomials* — adds a low-degree random polynomial to each sumcheck round to mask intermediate values. The minimal-overhead masking technique most LDT systems imitate.  
**SHROUD cites:** "small mask polynomial" alternative to full randomizer codewords — **comparison point when SHROUD justifies why FRI/WHIR layers need codeword-level (not just polynomial-level) masking**.  
**Tier:** comparison.

### 4.7 Zhang, Xie, Zhang, Papamanthou, Song — *Transparent Polynomial Delegation* (Virgo)
S&P 2020. ePrint 2019/1482.  
First complete recipe for "ZK on top of FRI" via masking polynomials. Composes ZK-GKR with FRI-based transparent PCS.  
**SHROUD cites:** composition pattern "(ZK-IP) over (FRI-PCS with hiding)" — directly comparable to SHROUD's adapter seam.  
**Tier:** comparison.

### 4.8 Bhadauria, Fang, Hazay, Venkitasubramaniam, Xie, Zhang — *Ligero++: A New Optimized Sublinear IOP*
ACM CCS 2020.  
Hybridizes Ligero's interleaved-RS masking with Aurora's univariate sumcheck. Reuses the randomizer-row primitive over a deeper IOP.  
**SHROUD cites:** **randomizer-row primitive composes across IOP-layer transformations** — load-bearing for SHROUD's compositionality lemma.  
**Tier:** supporting.

### 4.9 Ron-Zewi, Weiss — *Zero-Knowledge IOPs Approaching Witness Length*
CRYPTO 2024. ePrint 2024/816.  
First constant-query constant-round ZK-IOP with communication (1+γ)·m for 3SAT. Sharpens two ingredients: ZK codes and ZK sumcheck.  
**SHROUD cites:** **modular split "ZK code + ZK sumcheck" — the same modular split SHROUD's spec uses**; tight bounds on randomness overhead for masking.  
**Tier:** supporting.

### 4.10 Bowe, Grigg, Hopwood — *Halo (Recursive PLONK)*
ePrint 2019/1021 + follow-ups.  
Recursive SNARKs over polynomial commitments without trusted setup. In PLONK variants, quotient hiding is preserved across recursive steps.  
**SHROUD cites:** **recursive composition of quotient-hider invariants**.  
**Tier:** comparison.

---

## 5. Fiat-Shamir transcript binding

### 5.1 Fiat, Shamir — *How to Prove Yourself: Practical Solutions to Identification and Signature Problems*
CRYPTO 1986.  
Original FS heuristic: replace verifier's public-coin challenge in a 3-move sigma protocol by hash of the transcript so far.  
**SHROUD cites:** original FS transform; foundation for transcript-binding discipline.  
**Tier:** core.

### 5.2 Pointcheval, Stern — *Security Proofs for Signature Schemes*
EUROCRYPT 1996. J. Cryptology 2000.  
**Forking lemma**: if an adversary against an FS signature succeeds with non-negligible probability, rewinding and resampling yields a second accepting transcript with the same first message and different challenge → knowledge extraction. Canonical knowledge-soundness proof technique for FS-compiled sigma protocols.  
**SHROUD cites:** forking lemma for knowledge soundness of FS in ROM.  
**Tier:** core.

### 5.3 Canetti, Chen, Reyzin, Rothblum (CCRR) — *Fiat-Shamir and Correlation Intractability from Strong KDM-Secure Encryption*
EUROCRYPT 2018.  
Builds correlation-intractable hash families for sparse relations from strong KDM-secure encryption. This is a precursor to the standard-model Fiat-Shamir line, but SHROUD does not rely on this construction directly.  
**SHROUD cites:** correlation-intractability as the standard-model property that can replace an ideal random oracle in FS soundness arguments.  
**Tier:** supporting.

### 5.4 Canetti, Chen, Holmgren, Lombardi, Rothblum, Rothblum, Wichs (CCHLRRW) — *Fiat-Shamir: From Practice to Theory*
STOC 2019.  
Formalize **round-by-round (RBR) soundness**: a stronger soundness notion labeling "doomed" transcript prefixes such that any FS-derived challenge can leave "doomed" only with negligible probability. Theorem: FS applied to a constant-round RBR-sound public-coin protocol yields a sound NIZK under correlation-intractable hash. CCHLRRW instantiates CI from LWE → FS on standard-model footing.  
**SHROUD cites:** **RBR soundness as the right pre-image for FS compilation**; manifest exact-presence as the syntactic enforcer of "no doomed prefix becomes live".  
**Tier:** core.

### 5.5 Holmgren — *On Round-By-Round Soundness and State Restoration Attacks*
ePrint 2019/1261.  
Proves RBR soundness is **equivalent** to soundness against state-restoration attacks. Observes ROM security of FS does not by itself imply either. Operationally: the prover-side attack model that defeats naive FS is precisely the state-restoration adversary — exactly what SHROUD's transcript discipline must rule out structurally.  
**SHROUD cites:** **RBR = state-restoration equivalence — the precise attack model SHROUD's pre-grind and absorb-before-challenge guards defeat**.  
**Tier:** core.

### 5.6 Block, Garreta, Tiwari, Zając — *On Soundness Notions for Interactive Oracle Proofs*
J. Cryptology 2024. ePrint 2023/1256.  
Maps the lattice of IOP soundness notions: standard, special, RBR, RBR-knowledge, state-restoration. Shows generalized special soundness implies generalized RBR soundness. Reference taxonomy for which soundness flavor an IOP must satisfy before BCS / FS compilation.  
**SHROUD cites:** soundness-notion lattice; which property a downstream IOP must export for safe FS.  
**Tier:** core.

### 5.7 Attema, Fehr, Klooß — *Fiat-Shamir Transformation of Multi-Round Interactive Proofs*
TCC 2022. J. Cryptology 2023.  
**Tight security analysis of FS applied to (2μ+1)-move public-coin proofs in the ROM**: knowledge-soundness loss is Q^μ where Q is the adversary's oracle-query budget. Extends to adaptive settings and varying-size challenge spaces.  
**SHROUD cites:** multi-round FS knowledge-soundness bound; **query-budget loss per round — the concrete-security input for SHROUD's parameter audits on multi-round FRI/WHIR**.  
**Tier:** core (parameter analysis).

### 5.8 Chiesa, Orrù — *A Fiat-Shamir Transformation From Duplex Sponges*
ePrint 2025/536. TCC 2025. (Also: `spongefish` Rust impl + IETF draft `draft-irtf-cfrg-fiat-shamir`.)  
Concrete-security analysis of an FS transform built on the **duplex sponge** paradigm with explicit per-call security bounds and domain-separation discipline.  
**SHROUD cites:** **closest published match to SHROUD's transcript model** — domain labels separate slots, every absorb is positionally bound, every challenge is derived from current squeeze state. Sponge security parameters.  
**Tier:** core (implementation template).

### 5.9 Bernhard, Pereira, Warinschi — *How Not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios*
ASIACRYPT 2012.  
Distinguishes **strong FS** (hash includes statement + commitment) from **weak FS** (commitment only). Concrete soundness/extractability breakage of Helios when weak FS is used adaptively.  
**SHROUD cites:** weak vs. strong FS dichotomy; **SHROUD's manifest exact-presence rule is the formal answer to weak FS — every public input and oracle commitment must appear in the transcript before any derived challenge**.  
**Tier:** core (negative example).

### 5.10 Dao, Miller, Wright, Grubbs — *Weak Fiat-Shamir Attacks on Modern Proof Systems* ("Frozen Heart")
ePrint 2023/691. IEEE S&P 2023.  
Catalogues **36 weak-FS implementations across 12 modern proof systems** (Bulletproofs, PlonK, Spartan, Wesolowski VDF, Girault, Dusk Network, Iden3, ConsenSys). Concrete forgery PoCs.  
**SHROUD cites:** "Frozen Heart" vulnerability class; **the directly motivating "bad FS in the wild" reference for SHROUD's enforce-at-spec posture**.  
**Tier:** core (negative example, defensive motivation).

### 5.11 Khovratovich, Rothblum, Soukhanov — *How to Prove False Statements: Practical Attacks on Fiat-Shamir*
CRYPTO 2025. ePrint 2025/118.  
**Non-contrived attack on the FS-compiled GKR-based succinct argument under standard hash instantiations.** First demonstration that a deployed protocol — not a pathological counterexample — can be broken by FS instantiation.  
**SHROUD cites:** non-contrived FS attack on a real argument; **strongest case for layer-of-defense discipline rather than ad-hoc instantiation reasoning**.  
**Tier:** core (negative example).

### 5.12 Chiesa, Manohar, Spooner — *Succinct Arguments in the Quantum Random Oracle Model*
TCC 2019. ePrint 2019/834.  
Proves Micali's SNARG and (with extensions) BCS are unconditionally secure in **QROM**, including ZK and knowledge-soundness preservation. First zkSNARK secure in QROM.  
**SHROUD cites:** QROM soundness/ZK theorem for BCS-style transforms.  
**Tier:** supporting (post-quantum).

### 5.13 Don, Fehr, Majenz, Schaffner — *Security of the Fiat-Shamir Transformation in the QROM*
CRYPTO 2019. ePrint 2019/190.  
Generic ROM → QROM reduction for FS, with polynomial loss. Soundness + proof-of-knowledge preservation.  
**SHROUD cites:** QROM FS soundness theorem; companion to Chiesa-Manohar-Spooner for sigma-protocol case.  
**Tier:** supporting (post-quantum).

### 5.14 Fischlin — *Communication-Efficient NIZKPoK with Online Extractors* (CRYPTO 2005)
### 5.15 Unruh — *Non-Interactive Zero-Knowledge Proofs in the QROM* (EUROCRYPT 2015)
Alternatives to vanilla FS for online-extractable / quantum-secure NIZKAoK. **Fischlin gives straight-line knowledge extraction (no rewinding)** — critical when composition matters.  
**SHROUD cites:** straight-line vs. rewinding extraction; FS-vs-Fischlin tradeoff (scope-boundary citation).  
**Tier:** comparison.

---

## 6. Random oracle / sponge model

### 6.1 Bellare, Rogaway — *Random Oracles Are Practical*
ACM CCS 1993.  
Formalizes ROM. SHROUD's transcript-binding discipline is the syntactic invariant the ROM proof of FS/BCS requires.  
**SHROUD cites:** ROM as the model in which FS / BCS security holds.  
**Tier:** core.

### 6.2 Canetti, Goldreich, Halevi — *The Random Oracle Methodology, Revisited*
STOC 1998. JACM 2004.  
**Uninstantiability**: there exist schemes provably secure in ROM but insecure under every concrete instantiation. Motivates defense-in-depth.  
**SHROUD cites:** uninstantiability caveat as **justification for spec-layer audit** — formal ROM proofs alone don't guarantee deployed safety; transcript and domain-separation discipline must be machine-checkable.  
**Tier:** core (counterpoint).

### 6.3 Maurer, Renner, Holenstein — *Indifferentiability, Impossibility Results on Reductions, and Applications to the ROM*
TCC 2004.  
Defines **indifferentiability**: sufficient condition for safely replacing an ideal primitive by a construction over a weaker one.  
**SHROUD cites:** indifferentiability composition theorem.  
**Tier:** supporting.

### 6.4 Bertoni, Daemen, Peeters, Van Assche — *On the Indifferentiability of the Sponge Construction*
EUROCRYPT 2008.  
Sponge (Keccak / SHA-3) is indifferentiable from a random oracle when the underlying permutation is ideal. **Concrete cryptographic justification for sponge-based FS transcripts.**  
**SHROUD cites:** sponge indifferentiability bound; basis for duplex-based transcript implementations.  
**Tier:** supporting (justifies SHROUD's pinning of Keccak256-rooted sponge construction).

---

## 7. Alternative LDT/PCS families (comparison)

### 7.1 Bootle, Chiesa, Groth — *Linear-Time Arguments with Sublinear Verification from Tensor Codes*
TCC 2020. ePrint 2020/1426.  
"BCG" PCS: linear-time-encodable tensor codes give a PCS with O(N) prover and N^ε verifier. Substrate later instantiated by Brakedown.  
**SHROUD cites:** non-RS PCS comparison point.  
**Tier:** comparison.

### 7.2 Golovnev, Lee, Setty, Thaler, Wahby — *Brakedown: Linear-time and Field-agnostic SNARKs for R1CS*
CRYPTO 2023. ePrint 2021/1043.  
First linear-time SNARK: BCG over expander-based linear-time codes + Spartan sumcheck PIOP. Field-agnostic, plausibly post-quantum. Now also in Plonky3.  
**SHROUD cites:** linear-time-code PCS construction; field-agnosticism property absent from RS-FFT; **non-FRI seam in Plonky3** (relevant if SHROUD ever extends beyond FRI/WHIR).  
**Tier:** comparison.

### 7.3 Xie, Zhang, Song — *Orion: Zero Knowledge Proof with Linear Prover Time*
CRYPTO 2022. ePrint 2022/1010.  
Improves Brakedown via code-switching + proof composition. Plausibly post-quantum.  
**SHROUD cites:** code-switching technique; comparison point for non-RS PCS proof sizes.  
**Tier:** comparison.

### 7.4 Garreta et al. — *On Amortization Techniques for FRI-Based SNARKs*
ePrint 2024/661 (2024).  
Batch/pack multiple Plonkish instances into one FRI proof; analyzes combined quotient and degree growth.  
**SHROUD cites:** how degree contracts scale under packing — relevant if SHROUD extends to multi-instance hiding.  
**Tier:** comparison.

---

## 8. Mapping table — SHROUD object/invariant → primary citation

| SHROUD object / invariant | Primary citation(s) | Secondary |
|---|---|---|
| `TranscriptBinding` / `TranscriptBindingManifest` exact-presence | BCS-IOP §5 (1.2), Bernhard et al. (5.9), Frozen Heart (5.10) | RBR (5.4), Chiesa-Orrù sponge FS (5.8) |
| `ReferenceChallengeDeriver` / sponge-based FS | Chiesa-Orrù (5.8), Bertoni sponge (6.4) | Bellare-Rogaway ROM (6.1) |
| `DOMAIN_RANDOMIZER_COMMITMENT` (before-OOD obligation) | DEEP-FRI (2.3), Haböck-Kindi (3.3) | Aurora (3.6) |
| `ShroudBatchOpeningSpec` (interleaved-RS hiding) | Ligero (4.1), BCRSVW (4.2), RedShift (4.3) | Ligero++ (4.8), HVZK-WHIR (2.7) |
| `ShroudCodewordEmbeddingSpec` (randomizer columns) | BCRSVW (4.2), HVZK-WHIR (2.7) | Ron-Zewi-Weiss (4.9) |
| `ShroudOracleCommitmentSpec` (hiding MMCS) | Micali / Kilian (1.3), Bertoni sponge (6.4) | — |
| `ShroudQuotientHiderSpec` plain-additive `q_i + r_i` | Aurora (3.6), ZK Sumcheck (4.5) | STARK (3.1) only for the quotient/LDE substrate |
| `ShroudQuotientHiderSpec` vanishing-factor `q_i + v_H·t_i` | Haböck-Kindi (3.3), PLONK (3.4) | Sefranek (3.5), PlonKup (3.7) |
| `QuotientDegreeContract` `mask_poly_degree == quotient_chunk_degree` | Haböck-Kindi (3.3), Chiesa-Forbes-Spooner (4.5) | Aurora (3.6), Libra (4.6) |
| `QuotientDegreeContract` `2h−1` bound | Haböck-Kindi (3.3) | Haböck FRI summary (3.2) |
| `ShroudOpeningProjectionSpec` (public/hidden split) | Ligero (4.1), ZK-PCPPs (4.4) | BCS-IOP (1.2) |
| `HidingTechniqueClaim::RandomCodewordInterleaving` | RedShift (4.3), Ligero (4.1) | BCRSVW (4.2) |
| `HidingTechniqueClaim::QuotientChunkRandomization` | Haböck-Kindi (3.3) | PLONK (3.4) |
| `SecurityLevel::Perfect` simulator obligation | GMR (1.1), BCS-IOP (1.2) | Sefranek (3.5) |
| `Plonky3HashIdentifier` sponge ID embedding | Chiesa-Orrù (5.8), Bertoni sponge (6.4) | CGH uninstantiability (6.2) |
| Plonky3 backend constants (log_blowup, queries, PoW) | ethSTARK (2.10), Plonky2/3 (2.11) | Haböck FRI summary (3.2) |
| Stwo / Circle STARK seam | Haböck-Levit-Papini (2.9) | — |
| WHIR pivot target | WHIR (2.6), HVZK-WHIR (2.7) | BaseFold (2.8) |
| Proximity-gap soundness ceiling | Proximity Gaps (2.4) | Guruswami-Sudan (2.12) |
| Multi-round FS query-budget loss | Attema-Fehr-Klooß (5.7) | Pointcheval-Stern (5.2) |
| QROM stance | Chiesa-Manohar-Spooner (5.12), Don-Fehr-Majenz-Schaffner (5.13) | — |

---

## 9. Coverage notes & gaps

**Well-covered:**
- RS-LDT substrate (FRI / DEEP-FRI / STIR / WHIR / BaseFold / Circle STARKs).
- Quotient construction and masking (STARK / Aurora / PLONK / Haböck-Kindi / PlonKup / Sefranek).
- FS theory (FS / Pointcheval-Stern / RBR / CCHLRRW / Holmgren / Chiesa-Yogev / Attema-Fehr-Klooß / Chiesa-Orrù sponge).
- "Bad FS" catalogue (Bernhard et al. / Frozen Heart / Khovratovich-Rothblum-Soukhanov).
- HVZK-WHIR (ePrint 2026/391) — the WHIR-direction anchor.

**Gaps / things SHROUD might want to add:**
- **Specific BabyBear / Goldilocks / M31 small-field cryptography analyses.** SHROUD pins BabyBear (Plonky3) and references M31 (Stwo), but the small-field-specific FRI soundness analyses are spread across blog posts and unpublished notes; consider commissioning a small bibliography entry from Polygon Labs / StarkWare if there's an audit-grade reference.
- **Hiding-MMCS specifically.** SHROUD requires "hiding Merkle trees" but the literature on this is thinner than expected — Catalano-Fiore vector commitments + ZK-friendly Merkle constructions are the closest, plus the implicit hiding in BCS query openings. Worth a focused literature search.
- **Recursion + hiding interaction.** Halo / Plonky2 / Nova etc. discuss recursion but don't focus on how hiding obligations compose under proof aggregation. If SHROUD ever claims recursion-safety, this needs more references.
- **Negative simulator-correctness audits** beyond Sefranek 2024/848. Other "ZK proof actually has a simulator bug" papers exist (some in Halo2, Nova) — useful as additional defensive motivation.
- **Lookup arguments** (plookup, lasso, jolt) are quotient-aware but mostly out of SHROUD's scope. PlonKup is included; deeper lookup coverage is deferred.

---

## 10. Citation style for SHROUD docs

When citing in SHROUD documentation or Lean comments, use this form:

```
SHROUD's `QuotientDegreeContract::with_vanishing_poly` enforces the Layer-3
relation from Haböck-Kindi (ePrint 2024/1037 §3.2): `randomized_chunk_degree_bound
== quotient_chunk_degree + vanishing_poly_degree = 2h - 1`.
```

Or for Lean theorem headers:

```lean
/-- Habock-Kindi vanishing-factor degree relation (ePrint 2024/1037, Layer-3):
    randomized chunk bound = quotient chunk degree + vanishing degree = 2h - 1. -/
theorem quotientVanishing_valid_iff ...
```

Always link to ePrint number; never rely on author surname alone (ambiguous in Haböck's case across 3 papers).

---

## 11. How this maps to the Lean restructure plan

The Lean theorem backlog from `docs/Lean Normative Spec Restructure.md` §12 corresponds to upstream citations as follows:

| Lean theorem | Upstream citation it discharges to |
|---|---|
| `canonicalSchedule_valid` | BCS-IOP (1.2), Bernhard et al. (5.9) |
| `randomizerCommitment_before_ood` | DEEP-FRI (2.3), Haböck-Kindi (3.3) |
| `domainLabels_pairwiseDistinct` | Chiesa-Orrù sponge FS (5.8) |
| `canonicalManifest_complete` | BCS-IOP (1.2), Frozen Heart (5.10) |
| `degreeBudget_valid_iff` | Aurora (3.6), STARK (3.1) |
| `maskedRelation_preservesDegreeClass` | Aurora (3.6), Chiesa-Forbes-Spooner (4.5) |
| `quotientPlain_valid_iff` | Aurora (3.6), Chiesa-Forbes-Spooner (4.5) |
| `quotientVanishing_valid_iff` | Haböck-Kindi (3.3), PLONK (3.4) |
| `codewordEmbedding_statistical_randomizers` | Ligero (4.1), BCRSVW (4.2), RedShift (4.3) |
| `codewordEmbedding_minBlowup` | ethSTARK (2.10), Haböck FRI summary (3.2) |
| `batchOpening_statisticalPayload_hiddenCount` | Ligero (4.1), Aurora (3.6) |
| `perfectClaim_valid_implies_hidingMmcs` | GMR (1.1), BCS-IOP (1.2) |
| `preGrindGrammar_randomizerBeforeZeta` | DEEP-FRI (2.3), Haböck-Kindi (3.3) |

Lean proves the *local* algebraic / structural statement; the citation says *which upstream theorem* makes that local statement load-bearing for a real cryptographic claim. This is the Level-3 conditional bridge theorem framing from the restructure plan §5.

---

**Bibliography compiled:** 2026-05-18.  
**Metadata/source audit:** 2026-05-19.  
**Maintenance:** when a new SHROUD invariant is added or a new Lean theorem is stated, append an entry to §8 (mapping table) and §11 (Lean correspondence) in the same PR. When upstream papers change (new ePrint revisions, conference acceptances), update the citation in place.
