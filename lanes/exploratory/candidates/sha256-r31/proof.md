# SHA-256, 31 prefix rounds: two-block collision search with an A(-1)-keyed table

This **exploratory** package selects track `sha256-r31-exploratory`, target
`sha256-r31-prefix-v1`, cost model `collision-frontier-v5` and policy
`paired-lanes-v1`. It submits a complete randomized algorithm with declared
heuristics, a resource analysis in v5 units, and one organizer-executed
experiment. Readiness requests review; it asserts no AI outcome.

Declared scalar: `time_log2 = 48.4` target-compression equivalents. Declared
success probability: 0.39; section 6 derives at least 0.4236 under the declared
heuristics. The scalar includes a charge of 2^46 units for the historical
computation that produced the public differential characteristic and starting
point used here (heuristic H-HISTORICAL-COST).

## 1. Sources and what is new here

The construction is the two-block method of Mendel, Nad and Schlaeffer
(EUROCRYPT 2013) with the 31-step differential characteristic of Li, Liu and
Wang, "New Records in Collision Attacks on SHA-2" (EUROCRYPT 2024, ePrint
2024/349, Section 4.2, Table 6). The matching strategy follows the idea in Li,
Liu, Wang, Dong and Sun, "The First Practical Collision for 31-Step SHA-256"
(ASIACRYPT 2024): the table is keyed by A(-1) only, and the remaining chaining
words are absorbed by solving for message words. Those authors report a
practical collision found in 1.2 hours on 64 threads, with time 2^40.5 and
memory 2^19.8 in their units.

Everything needed for review is restated below. Nothing depends on the
external documents except the historical-cost bound of heuristic
H-HISTORICAL-COST. The package contributes:

1. an explicit algorithm for the organizer's word RAM using **one** starting
   point;
2. exact set sizes from exhaustive enumeration;
3. the observation that four W5 difference classes are compatible, which
   multiplies the match rate by 4.3 over one class;
4. measured completion probabilities; and
5. a full v5 cost account.

## 2. Target, notation and message format

The target is SHA-256 cut to compression-round indices 0..30 on every padded
block. It starts once from the standard IV, applies the full feed-forward and
FIPS 180-4 padding, and compares all 256 digest bits. There is no free-start,
semi-free-start or truncation relation. The output is two distinct 128-byte
messages

    P  = M0 || M1,    P' = M0 || M1'

with a common first block M0 and different second blocks. Both messages pad to
three blocks: the third is the common padding block (0x80, zeros,
BE_8(1024)). If the chaining values after block 2 are equal, the complete
digests are equal, because the third compression then receives equal inputs.
The algorithm checks the chaining values after block 2 directly, so every
returned pair is an actual collision (section 5.5).

All words are 32 bits and all additions are modulo 2^32. For a block with
words W[0..15], W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16] for
t = 16..30. Here s0, s1, S0, S1, IF and MAJ are the standard SHA-256
functions:

    s0(x) = ROTR7 ^ ROTR18 ^ SHR3
    s1(x) = ROTR17 ^ ROTR19 ^ SHR10
    S0(x) = ROTR2 ^ ROTR13 ^ ROTR22
    S1(x) = ROTR6 ^ ROTR11 ^ ROTR25
    IF(x,y,z)  = (x & y) ^ (~x & z)
    MAJ(x,y,z) = (x & y) ^ (x & z) ^ (y & z)

The round constants K[0..30] and the IV are those of FIPS 180-4. Write a
chaining value as (h0..h7) = (A-1, A-2, A-3, A-4, E-1, E-2, E-3, E-4). Then
step i = 0..30 is

    E_i = A_{i-4} + E_{i-4} + S1(E_{i-1}) + IF(E_{i-1},E_{i-2},E_{i-3}) + K_i + W_i   (1)
    A_i = E_i - A_{i-4} + S0(A_{i-1}) + MAJ(A_{i-1},A_{i-2},A_{i-3})                  (2)

This is the standard round: T1 = E_i - A_{i-4} and A_i = T1 + T2. The output
chaining value is the input plus (A30, A29, A28, A27, E30, E29, E28, E27).

**Signed differences.** Path 1 uses M1 and path 2 uses M1'. The symbol at each
bit of word X (most significant bit on the left) constrains the pair (X, X'):

| Symbol | Meaning |
| --- | --- |
| `=` | X = X' at that bit |
| `n` | (X, X') = (1, 0) |
| `u` | (X, X') = (0, 1) |
| `0` | both 0 |
| `1` | both 1 |

The message difference is W'_i = W_i XOR D_i for i = 5..9, and D_i = 0 for
other i < 16. The XOR masks are:

| i | D_i |
| --- | --- |
| 5 | 0x0000F006 |
| 6 | 0x00208811 |
| 7 | 0x50105A0E |
| 8 | 0x58011100 |
| 9 | 0x00008004 |

## 3. The 31-step characteristic (Li-Liu-Wang Table 6)

Columns are the signed differences of A_i, E_i and W_i. Rows -4..-1 are the
chaining input. Rows 17..30 are all `=` in every column and are not shown.

```text
 i  A_i                              E_i                              W_i
-4  ================================ ================================
-3  ================================ ================================
-2  ================================ ================================
-1  ================================ ================================
 0  ================================ ================================ ================================
 1  ================================ ================================ ================================
 2  ================================ ================================ ================================
 3  ================================ ==========================10==== ================================
 4  ================================ ============0===0=========01===0 ================================
 5  ===================n=unnnnnnn=n= 000111010001111110nu=11111unnnu1 ================nuuu=======0=uu=
 6  ========n======================u 101011=11==0n0==u11110==1110011n ==========u=====u===u======n===u
 7  ===u===n==n========n=========n=u un0u1100n=01u11111001u1=n110u10n =u=u=======n=====n=nu=n=====nun=
 8  =============================n== 1u01un0u0=1=1=11n=0=u0=001001u0= =u=nn==========u===u===u==1=====
 9  ================================ 01100001110=0=010===00=11101u0=1 ================u==========1=u==
10  ================u============u== =1n1uuuuu0100=1un0=10unnnnnnn010 ================================
11  ================================ =01u1010uu1==11100===1000001n=0= ================================
12  ================================ ==110001=11====1n====0011110n=0= ================================
13  ================================ ===0====01======1=============== ================================
14  ================================ ================u===========0u== ================================
15  ================================ ================0============1== ================================
16  ================================ ================1============1== =============unnnunnnnnnnnnnnn==
18  ================================ ================================ ==============1=n=0==========n==
```

Row 17 and rows 19..30 are `=` in every column. Mechanical cross-check: the
published pair (section 4) satisfies every symbol of this table on its second
block, with zero violations under the sign convention above.

## 4. Public data: the published pair and the starting point

The published colliding pair (Li-Liu-Wang-Dong-Sun) is:

    M0  = 8ce3f805 5c401aed 579e5f7f bc3116cb ca189b3c eb75f04c 958f0a0e 7760b082
          dcd5027d 32260ad6 7b12b659 eee66518 ad7f88dd f8ad20bb 7ae40ffd 21609249
    M1  = 9abdeb1b 1f195f41 5a7210c1 55614f13 a2269dd1 be888a61 359257d4 adf3737b
          9f0484a6 eb830a58 66add94a 9669232d 45271fa5 b8f69585 428bbce3 0703b904
    M1' = M1 with W5..W9 XORed with D5..D9

The complete sha256-r31 digest of both 128-byte messages is
`55fdfb37efcbd086e19c3de0f72596300a3acdf48da5b1d0450a592bb2869fcd`.

A **starting point** is a solution of steps 5..12 of Table 6:
(A1..A12, E5..E12, W9..W12). This package uses exactly one, read from path 1
of the published second block:

    A1..A12: f36e6fcf b741c202 90c67413 fc7566c3 fa9053fb 11af5d4e
             87f5120c 9180b607 4f5af3a8 4b9e4fb8 83e817e6 2be31c3f
    E5..E12: 1d1fa7dd afe878e7 4c97cbe5 946f8048 61c171d3 f02293fa aa270418 b1f7f9e8
    W9..W12: eb830a58 66add94a 9669232d 45271fa5

The algorithm uses neither M0 nor the published M1 as a precomputed answer. It
searches for its own first block (section 5.3), so its output does not
reproduce the published pair except with negligible probability. M0 appears
only in the experiment (section 8).

## 5. The algorithm

### 5.1 Sets of admissible message words

Each set is defined by a predicate on one 32-bit word. The algorithm builds the
sets by scanning all 2^32 words once. The counts are exact results of that
enumeration.

- **V6**: W with W's Table 6 bits (`n`, `u`, `0`, `1` of row 6) and
  s0(W ^ D6) - s0(W) = -(W5' - W5), where W5' - W5 = 0xfffff006 is the
  modular value of D5 under row 5. This makes δW21 = 0. |V6| = 2^23.
- **V7**: row-7 bits and s0(W ^ D7) - s0(W) = -(δW6), so δW22 = 0.
  |V7| = 2^9.
- **V8**: row-8 bits and s0(W ^ D8) - s0(W) = -(δW16 + δW7), so δW23 = 0.
  |V8| = 2^13.
- **V5**: row-5 bits and s0(W ^ D5) - s0(W) in the class set
  T = {d0017fe0, cffe8020, d0018020, cffe7fe0}. Each class holds exactly
  2^14 words, so |V5| = 2^16. The published W5 is in class d0018020. These are
  the only four classes for which some admissible W18 has
  s1(W18') - s1(W18) = -t, which is needed for δW20 = 0.
- **V16**: W with row-16 bits and (W ^ D16) - W = δW9 = 0x00008004, where D16
  is the XOR mask of row 16. |V16| = 2^15.

The fixed modular differences are:

| Word | Modular difference |
| --- | --- |
| δW5 | fffff006 |
| δW6 | 002087f1 |
| δW7 | 4fefb5fa |
| δW8 | 28011100 |
| δW9 | 00008004 |
| δW16 | 00008004 |
| δW18 | ffff7ffc |

The last row equals -δW9, so δW25 = 0.

### 5.2 The pair table (preprocessing)

The starting point fixes (A1..A4, E5..E8). By (1) and (2), each choice of
(W7, W8) determines, in this order:

    E4 = E8 - A4 - S1(E7) - IF(E7,E6,E5) - K8 - W8
    A0 = E4 + S0(A3) + MAJ(A3,A2,A1) - A4
    E3 = E7 - A3 - S1(E6) - IF(E6,E5,E4) - K7 - W7
    A-1 = E3 + S0(A2) + MAJ(A2,A1,A0) - A3

For each (W8, W7) in V8 x V7 (2^22 pairs), the algorithm checks rows 3 and 4 on
E3 and E4. It then runs steps 5..12 on both paths from (A1..A4, E1..E4), with
E2 and E1 re-derived by (1) from any fixed admissible W6 and W5, and checks
rows 5..12. Rows 5..12 do not depend on W5 or W6. Those words only move E1 and
E2, and E1 and E2 enter steps 5..8 identically on both paths, only through the
E_{i-4} term and the h input.

Exactly **2560 = 2^11.32** pairs pass. The paper reports about 2^11 per
starting point. They carry 664 distinct values of A-1, and at most 8 pairs
share one value. Each passing pair is stored with (W7, W8, E3, E4, A0, A-1) and
two derived constants:

    E2 = G2 - W6,   with G2 = E6 - A2 - S1(E5) - IF(E5,E4,E3) - K6
    A-2 = E2 + S0(A1) + MAJ(A1,A0,A-1) - A2 = Kp - W6,
          with Kp = G2 + S0(A1) + MAJ(A1,A0,A-1) - A2

For a given W6:

    E1 = G1 - IF(E4,E3,E2) - W5,   with G1 = E5 - A1 - S1(E4) - K5
    A-3 = E1 + S0(A0) + MAJ(A0,A-1,A-2) - A1

So A-3 = Kpp(W6, A-2) - W5. The table is indexed by A-1: a 2^32-bit
membership bitmap plus a list of at most 8 pair indices for each present value.

### 5.3 Matching phase

Draw one fresh uniform 256-bit word r. For i = 0, 1, ..., B-1 with B = 2^48:

1. Set M0(i) = BE_32(i) || BE_32(r) and compute the 31-round compression
   h = f(IV, M0(i)). This costs one unit.
2. Read A-1 = h0. If the bitmap bit for A-1 is clear, continue with i + 1.
   This happens with probability 1 - 664/2^32 under H-UNIFORM.
3. For each pair with this A-1, set W6 = Kp - h1, where h1 = A-2. Test
   W6 in V6. If it passes, compute E2, then W5 = Kpp(W6, h1) - h2, where
   h2 = A-3. Test W5 in V5. If it passes, this is a **full match** for the
   pair, W6 and W5.

A full match fixes E1..E4 and A-4..A0 (with A-4 = h3), and
E-1..E-4 = h4..h7. From (2) at i = 0,

    E0 = A0 + A-4 - S0(A-1) - MAJ(A-1,A-2,A-3),

and (1) solved for W_i gives W0..W4. Now W0..W12 are fixed and steps 0..12 of
Table 6 hold on both paths:
- Rows 0..2 have no conditions.
- Rows 3..12 hold by the table.
- δW_i = 0 for i < 5.

### 5.4 Step 3: completion with W13, W14, W15

Let t be the class of W5. The algorithm proceeds as follows:

1. For each candidate W16 in V16, in a fixed order:
   - set W14 = s1^{-1}(W16 - W9 - s0(W1) - W0);
   - compute W18 = s1(W16) + W11 + s0(W3) + W2, and W18' from W16 ^ D16;
   - take the **first** W16 for which (W18, W18') satisfies row 18 and
     s1(W18') - s1(W18) = -t. The latter gives δW20 = 0.

   Here s1 is GF(2)-linear and invertible; its inverse is a fixed 32x32 bit
   matrix. If no W16 passes, the match is abandoned.
2. Repeat, up to 2^16 times: draw E13 with row-13 bits forced and set
   W13 = E13 - (E13 computed with W13 = 0). Run steps 13..15 on both paths.
   Keep E13 if rows 13 and 14 hold and δE15 = δA15 = 0. The modular
   differences of E15 and A15 do not depend on W15.
3. Repeat, up to 2^8 times: draw E15 with row-15 bits forced, set W15 in the
   same way, compute both complete second-block compressions, and **compare
   the chaining values**. On equality, return (M0||M1, M0||M1'). As a final
   check, the complete padded hashes are recomputed (six compressions).

At most 64 full matches are processed. After that the run stops with FAIL.

### 5.5 Output correctness

A pair is returned only after both chaining values after block 2 are checked
equal and M1 != M1' (D5 != 0). Both complete hashes are then recomputed. So the
algorithm never returns a non-colliding pair. The heuristics affect only
success probability and cost, never correctness.

## 6. Success probability

The per-block probability of a full match is

    d = 2560 * (|V6|/2^32) * (|V5|/2^32) / 2^32
      = 2^11.3219 * 2^-9 * 2^-16 * 2^-32
      = 2^-45.678,

split into four classes of 2^-47.678 each. This uses H-UNIFORM: for distinct
first blocks, h0, h1 and h2 act as independent uniform words for these
membership events, and different blocks act independently.

Given a full match in class t, Step 3 succeeds with probability p_t. Under
H-UNIFORM, the only data-dependent quantity in step 1 of 5.4 is
C = W11 + s0(W3) + W2, where W2 and W3 absorb the uniform E-2 and E-1. So p_t
is the probability, over uniform C, that some W16 in V16 gives an admissible
W18. Given such a W16, steps 2-3 succeeded in every simulated case (H-STEP3).
Monte Carlo over 10^6 uniform C per class gives:

| Class t | p_t | 99% lower bound |
| --- | --- | --- |
| d0017fe0 | 0.1069 | 0.1053 |
| cffe8020 | 0.1164 | 0.1148 |
| d0018020 | 0.1164 | 0.1148 |
| cffe7fe0 | 0.1075 | 0.1059 |

The lower bounds are Hoeffding, with half-width 0.00163. Their sum is 0.4408.
So the per-block success probability is at least

    q = 2^-47.678 * 0.4408 = 2^-48.860,

and over B = 2^48 blocks

    Pr[success] >= 1 - (1 - q)^B >= 1 - exp(-B q) = 1 - exp(-2^-0.860)
                 = 1 - exp(-0.5510) > 0.4236 > 0.39.

The cap of 64 full matches changes this by less than Pr[Poisson(5) > 64],
which is below 2^-100. The expected number of full matches is B·d = 5.0.
`success_probability: 0.39` is a lower bound for the algorithm's fresh coins
under the declared heuristics. It is not a statement of confidence in them.

## 7. Resources (collision-frontier-v5)

One selected compression costs 1 unit; every other primitive word operation
costs 1/2140. As in the organizer model, each executed instruction performs at
most one primitive. Every instruction is also charged a second operation for
its fetch (**two operations per instruction**). Bounds are worst-case over the
coins, given the caps in sections 5.3 and 5.4 and the hit cap below.

**Per first block (B = 2^48 times).** One compression unit, plus these
instructions:

| Work | Instructions |
| --- | ---: |
| Counter increment | 1 |
| Unpack the counter word into 8 block words (shift, mask, store) | 24 |
| Restore the 8 IV words | 16 |
| Call and return of the primitive | 2 |
| Load h0 | 1 |
| Bitmap word index, load, bit extract and test, branch | 6 |
| Loop test and branch | 2 |
| **Total** | **52** |

The words of r are unpacked once, at setup. 52 instructions are 104
operations, budgeted at 128. So each block costs at most 1 + 128/2140
= 1.059813 units.

**Hit path.** A bitmap hit happens with probability 664/2^32 = 2^-22.6, so
2^25.4 hits are expected. The run stops with FAIL after 2^28 hits; the
Chernoff probability of reaching that is below 2^-1000. Each hit takes:
- at most 20 instructions to reach the list;
- for each of at most 8 entries, at most 40 instructions (two subtractions,
  bitmap tests, E2 and Kpp).

That is at most 340 instructions, 680 operations, per hit. Total:
2^28 x 1024 / 2140 < 2^27 units.

**Step 3.** At most 64 invocations. Each needs at most:
- 2^15 W16 candidates x 40 instructions;
- 2^16 E13 trials x 400 instructions (three steps on two paths, each step
  under 60 instructions with 32-bit rotations emulated by 4 word operations);
- 2^8 E15 trials x (2 compressions + 100 instructions);
- 100 instructions to derive W0..W4 and E0;
- 6 compressions of final verification.

That is under 2^15 units per invocation and under 2^21 units in total.

**Preprocessing (in the run).**
- One scan of 2^32 words evaluating the V5..V8 and V16 predicates and setting
  bitmap bits: at most 256 instructions per word, so
  2^32 x 512 / 2140 < 2^30 units.
- Pair checks: 2^22 x 1200 instructions x 2 / 2140 < 2^22.2 units.
- Bitmap clearing (3 x 2^24 word stores) and index building: under 2^20 units.
- s1^{-1} and the constants: negligible.
- Total: under 2^30.1 units.

**Historical public-data cost (H-HISTORICAL-COST).** The characteristic of
section 3 and the starting point of section 4 came from earlier SAT/SMT
searches and from the practical collision search that produced the published
pair. Their combined computation is charged at **2^46 units**. That is about
1,700 core-hours at 3 GHz, counting each cycle as up to 8 word operations,
since 2^46 x 2140 = 2^57.06 operations. The only reported run time is 1.2
hours on 64 threads for the published pair. A starting point by itself costs
about 2^31.7 of the authors' tool units.

**Total time.**

    T <= 2^48 * 1.059813 + 2^46 + 2^30.1 + 2^27 + 2^21
       <  2^48 * (1.059813 + 0.25 + 2^-16)
       <  2^48 * 1.3099.

To certify log2(1.3099) < 0.4, let u = 0.3099. Then
ln(1+u) <= u - u^2/2 + u^3/3 < 0.3099 - 0.04801 + 0.00993 = 0.27182. Also
0.4 ln 2 > 0.4 x 0.6931 = 0.27724. Hence **T < 2^48.4**, which is
`time_log2: 48.4`.

**Sensitivity.** Without the historical charge, T < 2^48.09. If the historical
cost were 2^48 instead, T < 2^49.05.

**Memory.**

| Item | Size |
| --- | --- |
| Bitmaps for V5, V6 and A-1 | 2^29 bytes each |
| V16 list | 2^15 x 32 bytes |
| Pair table and index | < 2^21 bytes |
| Code, constants and buffers | < 2^16 bytes |

The total is below 2^31 bytes, so `memory_log2_bytes: 31`.

**Other fields.**
- `preprocessing_log2: 46.01` covers the 2^46 historical charge plus the
  in-run preprocessing below 2^30.1. Both are already inside T.
- `nonuniform_advice_log2_bytes: 12` covers the public constants the program
  embeds: Table 6 as masks, the starting point, the class set T, the IV and
  K. They fit in under 4096 bytes. None is a precomputed answer.

## 8. Evidence

**Experiment `fresh-completions`** (host-checked full-collision event).
- The program fixes the published matched chaining value f(IV, M0) and the
  published W0..W12 and W14.
- For each organizer seed it runs steps 2 and 3 of section 5.4 with SHAKE-256
  randomness derived from the seed, returning M0||M1 and M0||M1' with new W13
  and W15.
- The organizer recomputes both complete hashes. Distinct trials give
  distinct pairs.
- Author run with 256 seeds: 256/256 distinct collisions on the exact target,
  checked with `verifier/hash_functions.py`, in 0.4 s.
- This checks that Step 3 works on a real matched state and that Table 6
  rows 13..30, as transcribed, suffice. It does not measure the match rate or
  p_t.

**Author computations** (deterministic C programs, not executed by the
organizer):
- exhaustive set counts (section 5.1);
- the 2560-pair table from the starting point (section 5.2);
- p_t by 10^6-sample Monte Carlo per class (section 6);
- simulated full matches with uniform A-4 and E-4..E-1 for each class: 12,000
  trials. Step 3 success equalled the W18-existence rate, with zero failures
  after a W18 was found. On average about 30 E13 trials and 1 E15 trial were
  needed.
- An end-to-end run on the published M0 recovered the published W6 and W5
  through the formulas of 5.2-5.3, and found a full match in class d0018020.

## 9. Heuristics and limitations

- **H-UNIFORM** (score-critical): the full-match and success events for
  distinct M0(i) behave like independent draws with the probabilities of
  sections 5.3 and 6. It is standard in two-block attacks and unproved. It is
  not tested at scale here, because single events have probability about
  2^-46.
- **H-STEP3** (score-critical): p_t is at least the 99% lower bounds above,
  for real matches. It rests on simulation with uniform free chaining words
  plus the experiment on one real match.
- **H-HISTORICAL-COST** (score-critical, with low sensitivity): the public
  inputs cost at most 2^46 units. It rests on the published timing of the
  practical run; the characteristic-search time is not published.

This is an exploratory, heuristic cost estimate for a cryptanalytic algorithm.
It is not a proof, not a full-scale execution, and not a new security claim
about SHA-256 beyond 31 steps.
