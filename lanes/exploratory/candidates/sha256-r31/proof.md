# SHA-256, 31 prefix rounds: two-block collision search with an A(-1)-keyed table

This **exploratory** package selects track `sha256-r31-exploratory`, target
`sha256-r31-prefix-v1`, cost model `collision-frontier-v5` and policy
`paired-lanes-v1`. It submits a complete randomized algorithm with declared
heuristics, a resource analysis in v5 units, and three organizer-executed
experiments. Readiness requests review; it asserts no AI outcome.

Declared scalar: `time_log2 = 48.25` target-compression equivalents. Declared
success probability: 0.39; section 6 derives at least 0.4178 under the declared
heuristics. The scalar includes a charge of 2^45 units for the historical
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

For a block, let E_j be the event that table entry j gives a full match, and
S_j the event that E_j holds and Step 3 then succeeds. Under H-UNIFORM
(h0, h1 and h2 are uniform and independent for these events), for entry j:

    P(E_j) = 2^-32 * P[Kp_j - h1 in V6] * P[W5 in V5]
           = 2^-32 * (|V6|/2^32) * (|V5|/2^32) = 2^-32 * 2^-9 * 2^-16.

W5 falls in class t with probability 2^14/2^32 for each of the four classes,
and a full match in class t completes with probability p_t (H-STEP3):

| Class t | p_t | 99% lower bound |
| --- | --- | --- |
| d0017fe0 | 0.1069 | 0.1053 |
| cffe8020 | 0.1164 | 0.1148 |
| d0018020 | 0.1164 | 0.1148 |
| cffe7fe0 | 0.1075 | 0.1059 |

These are Monte Carlo estimates over 10^6 uniform C per class, with Hoeffding
half-width 0.00163. Summing over the 2560 entries,

    sum_j P(S_j) >= 2^-32 * 2560 * 2^-9 * 2^-18 * (0.1053+0.1148+0.1148+0.1059)
                 =  2^-47.678 * 0.4408 = 2^-48 * 0.5510.

**Overlap between entries (H-PAIR-OVERLAP).** Entries with different A-1 keys
are disjoint events, because h0 takes one value. For entries j < k with the
same key, Bonferroni gives

    P(union_j S_j) >= sum_j P(S_j) - sum_{j<k, same key} P(E_j and E_k).

There are 4976 same-key pairs. For each one, the joint W6 probability
|V6 ∩ (V6 + Kp_k - Kp_j)| / 2^32 was computed **exactly** by enumerating V6.
The sum over all same-key pairs is 1.7286 against 5 for the single entries,
and 240 pairs share Kp exactly. The joint W5 condition was then evaluated on
up to 64 h1 values per pair, where both W6 values are admissible. In every
case the two W5 values differ by a nonzero shift, and the shifted class sets
almost never intersect. The measured correction is

    sum P(E_j and E_k) = 2^-48 * 0.0002.

The bound below subtracts 2^-48 * 0.01, fifty times the measured value:

    q = P(block success) >= 2^-48 * (0.5510 - 0.0100) = 2^-48 * 0.5410.

With B = 2^48 blocks, using independence across blocks (H-UNIFORM),

    Pr[success] >= 1 - (1 - q)^B >= 1 - exp(-0.5410) > 0.4178 > 0.39.

**Caps.** The cap of 64 full matches changes this by less than
Pr[Poisson(5) > 64] < 2^-100. The E13 and E15 caps are 2^16 and 2^8. When an
admissible W18 exists, the observed success rate is about 1/30 per E13 trial
and above 1/4 per E15 trial (12,000 simulated matches and 4096 real-free-word
trials, with no cap ever reached). Under a geometric model the caps fail with
probability below 2^-100. The measured p_t already include the caps, since the
simulations used them.

**Real chaining words.** Experiment `real-state-completion` runs Step 3 on
states that combine a real chaining value f(IV, M0) (its free words A-4,
E-1..E-4) with table values. The success rate was 467/4096 = 0.114 in the
author run (99% Hoeffding interval [0.089, 0.139]) and 25/256 in a 256-trial
run. The class-averaged model prediction is 0.112.

`success_probability: 0.39` is a lower bound on the algorithm's success under
its fresh coins and the declared heuristics. It is not confidence in those
heuristics.

## 7. Resources (collision-frontier-v5)

One selected compression costs 1 unit; every other primitive word operation
costs 1/2140. Each executed instruction performs at most one primitive, and
every instruction is charged a second operation for its fetch (**two
operations per instruction**). Bounds are worst-case over the coins, given the
caps in sections 5.3 and 5.4 and the hit cap below.

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

52 instructions are 104 operations, budgeted at 128. So each block costs at
most 1 + 128/2140 = 1.059813 units.

**Hit path.** A bitmap hit happens with probability 664/2^32 = 2^-22.6. The run
stops with FAIL after 2^28 hits; the Chernoff probability of that is below
2^-1000. Each hit takes:
- at most 20 instructions to reach the list;
- for each of at most 8 entries, at most 40 instructions;
- at most 340 instructions in total, 680 operations.

Total: 2^28 x 1024 / 2140 < 2^27 units. The 664 distinct keys and the maximum
multiplicity of 8 are recomputed by experiment `table-replay`.

**Step 3.** At most 64 invocations. Each needs at most:
- 2^15 W16 candidates x 40 instructions;
- 2^16 E13 trials x 400 instructions (three steps on two paths, each step
  under 60 instructions, with 32-bit rotations emulated by 4 word operations);
- 2^8 E15 trials x (2 compressions + 100 instructions);
- 100 instructions to derive W0..W4 and E0;
- 6 compressions of final verification.

That is under 2^15 units per invocation and under 2^21 units in total.

**Preprocessing (in the run).**
- One scan of 2^32 words evaluating the V5..V8 and V16 predicates and setting
  bitmap bits: at most 256 instructions per word, so
  2^32 x 512 / 2140 < 2^30 units.
- Pair checks: 2^22 x 1200 instructions x 2 / 2140 < 2^22.2 units.
- Bitmap clearing and index building: under 2^20 units.
- Total: under 2^30.1 units.

**Historical public-data cost (H-HISTORICAL-COST): 2^45 units charged.** Two
earlier computations produced the public inputs.

(a) *Starting point.* It is read from the published pair. The authors report
that the practical search producing that pair, including its own starting
points, table and matching, took 1.2 hours on 64 threads: 76.8 thread-hours.

(b) *Characteristic.* The time for Table 6 is not reported, so it was measured
here instead. The authors' public characteristic-search models for 31-step
SHA-256 are `find_dc_model_31_256.py` (message and state differences) and
`correct_dc_model_31_256.py` (adding value transitions for steps 5..7). They
were re-run unchanged, except that the solver is STP 2.4.1 with MiniSat on
**one** core instead of CryptoMiniSat on 26 threads. Each script lowers the
Hamming-weight bound from 60 until the query is unsatisfiable.
- Stage 1 found its first characteristic (weight 60) after 3.5 minutes. It
  reached Table 6's level (weight 52) after 19.2 minutes and weight 43 after
  34.6 minutes. It was still lowering the bound when measured at 35.5 minutes
  of single-core time. Further minimization is optional for producing a
  usable characteristic.
- Stage 2 terminated after 548 s (9.1 minutes) of single-core CPU time, with
  a peak memory of 0.96 GB. It lowered its objective bound from 60 to 0 and
  output a complete signed characteristic for steps 0..30, with message
  differences in W5..W9, W16 and W18. Its W16 row equals Table 6's.

Along the way both stages produced characteristics at least as sparse as
Table 6, which has 52 E-difference bits over steps 5..18.

Conversion: one core-hour is at most 3600 s x 5·10^9 cycles x 8 word
operations per cycle = 1.44·10^14 operations, which is 2^35.97 units. We charge:
- 64 x 1.2 thread-hours for (a);
- 100 times the measured stage-1 and stage-2 core time for (b), covering
  design iterations and parameter tuning;
- in total 2^42.23 units for (a) plus 100 x 0.744 core-hours = 2^42.19 units
  for (b), together 2^43.21: a factor of 3.4 below the 2^45 charged.

**Total time.**

    T <= 2^48 * 1.059813 + 2^45 + 2^30.1 + 2^27 + 2^21
       <  2^48 * (1.059813 + 0.125 + 2^-16)
       <  2^48 * 1.18483.

To certify log2(1.18483) < 0.25, let u = 0.18483. Then
ln(1+u) <= u - u^2/2 + u^3/3 < 0.18483 - 0.01708 + 0.00211 = 0.16986. Also
0.25 ln 2 > 0.25 x 0.6931 = 0.17328. Hence **T < 2^48.25**, which is
`time_log2: 48.25`.

**Sensitivity.** With no historical charge, T < 2^48.09. If the historical
charge were 2^47, T < 2^48.6.

**Memory.**

| Item | Size |
| --- | --- |
| Bitmaps for V5, V6 and A-1 | 2^29 bytes each |
| V7 and V8 lists | (2^9 + 2^13) x 32 bytes |
| V16 list | 2^15 x 32 bytes |
| Pair table and index | < 2^21 bytes |
| Code, constants and buffers | < 2^16 bytes |

The total is below 2^31 bytes, so `memory_log2_bytes: 31`.

**Other fields.**
- `preprocessing_log2: 45.01` covers the 2^45 historical charge plus in-run
  preprocessing below 2^30.1. Both are inside T.
- `nonuniform_advice_log2_bytes: 12` covers Table 6 as masks, the starting
  point, the class set, the IV and K: under 4096 bytes, and none is a
  precomputed answer.

## 8. Evidence

Three organizer-executed experiments, each with a host-checked full-collision
event:

1. **`fresh-completions`.**
   - Setup: the published matched chaining value f(IV, M0) and W0..W12 are
     fixed.
   - Each trial runs the complete Step 3 with seed-derived randomness: the
     V16 scan from a seed offset, then W14, W18, E13 and E15.
   - It returns M0||M1 and M0||M1'.
   - Author run: 256/256 distinct collisions on the exact target, checked
     with `verifier/hash_functions.py`.
2. **`table-replay`.**
   - Each trial recomputes, for one listed W8, its V8 membership, the V7
     predicate for all 512 listed V7 words, and the number of admissible
     (W7, W8) pairs from the starting point.
   - Trial 0 rebuilds the whole table: 2560 entries, 664 keys, maximum
     multiplicity 8.
   - A trial returns a (fresh-completion) collision **only if** every
     recomputed value equals the stated value. The checked success count
     therefore equals the number of agreeing replays.
   - Author run: 256/256.
3. **`real-state-completion`.**
   - Each trial draws a real first block, computes f(IV, M0), and keeps its
     free words.
   - It sets (A-1, A-2, A-3) from a seed-chosen table entry and admissible
     (W6, W5).
   - It runs Step 3 and returns a collision receipt only on success. The
     checked success count estimates the per-match Step 3 success rate on
     real free words.
   - Author runs: 25/256, and 467/4096 = 0.114. Prediction: 0.112.

The table replay covers V7, the listed W8 and the table statistics. It checks
only the listed values, which is enough for the lower bounds used. The V5 and
V6 sizes (2^16, 2^23) and V16 (2^15) come from exhaustive author enumeration;
V16 is also rebuilt by every experiment, which enumerates its 2^15 free-bit
patterns. The per-class p_t come from author Monte Carlo, supported by
experiment 3. The same-key overlap is exact for W6 and sampled for W5
(author code).

## 9. Heuristics and limitations

- **H-UNIFORM** (score-critical): distinct first blocks give independent,
  uniform (h0, h1, h2) for the match events. It is standard for two-block
  attacks and unproved at 2^-46 event scale. Experiment 3 supports uniformity
  of the free words h3..h7 for Step 3.
- **H-STEP3** (score-critical): p_t is at least the tabulated lower bounds. It
  is supported by the Monte Carlo, 12,000 simulated matches, and experiment 3
  on real free words.
- **H-PAIR-OVERLAP** (supporting): the same-key full-match overlap is at most
  2^-48 x 0.01. The W6 part is exact; the W5 part is sampled, with a measured
  value of 0.0002.
- **H-HISTORICAL-COST** (score-critical, low sensitivity): the historical
  computation is at most 2^45 units. It is supported by the authors' reported
  76.8 thread-hours and by a timed re-run of their public characteristic
  search.

This is an exploratory, heuristic cost estimate for a cryptanalytic algorithm.
It is not a proof, not a full-scale execution, and not a new security claim.
