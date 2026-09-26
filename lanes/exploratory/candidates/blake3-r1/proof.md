# A structural sub-birthday collision attack on 1-round BLAKE3

The scalar below is `time_log2` under `collision-frontier-v5`. Memory remains
a separately reported resource bound.

This exploratory package targets blake3-r1-prefix-v1. It proposes a classical
randomized algorithm with success probability at least 0.9, total charged time
at most 2^48 target-compression units, and peak memory at most 2^54 bytes under
collision-frontier-v5. The claimed scalar is 48.

Unlike a generic birthday construction, this attack exploits the dependency
graph of a single BLAKE3 round: with the eight column message words fixed, the
256-bit digest splits into two independent 128-bit halves, and each half is
exactly an XOR of a function of one 64-bit diagonal message pair. A collision
of each half is therefore a four-sum (Wagner) problem on 128 bits, solvable
with about 2^44 partial-round evaluations per half instead of the 2^128 full
evaluations a birthday search needs. The decomposition is exact algebra, not a
statistical approximation. The only heuristic premise concerns how many
four-sum solutions the induced finite lists contain; it is declared as
heuristic H1 with scoped experimental support, and its failure can only cause
a failure verdict, never a false collision, because every returned pair is
verified by two complete hash recomputations.

## 1. Exact complete hash

Each message is exactly 64 bytes, of bit length 512 < 2^64. A message is
sixteen little-endian 32-bit words w[0..15]; the message space D has size
2^512. There is no unknown IV, free-start state, or supplied prefix/advice.

H is unkeyed BLAKE3-256 with 1 prefix round in every compression. On exactly
64-byte messages there is one chunk, one full block, no parent, and exactly
one compression with CHUNK_START | CHUNK_END | ROOT = 11. The true block
length is 64 and both the chunk index and root-output counter are zero.

The eight-word IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

Initialize v[0..7]=IV, v[8..11]=IV[0..3], and v[12..15]=(0,0,64,11). All
additions are modulo 2^32; ROR rotates right within a 32-bit lane. The round
applies, on v, the eight calls

    G(0,4,8,12,w0,w1);    G(1,5,9,13,w2,w3)
    G(2,6,10,14,w4,w5);   G(3,7,11,15,w6,w7)
    G(0,5,10,15,w8,w9);   G(1,6,11,12,w10,w11)
    G(2,7,8,13,w12,w13);  G(3,4,9,14,w14,w15)

with G(a,b,c,d,x,y) defined by

    v[a] = v[a]+v[b]+x; v[d] = ROR(v[d] XOR v[a],16)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],12)
    v[a] = v[a]+v[b]+y; v[d] = ROR(v[d] XOR v[a],8)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],7).

Exactly the first 1 round is executed; the message permutation between rounds
never acts because no second round exists. The compression output is
o[i]=v[i] XOR v[i+8] and o[i+8]=v[i+8] XOR IV[i] for i=0..7, and the digest
H(m) is LE4(o[0]) || ... || LE4(o[7]), the first 32 root-output bytes. This
retains the ordinary hash's flags and feed-forward. The algorithm below only
generates 64-byte messages, so this one-root-compression description covers
every hash it evaluates, including final verification; no parent, chunk-chain,
or second root-output compression occurs on this domain.

## 2. The one-round decomposition

Name the diagonal message pairs

    E=(w8,w9), F=(w10,w11), Gp=(w12,w13), Hp=(w14,w15)

and call w0..w7 the column words. Fix the column words to arbitrary constants.

The four column G calls are applied first and involve only the fixed column
words, so the state after the column step is a constant vector
s[0..15] determined by the column words. The four diagonal G calls then act
on disjoint state words: G(0,5,10,15,E) writes only v0,v5,v10,v15;
G(1,6,11,12,F) writes only v1,v6,v11,v12; G(2,7,8,13,Gp) writes only
v2,v7,v8,v13; G(3,4,9,14,Hp) writes only v3,v4,v9,v14. Within each call, the
four updated words are deterministic functions of the constant pre-diagonal
state words and that call's two message words. Define, with the column words
fixed:

    a(E)  = (v0, v10, v5, v15)   after G(0,5,10,15,E)
    b(Gp) = (v8, v2, v13, v7)    after G(2,7,8,13,Gp)
    g(F)  = (v1, v11, v12, v6)   after G(1,6,11,12,F)
    d(Hp) = (v9, v3, v4, v14)    after G(3,4,9,14,Hp)

each a function from 64 bits to 128 bits, computable with one G call (14
primitive word operations) plus four constant state-word loads.

Theorem (exact decomposition). For every message with the fixed column
words, the digest words satisfy

    o0 = a0(E)  XOR b0(Gp)     o1 = g0(F) XOR d0(Hp)
    o2 = a1(E)  XOR b1(Gp)     o3 = g1(F) XOR d1(Hp)
    o4 = a2(E)  XOR b2(Gp)     o5 = g2(F) XOR d2(Hp)
    o6 = a3(E)  XOR b3(Gp)     o7 = g3(F) XOR d3(Hp)

where the component orderings are the ones in the displayed definitions:
o0=v0 XOR v8, o2=v10 XOR v2, o5=v5 XOR v13, o7=v15 XOR v7, and
o1=v1 XOR v9, o3=v11 XOR v3, o4=v12 XOR v4, o6=v6 XOR v14.

Proof. Feed-forward gives o[i]=v[i] XOR v[i+8] for i=0..7. For each i in
0..7, exactly one of {i, i+8} is written by exactly one diagonal call, and
the pairing is: v0(E) with v8(Gp); v1(F) with v9(Hp); v2(Gp) with v10(E);
v3(Hp) with v11(F); v4(Hp) with v12(F); v5(E) with v13(Gp); v6(F) with
v14(Hp); v7(Gp) with v15(E). No other message word reaches any of these
state words, because the only other message-touching calls are the column
calls, which use only the fixed column words. QED.

Consequently the 256-bit digest is D = L(F,Hp) || R(E,Gp) with

    R(E,Gp) = a(E) XOR b(Gp)        (words o0,o2,o5,o7; 128 bits)
    L(F,Hp) = g(F) XOR d(Hp)        (words o1,o3,o4,o6; 128 bits)

two independent 128-bit halves keyed by disjoint message variables.

Corollary (collision composition). If R(E1,Gp1) = R(E2,Gp2) with
(E1,Gp1) != (E2,Gp2) and L(F1,Hp1) = L(F2,Hp2) with (F1,Hp1) != (F2,Hp2),
then the two 64-byte messages

    m  = cols || E1 || F1 || Gp1 || Hp1
    m' = cols || E2 || F2 || Gp2 || Hp2

are distinct and satisfy H(m) = H(m') on all 256 bits: an ordinary collision
for the complete 1-round BLAKE3 hash. Both messages lie in the profile's
domain (64 bytes < 2^64 bits), use the standard IV, unkeyed mode, standard
flags and full output length.

## 3. The four-sum subproblem and the algorithm

A collision of one half, say R, is a quadruple (a1,a2,b1,b2) with
a1 = a(E1), a2 = a(E2), b1 = b(Gp1), b2 = b(Gp2) and a1 XOR a2 = b1 XOR b2,
i.e. a1 XOR a2 XOR b1 XOR b2 = 0, with (E1,Gp1) != (E2,Gp2). This is a
four-sum instance on 128 bits. Wagner's two-level algorithm solves such
instances with lists of size about 2^(128/3); the disjointness needed for a
genuine collision is enforced by construction below.

Parameters. s = 2^44 entries per sublist; c = 45 level-1 filter bits.
Caps: at most 2^45 level-1 pairs per side and at most 2^8 final matches per
half; if either cap is exceeded the algorithm halts with failure (this never
triggers under the success event analyzed below).

The algorithm, run independently for the R half (functions a,b, variables
E,Gp) and the L half (functions g,d, variables F,Hp):

1. Coins and column fixing. Draw the eight column words and any fixed
   cross-half variables uniformly at random (one 256-bit random word
   supplies eight 32-bit lanes). These coins, together with the list-entry
   coins below, are the algorithm's entire probability space.
2. Sublist generation. For the R half, fill four sublists A1,A2,B1,B2 with
   s entries each. An A-entry draws a fresh uniform 64-bit E with the top
   bit of w8 forced to 0 for A1 and to 1 for A2 (disjointness by
   construction), evaluates a(E) with one G call, and stores the record
   (value: 1 word holding the 128-bit half value, input: 1 word holding E).
   B-entries are symmetric with the top bit of w12 forced. The L half fills
   C1,C2,D1,D2 analogously with F,Hp. Disjoint top bits guarantee that any
   level-2 match has E1 != E2 and Gp1 != Gp2, hence (E1,Gp1) != (E2,Gp2).
3. Level-1 filter. Radix-sort each sublist by its low c=45 key bits
   (two stable counting-sort passes, a 32-bit digit then a 13-bit digit,
   deterministic worst case), so that all entries with equal low-45-bit
   keys become contiguous, then merge-join A1 with A2 on equality of the
   low c=45 bits, emitting pair records (asum = a1 XOR a2, E1, E2; three
   words). Emit analogously for B. Under the cap, at most 2^45 pairs per
   side are kept. The low 45 bits of every emitted asum are zero.
4. Level-2 match. Radix-sort each side's pair list by asum bits 45..127
   (83 bits, three counting-sort passes with 32-bit digits), then
   merge-join the two sorted pair lists on exact 128-bit asum equality.
   Each match is a four-sum solution a1 XOR a2 XOR b1 XOR b2 = 0 on all
   128 bits, i.e. R(E1,Gp1) = R(E2,Gp2) with (E1,Gp1) != (E2,Gp2).
5. Compose and verify. Take one R-half solution and one L-half solution,
   assemble m and m' as in the Corollary, recompute both complete hashes
   from the all-zero state (two target compressions, charged), check message
   distinctness and equality of all 256 output bits, and return the pair if
   verified. Any cap overflow, absent match, or failed verification halts
   with failure. There is one batch and no restart.

## 4. Correctness is heuristic-free

Every returned pair passes Step 5's explicit recomputation of the complete
target hash on both messages, so a false collision can never be returned:
the algorithm is sound regardless of any heuristic. The decomposition
theorem of Section 2 is exact algebra with no probabilistic content, and it
is additionally machine-checked during development against the trusted
reference `verifier/blake3.py:blake3` (rectangle identities
o(E1,Gp1) XOR o(E1,Gp2) XOR o(E2,Gp1) XOR o(E2,Gp2) = 0 on the R-half words
and the analogous L-half identities, plus cross-independence of the halves,
verified on random instances). The only probabilistic question is whether
Step 4 finds at least one match in each half, analyzed next.

## 5. Success probability and heuristic H1

The ideal-model analysis treats the four sublist value multisets of each
half as independent uniform random 128-bit strings. This is exactly the
content of the declared heuristic H1 (Section 7); nothing else in the
success analysis is assumed.

Under that model, for one half: the level-1 join of two s-entry sublists
produces a binomial-style pair count with mean s^2 / 2^c = 2^88 / 2^45 =
2^43 and standard deviation below 2^22, so the 2^45 pair cap (four times
the mean, over 2^21 standard deviations out) is exceeded with probability
far below 10^-6 by a Chebyshev bound; likewise for the other side. Each emitted pair-sum is
uniform on the 83 nonzero-filter bits, so the level-2 join of two pair
lists of size about 2^43 yields a match count with mean

    lambda = (s^2 / 2^c)^2 / 2^(128-c) = s^4 / 2^(128+c)
           = 2^176 / 2^173 = 8,

and the count is approximately Poisson, giving Pr[no match] <= e^{-8}
< 4 x 10^-4 per half. The two halves use disjoint variables and independent
coins, so

    Pr[success] >= (1 - e^{-8})^2 - 2 x 10^-6  > 0.9993

under H1, where the subtracted term covers both cap-overflow modes. The
claimed success_probability is 0.9, conservative against the ideal-model
0.9993 and above the required 0.39. If H1 should fail for the actual fixed
function, the outcome is a failure verdict, never an incorrect collision;
the claim's soundness does not depend on H1.

Why the ideal model is plausible here. Each sublist's entries are iid
samples a(E) with E uniform over a 63-bit affine slice. The maps a,b,g,d
are public fixed functions with 64-bit domains and 128-bit codomains, so
their value distributions are supported on at most 2^64 points; the
four-sum count of the sampled multisets, however, depends only on XOR
closure statistics, to which a random 2^64-point support is
indistinguishable from uniform at the sampled sizes. No differential,
linear, or independence property of the round function is assumed beyond
this closure-abundance statement. Section 7 declares H1 with its exact
scope, and the declared experiments measure the same algorithm on the same
fixed target at reduced constraint width.

## 6. Fully charged RAM implementation

One 256-bit word is 32 bytes. Each selected compression costs one unit;
every other listed RAM primitive costs 1/C units, C = 222. All bounds
include message construction, randomness, failed trials, sorting, matching,
verification, and fixed code/constants. There is no external disk,
unaccounted preprocessing service, precomputed collision, or free step.
All counts below are deterministic worst-case caps: every phase performs
its declared work on every execution path, and caps convert data-dependent
counts into fixed budgets.

Fixed storage. Fewer than 2^16 instruction templates suffice for the
displayed G formula, the radix passes, the merge-joins and the driver, each
template at most four words: at most 2^23 bytes of code. Another 2^23 bytes
cover constants, the column-state vector, cursors, and scratch. Fixed
storage is at most 2^24 bytes (2^19 words); initializing it costs at most
2^24 word operations and is the preprocessing charge: 2^24 / 222 < 2^17
units, so preprocessing_log2 = 17.

Per-entry generation (cap 32 word operations). One fresh random-word draw
(1 op; its low 63 bits supply the entry's diagonal pair after the partition
bit is forced, 2 ops), one G-call evaluation (6 additions, 4 XORs, 4
rotations = 14 ops), four constant state-word loads (4 ops), record stores
(2 ops), address and loop control (at most 9 ops). Total at most 32 ops per
entry. Eight sublists of s = 2^44 entries: at most 2^47 x 32 = 2^52 word
operations.

Sublist radix sort (cap 40 word operations per entry-pass). Each pass
zeroes a 2^32-counter bucket table and prefix-sums it (2 x 2^33 ops),
sweeps the list twice (count, then stable scatter). Per entry per pass:
key load, digit extract (shift+mask), counter load/increment/store, base
add, address shift/add, two record loads, two record stores, and control:
at most 20 ops, charged 40 for envelope. Two passes (32-bit then 13-bit
digits) sort the 45-bit key, so all equal low-45-bit keys become
contiguous; the second pass uses only 2^13 counters, within the same
bucket-table envelope. Per half: 4
lists x 2 passes x 2^44 x 40 = 2^52.3 word operations; both halves 2^53.3.
Bucket-table work over all 28 list and pair passes is below 2^39,
negligible by comparison.

Level-1 join (cap 2^51 word operations total). Per half there are two
joins (A1 with A2, B1 with B2). Each merge scans both sorted sublists once
(2 x 2^44 records, at most 8 ops each: two key loads, masked compare,
branch, cursor advances, control; 2^48 per join) and emits at most 2^45
pair records per side (cap), each costing at most 8 ops (one XOR, three
stores, counter, control; 2^48.3 per side). Per half: below 2^50.1. Both
halves: below 2^51.1.

Pair-list radix sort (cap 2^54 word operations total). Pair records are
three words; the sort key is asum bits 45..127 (83 bits), three passes
with 32-bit digits. Per half: 2 sides x 3 passes x 2^45 records x 40 ops =
2^52.9. Both halves: 2^53.9. (Records beyond the 2^45 cap are never
produced; the cap sizes the arrays.)

Level-2 join and recovery (cap 2^51 word operations total). The final
merge scans two sorted pair lists per half (2 x 2^45 records x 8 ops =
2^49.3 per half, 2^50.3 both halves), keeps at most 2^8 matches per half,
and the driver then assembles and verifies one pair per half: message
assembly, two complete target compressions (charged as 2 units, not word
operations), distinctness and digest equality checks: below 2^20 word
operations.

Total charged time. Summing the caps:

    word ops <= 2^24 (setup) + 2^52 (generation) + 2^53.3 (list sorts)
              + 2^39 (buckets) + 2^51.1 (level-1) + 2^53.9 (pair sorts)
              + 2^50.3 (level-2) + 2^20 (recovery)
              < 2^55.1

    T <= 2 compressions + 2^55.1 / 222  <  2 + 2^47.3  <  2^48.

The claimed scalar is time_log2 = 48, about 0.7 bits above the capped
ledger; the per-activity envelopes themselves are charged at roughly twice
the counted operations, so the effective margin is larger. The dominant
terms are generation and sorting of the 2^47 sublist entries; no term
relies on unit-cost high-level operations.

Memory. Per half, four sublists of 2^44 two-word records occupy 2^52
bytes; the two capped pair lists occupy at most 2 x 2^45 x 96 = 2^52.6
bytes and coexist with the sublists only during level 1; the bucket table
is 2^37 bytes, reused across passes; fixed storage is 2^24 bytes. Each
stable counting-sort pass scatters into an auxiliary output array the size
of the list being sorted; lists are sorted one at a time, so one scratch
array sized for the largest list (a capped pair list, 2^45 x 96 = 2^51.6
bytes) is reused across all list and pair passes. Halves
are processed sequentially and reuse the same arrays, so

    peak bytes <= 2^52 + 2^52.6 + 2^51.6 + 2^37 + 2^24 < 2^54.

The claimed memory_log2_bytes is 54. Memory is an abstract RAM allowance,
reported as a metric only, with no scalar contribution.

Data and advice. Complete-hash evaluations number exactly 2 (the final
verification), so data_log2 is omitted as the schema recommends for new
claims; all list evaluations are partial single-G computations charged as
word operations, never as compressions. Nonuniform advice is zero: the
program contains only public constants and code, fully charged in fixed
storage, so nonuniform_advice_log2_bytes = 0.

## 7. Heuristic declaration and evidence

H1 (four-sum abundance; role: score-critical). Statement: for the fixed
blake3-r1-prefix-v1 target, when the column words and the sublist entries
are drawn from the algorithm's independent uniform coins, the four-sum
match counts produced by Steps 3-4 in each 128-bit half follow the
ideal-model law of Section 5; in particular, at s = 2^44 and c = 45 each
half yields at least one level-2 match with probability at least 0.999, and
the pair-count caps are exceeded with probability below 10^-6.

Scope. H1 is used only for the success-probability analysis of Section 5.
The decomposition (Section 2), collision correctness and soundness
(Section 4), and every resource bound (Section 6) are proved without it.
H1 asserts nothing about differentials, linear trails, round independence,
or output uniformity of the target; it concerns only XOR-closure abundance
of four explicitly constructed sublist multisets at the stated sizes.

Evidence. experiment:wagner-rhalf-mask32 and experiment:wagner-lhalf-mask32
execute the identical two-level four-sum search, on the same fixed target
and the same G-call subroutines, constrained to 32 of the 128 half bits
with s = 2048 and c = 11, over 256 independent organizer-seeded trials per
half. The ideal model predicts per-trial success 1 - e^{-2} = 0.8647. The
organizer-recomputed execution of this exact package measured 229/256 =
0.895 for the R half and 209/256 = 0.816 for the L half, bracketing the
prediction (mean 0.855). A separate development scaling check at 64
constrained bits (s = 2^22, c = 22, predicted 1 - e^{-4} = 0.982) also
succeeded on its trials; the trusted evidence for the judge is the executed
32-bit report. The prediction verified is the scaling law
lambda = s^4 / 2^(m+c) with m the constrained width, evaluated at m = 32
against 256-trial frequencies.

Extrapolation. The claim extrapolates the validated law from m = 32 (and
the development point m = 64) to m = 128, with list sizes scaled from
2^11 to 2^44 exactly as the law prescribes. The target function, the
decomposition, and the algorithm are unchanged; only the constraint width
and list sizes grow.

Limitations. Small-width success does not prove 128-bit abundance; the
value distributions could in principle deviate from the ideal model at
larger width in a way the experiments do not detect, and no full-scale
execution is performed or claimed. The 256-trial frequencies are
organizer-recomputed mask events, not iid success-probability estimates,
and the program's internal counters are untrusted observations. Failure of
H1 produces a failure verdict, never a false collision. The attack says
nothing about BLAKE3 with two or more rounds: the message permutation and
the second round mix every state word, destroying the decomposition.

## 8. Interpretation

This is a structural attack on the organizer-selected exploration target,
not a generic birthday repackaging: the charged work is about 2^47 partial
evaluations plus sorting, versus 2^128 full compressions for a birthday
search at comparable success. The required baseline_improved identifier
blake3-r1-nominal-v2 names the organizer's nominal display reference 128,
which is not an established attack, qualified baseline, or security bound;
the claimed scalar 48 is below that nominal reference, and no Pareto or
rigorous-lane claim follows from it. Exploratory qualification is
plausible_not_refuted, an AI review outcome, not mathematical proof or
human acceptance. submission_state = ready means this package is complete
for review; it asserts no qualifying review, emitted score, human
acceptance, or Yukon promotion by itself.
