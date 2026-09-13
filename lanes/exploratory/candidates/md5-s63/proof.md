# MD5-s63: exploratory low-memory generic collision search

This package fixes `md5-s63-prefix-v1`, 63 steps, ordinary collisions,
`collision-frontier-v3`, and the exploratory lane. It replaces the stored-sample
birthday batch of the initial candidate with a distinguished-point collision
search over trajectories of a fixed iteration function, in the style of the
van Oorschot-Wiener collision search, specialized to one walk with restarts.
All resource fields are deterministic upper bounds enforced by a hard
per-evaluation budget check and hard table caps. All empirical content is
isolated in two explicitly declared heuristics, H1 and H2, about the iteration
statistics of the fixed target function; the success probability is conditional
on them and is derived below, including an explicit cycle-occupancy analysis of
the post-repeat regime. The required `baseline_improved` value
`md5-s63-nominal-v2` is an organizer identifier only: its nominal exponent 64
is not an established attack, qualified baseline, or security bound, and this
submission does not claim to improve it. An eventual AI qualification is
distinct from mathematical or human acceptance, and an exploratory
qualification does not qualify the rigorous sibling lane.

## 1. Exact message family and complete hash

Let N = 2^128. For a 128-bit word w, let m(w) be its 16-byte little-endian
encoding, including leading zero bytes. This encoding is injective. Every m(w)
has exactly 128 bits, within the profile's bit-length limit 2^64. The input
domain of the iteration function below has N elements. No IV is chosen by the
algorithm.

Every m(w) receives the mandatory complete-message MD5 padding: append byte
0x80, then 39 zero bytes, then the eight-byte little-endian integer 128. Thus
there is exactly one 64-byte block. Split into sixteen 32-bit little-endian
words M[0], ..., M[15], this block is M[j] = (w >> (32*j)) AND 0xffffffff for
0 <= j < 4, M[4] = 0x80, M[5] through M[13] = 0, M[14] = 128, and M[15] = 0.

Here is the exact compression and output definition. All intermediate MD5 state
values are reduced modulo 2^32, NOT means the 32-bit complement, and ROL32(v,s)
is ((v << s) OR (v >> (32-s))) AND 0xffffffff after masking v to 32 bits.
Start (a,b,c,d) = (A0,B0,C0,D0) =
(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476).
For i = 0,1,...,62 in that order, use these original-index rules:

| Index i | F | g | rotation s, repeating every four steps |
| --- | --- | --- | --- |
| 0..15 | (b AND c) OR ((NOT b) AND d) | i | 7,12,17,22 |
| 16..31 | (d AND b) OR ((NOT d) AND c) | (5*i+1) mod 16 | 5,9,14,20 |
| 32..47 | b XOR c XOR d | (3*i+5) mod 16 | 4,11,16,23 |
| 48..62 | c XOR (b OR (NOT d)) | (7*i) mod 16 | 6,10,15,21 |

Perform the simultaneous assignment
(a,b,c,d) := (d, b + ROL32(a+F+K[i]+M[g],s), b, c), modulo 2^32.
The 63 constants K[0] through K[62], in index order, are the following
literal hexadecimal integers. They are public program constants, with storage
and loading charged below; there is no run-time trigonometric computation.

```text
d76aa478 e8c7b756 242070db c1bdceee f57c0faf 4787c62a a8304613 fd469501
698098d8 8b44f7af ffff5bb1 895cd7be 6b901122 fd987193 a679438e 49b40821
f61e2562 c040b340 265e5a51 e9b6c7aa d62f105d 02441453 d8a1e681 e7d3fbc8
21e1cde6 c33707d6 f4d50d87 455a14ed a9e3e905 fcefa3f8 676f02d9 8d2a4c8a
fffa3942 8771f681 6d9d6122 fde5380c a4beea44 4bdecfa9 f6bb4b60 bebfbc70
289b7ec6 eaa127fa d4ef3085 04881d05 d9d4d039 e6db99e5 1fa27cf8 c4ac5665
f4292244 432aff97 ab9423a7 fc93a039 655b59c3 8f0ccc92 ffeff47d 85845dd1
6fa87e4f fe2ce6e0 a3014314 4e0811a1 f7537e82 bd3af235 2ad7d2bb
```

After step 62, feed forward every word: (A,B,C,D) =
(A0+a, B0+b, C0+c, D0+d), modulo 2^32. The digest is the 16-byte concatenation
LE32(A) || LE32(B) || LE32(C) || LE32(D). Write H(w) for its injective numeric
encoding A + (B << 32) + (C << 64) + (D << 96), stored in one 256-bit RAM word
with upper 128 bits zero. Numeric equality of H values is equality of all 16
digest bytes. There is no truncation or omitted padding block. This definition
matches the selected profile and its organizer digest reference
(`verifier/hash_functions.py:digest` with algorithm md5 and rounds 63). In
particular, step 63 of full MD5 is not executed; MD5-s64 is a different target.

## 2. The iteration function

Define f(w) = H(w) on {0,1}^128. By Section 1, one evaluation of f is exactly
one evaluation of the complete md5-s63 hash of the one-block message m(w), which
uses exactly one selected 63-step target compression. The charged wrapper around
that compression is ledgered in Section 6. A collision of f, meaning words u,v
with u != v and f(u) = f(v), yields messages m(u) != m(v) by injectivity of the
encoding, both in the message domain, with byte-equal complete md5-s63 digests:
precisely the target relation of the profile. The algorithm below only ever
outputs such verified pairs.

## 3. Algorithm: one distinguished-point walk with restarts

Parameters, all fixed public constants:

| Symbol | Value | Meaning |
| --- | --- | --- |
| N | 2^128 | digest space size |
| d | 56 | distinguished-point prefix length |
| D(v) | v < 2^72 | distinguished predicate (top 56 bits zero) |
| G | 2^60 | inactivity limit: abandon a walk after G steps with no distinguished point |
| C | 2^14 | hard cap on stored table records |
| E | 2^20 | hard cap on processed distinguished-point events |
| Q | 2^66.1 | hard cap on total f evaluations, including recovery and verification |

State: a table T implemented as an unordered array of at most C records, each
occupying two 256-bit words: the first word packs the 128-bit distinguished
value in its lower half and the 128-bit walk start in its upper half, and the
second word holds the walk length ell at which the value was stored. There is
no hashing and no probing: lookup is a linear scan, insertion is an append, so
table behavior has no distributional premise. Further state: the current point
w, the current walk's start s and length ell, the number g of steps since the
walk's last distinguished-point hit, the global evaluation counter t, and the
distinguished-point event counter e.

Evaluation guard. Every evaluation of f, in every phase, is preceded by the
check t < Q; if t = Q the algorithm halts with failure immediately, including
inside RECOVER and inside the final verification. This makes Q a deterministic
cap on total evaluations, not merely a main-loop condition.

Initialization (before the main loop). Draw one fresh independent uniform
256-bit word using the cost-model primitive, mask it to its lower 128 bits, and
set s := w := that value, ell := 0, g := 0, t := 0, e := 0, T empty. The first
walk therefore starts uniformly at random, which is what the success analysis
of Section 5 requires.

Main loop. Repeat forever (every f evaluation guarded as above):

1. w := f(w); t := t+1; ell := ell+1; g := g+1.
2. If g > G, abandon the walk: draw one fresh independent uniform 256-bit
   word, mask it to its lower 128 bits, set s := w := that value, ell := 0,
   g := 0, and continue. Table records of abandoned walks are retained.
3. Else if D(w): set g := 0. If e = E, continue (event cap reached; table work
   is skipped). Otherwise e := e+1 and scan T for a record with value w.
   a. If a record (w, s', ell') is found, run RECOVER (below) on
      (s, ell, s', ell'). If RECOVER returns a pair (u,v), evaluate f(u) and
      f(v) directly (guarded, charged in t), check u != v and f(u) == f(v),
      and on success output (m(u), m(v)) and halt. If RECOVER reports
      degenerate, abandon the walk as in step 2 and continue. Verification
      cannot fail on a non-degenerate RECOVER pair; the check is defensive.
   b. Else, if T holds fewer than C records, append (w, s, ell).
   c. Else (table full), continue.

If the evaluation guard ever fires, the algorithm has already returned failure.
There is one batch, no restart of the whole search, no amplification, and no
early stop before success or budget exhaustion. Walk restarts after abandonment
are part of the loop and draw their randomness from the charged primitive.
Because lookup is a complete scan, a value already in T is always found, so no
duplicate records arise.

RECOVER(s1, ell1, s2, ell2). Both trajectories reached the same distinguished
value: the trajectory from s1 at length ell1 equals the trajectory from s2 at
length ell2. Assume ell1 <= ell2 (else swap) and write delta = ell2 - ell1.
Walk A starts at s1 and walk B starts at s2. Advance B by delta evaluations
(each guarded, charged in t). Then step A and B in lockstep for
t' = 0,1,...,ell1, keeping the previous values pa,pb: one lockstep step
evaluates both f(A) and f(B) (two guarded evaluations, charged in t). At the
first t' with A_{t'} == B_{t'}, stop. If t' = 0, report degenerate. Otherwise
return (pa, pb) = (A_{t'-1}, B_{t'-1}).

## 4. Correctness

The algorithm outputs only pairs that pass the explicit final check u != v and
f(u) == f(v) evaluated directly from Section 1, so there are no false
positives: any output is a verified ordinary collision of the exact target on
two distinct 16-byte messages. It remains to show that RECOVER, whenever it is
non-degenerate, returns a pair passing this check, and that a trajectory repeat
is detected whenever one occurs, up to the bounded losses of Section 5.

Recovery lemma. Write the trajectory values from any start as x_0, x_1, ...
with x_{i+1} = f(x_i), deterministic. RECOVER is invoked with
x^1_{ell1} = x^2_{ell2} and ell1 <= ell2. With delta = ell2 - ell1, the
lockstep compares A_{t'} = x^1_{t'} and B_{t'} = x^2_{t'+delta} for
t' = 0,...,ell1. Agreement occurs at t' = ell1 at the latest, because
x^1_{ell1} = x^2_{ell2} = x^2_{ell1+delta}. Let t* be the first agreement.
If t* >= 1, then f(A_{t*-1}) = A_{t*} = B_{t*} = f(B_{t*-1}), and
A_{t*-1} != B_{t*-1}, because equality would be an agreement at t*-1 < t*.
So the returned pair is a genuine collision of f. If t* = 0, then
x^1_0 = x^2_{delta}: for a single walk (s1 = s2) this means the trajectory
returned to its exact start; for two walks it means one start lies on the
other's trajectory at offset delta. Both are reported degenerate and the walk
is abandoned. Hence every RECOVER call either yields a verified collision of
distinct words or is detected as degenerate. No silent failure mode exists.

Detection. If any value repeats within the current walk, or between the current
walk and a retained abandoned walk, consider the first such repeat in
trajectory order. The repeated value lies on a cycle that the current walk then
follows. The walk keeps iterating; the next distinguished point it reaches on
that cycle was already stored during the first pass over the cycle (or by the
other walk), so the scan in step 3a finds it and RECOVER is invoked. Detection
fails only when (a) the cycle contains no distinguished value at all, or (b)
the walk is abandoned (g > G) before reaching the next distinguished point on
the cycle, or (c) the relevant record was never inserted (table full or event
cap). All three losses are bounded in Section 5; loss (a) is the cycle-
occupancy event analyzed there, not a geometric-gap event: after the repeat the
trajectory is periodic, and this analysis does not assume otherwise.

## 5. Probability analysis and declared heuristics

The probability space consists of the algorithm's fresh independent uniform
random words (the initial start and each restart start), with f fixed and
deterministic. No seeded PRNG or hash-distribution assumption is used for the
coins. Two heuristic premises about the fixed f are declared in claim.json and
supported here as far as current techniques allow; they are the entire
empirical content of the success analysis.

H1 (score-critical). For f of Section 2, forward trajectories x_{i+1} = f(x_i)
from uniform random starts have the collision statistics of a uniform random
mapping on N points: conditional on x_0,...,x_{i-1} being distinct, x_i is
uniform on the N digest values, for all trajectory lengths up to 2^66.

Exact random-mapping derivation. For a uniform random mapping, given that
x_0,...,x_{i-1} are distinct, the value f(x_{i-1}) has not been queried before
and is uniform and independent of the trajectory so far, so
Pr[x_i not in {x_0,...,x_{i-1}}] = 1 - i/N exactly. Multiplying,

    Pr[no repeat in the first t steps] = product_{j=1}^{t} (1 - j/N)
      <= exp(-t(t+1)/(2N)),

using 1-u <= exp(-u). This product formula is exact for a uniform random
mapping; H1 asserts it for the fixed f. With t0 = 2^64.4,

    t0*(t0-1)/(2N) >= 2^128.8/2^129 * (1 - 2^-64.4) >= 0.87,

so Pr[first repeat within t0 steps] >= 1 - exp(-0.87) >= 0.581, where
exp(-0.87) <= 0.4190 follows from bracketing the alternating series for
exp(-0.87) between consecutive partial sums.

H1 is the standard iteration heuristic underlying birthday-bound security
claims, including the organizer's nominal reference exponent 64 for MD5, and
underlying the classical analyses of rho and distinguished-point collision
search. Two honest qualifications are recorded. First, uniform one-step output
distributions do NOT by themselves imply trajectory collision statistics: a
permutation has uniform marginals, yet every repeat under iteration is a
degenerate cycle closure and the algorithm of Section 3 always fails on one.
Whether f is permutation-like is unproven either way; f derives from a
many-to-one compression construction (512 message bits and the 128-bit state
are compressed to 128 bits), and no evidence suggests permutation-like
behavior, but this remains an assumption, not a theorem. Second, the
distribution-free birthday inequality for independent samples (uniform output
is the worst case for collision probability) applies to iid sampling only; it
does not transfer to iterated trajectories and is recorded as context, not as
support for H1. H1 is the load-bearing unproven premise of this package.

H2 (supporting, pre-repeat regime only). Before a trajectory's first repeat,
distinguished-point hits behave as Bernoulli trials with probability 2^-56 per
step: pre-repeat gaps between consecutive distinguished points are geometric
with mean 2^56, and Pr[pre-repeat gap > 2^60] <= (1 - 2^-56)^(2^60) <=
exp(-16) <= 1.2 * 10^-7. Derivation under H1: given distinct pre-repeat values,
each was uniform when drawn, so for any fixed set of G consecutive pre-repeat
positions the probability that none is distinguished is
C(N - 2^72, G)/C(N, G) <= (1 - 2^-56)^G, the without-replacement bound. H2 is
used only for the pre-repeat abandonment rate and the expected table occupancy.
H2 makes NO claim about the post-repeat regime: after the first repeat the
trajectory is periodic, distinguished-point indicators are fixed by the cycle,
and the detection analysis below uses cycle occupancy instead of any geometric
post-repeat gap model.

Success probability. The search succeeds whenever (i) the first walk's
trajectory repeats within t0 = 2^64.4 steps; (ii) the cycle entered at that
repeat contains at least one distinguished value; (iii) no gap between
distinguished points exceeds G = 2^60 before detection, including the
post-repeat distance from the repeat point to the next distinguished value on
the cycle; (iv) the first RECOVER is non-degenerate; and (v) the table and
event caps are not exceeded before detection. Under H1 and H2:

- (i) contributes Pr >= 0.581, derived above.
- (ii) cycle occupancy. Conditional on the first repeat occurring at step j,
  the repeated value x_j equals x_i with i uniform on [0, j-1] (under H1, x_j
  is uniform given the distinct trajectory so far), so the cycle length
  lambda = j - i is uniform on [1, j]. The lambda cycle values are distinct
  pre-repeat draws, so the probability that none is distinguished is
  C(N - 2^72, lambda)/C(N, lambda) <= (1 - 2^-56)^lambda. Averaging over the
  uniform lambda and summing over the first-repeat density
  Pr[first repeat at j] = (j/N) * product_{i<j}(1 - i/N) <=
  (j/N) * exp(-j(j-1)/(2N)):

      Pr[repeat by t0 with a distinguished-free cycle]
        <= sum_{j <= 2^56} (j/N) * 1
           + sum_{2^56 < j <= t0} (j/N) * exp(-j(j-1)/(2N)) * (2^56/j)
        <= 2^112/(2N) + (2^56/N) * (1 + integral_0^inf exp(-x^2/(2N)) dx)
        = 2^-17 + (2^56/N) * (1 + sqrt(pi*N/2))
        <= 7.6 * 10^-6 + 2^56 * 2^-128 * 1.2534 * 2^64
        <= 7.6 * 10^-6 + 0.0049 <= 0.005.

  On this event the walk never detects the collision and is eventually
  abandoned; later walks cannot detect it either, because the cycle's values
  are never stored. The bound charges the full 0.005 as loss.
- (iii) gap losses. The number of distinguished-point hits before step t0
  exceeds 2^10 with probability below 10^-100 under H1 (the hit count is
  dominated by a binomial with mean t0/2^56 = 2^8.4; Chernoff). A union bound
  over at most 2^10 pre-repeat gaps gives Pr[some pre-repeat gap > G] <=
  2^10 * 1.2 * 10^-7 <= 1.3 * 10^-4. For the post-repeat gap, condition on
  event (ii) (the cycle has k >= 1 distinguished values) and on lambda. If
  lambda <= G the gap is at most lambda <= G and there is no loss. If
  lambda > G, the k distinguished positions are exchangeable on the cycle, so
  the distance from the repeat point to the next distinguished position exceeds
  G with probability E[(1 - G/lambda)^k | k >= 1] <= E[(1 - G/lambda)^k] /
  Pr[k >= 1] <= exp(-G/2^56) / (1 - exp(-lambda/2^56)) <= 1.2 * 10^-7 /
  (1 - 1.2 * 10^-7), using k ~ Binomial(lambda, 2^-56) up to the
  without-replacement adjustment. Total (iii) <= 1.3 * 10^-4 + 1.3 * 10^-7.
- (iv) degeneracy requires x^1_0 = x^2_delta; for a single walk this means the
  trajectory returns to its exact start, with probability at most
  (t0 + G)/N <= 2^65.5/2^128 = 2^-62.5 under H1; for two walks it requires a
  start collision, probability at most 2^-127 per pair of starts, with fewer
  than 2^7 starts in any run.
- (v) cap overflows. Distinguished-point events before detection number at most
  the distinguished hits in t0 + 2G steps, dominated by a binomial with mean
  2^9.5 under H1; the entry cap C = 2^14 and event cap E = 2^20 are exceeded
  with probability below 10^-1000 by Chernoff. On overflow the algorithm skips
  table work, so overflow can only lose the detection, which is charged here.

Combining, Pr[success] >= 0.581 - 0.005 - 1.3 * 10^-4 - 2^-62.5 - 10^-1000
>= 0.5757. The claim field `success_probability: 0.57` is this
heuristic-conditional lower bound, not an exact success estimate, not reviewer
confidence, and not a physical feasibility statement.

Budget consistency. On the success event, with the repeat at trajectory
position rho <= t0 and detection at length ell2 <= rho + G (event (iii) bounds
the post-repeat distance by G), the total number of f evaluations is at most
ell2 (main loop) + (ell1 + ell2) (recovery: delta advance plus lockstep,
delta + 2*t* <= ell1 + ell2) + 2 (verification) <= ell1 + 2*ell2 + 2 <=
3*(t0 + G) + 2 = 3*(2^64.4 + 2^60) + 2 <= 2^65.99 + 2 < Q = 2^66.1, so the
evaluation guard does not bind on the success event. Restarts occur only off
the analyzed success path; each abandoned walk costs at most G evaluations and
one random word, and the guard caps their total effect deterministically.

Scope, extrapolation, and limitations. H1 and H2 are asserted only for the
fixed f of Section 2, for trajectory lengths up to 2^66, and only as premises
for this algorithm's success probability. The extrapolation is from the exact
uniform-random-mapping statements to one fixed deterministic function; this is
the standard premise of generic collision search, but it is unproven for this
f. A pathological iteration structure could defeat the construction in two
different ways: permutation-like behavior makes every repeat degenerate
(Section 4 detects this and abandons; success would be zero), and an
anomalously distinguished-point-free cycle cover defeats detection (bounded in
expectation by event (ii) only under H1). Neither is known for MD5 variants;
both are disclosed as exploratory-lane uncertainty. H1 and H2 are not asserted
to rigorous-lane standards. One small-scale executable experiment supporting
both premises is declared and specified in Section 6.

## 6. Declared experiment: trajectory prefix-collision probe

The package declares one small-scale executable experiment,
`trajectory-prefix-collision-v1` (experiments/manifest.json), executed by the
organizer's bounded, networkless Docker executor. The submitted Python source
(experiments/probe.py) is inert, untrusted review material and runs only in
that sandbox; it uses the standard library only, is deterministic in the
organizer seeds, and retains no ambient state.

Design. For each of 256 organizer-seeded trials, the program iterates the
claim's exact function f (Sections 1-2) from a SHAKE-256-derived start for at
most K = 512 steps, tracking the leading 16 digest bits (digest bytes 0-1,
the low half of the A word). On the first prefix match it returns the two
distinct 16-byte messages whose digests share the prefix; otherwise it returns
two nulls. The organizer independently recomputes both messages' complete
md5-s63 digests with the trusted reference and checks the declared
digest-xor-mask event (mask ffff00...00, expected zero) and message
distinctness. Participant-internal counters are labeled untrusted by the
runner; only the recomputed output predicate is checked.

Prediction under H1 and H2. One trial evaluates K trajectory values, giving
C(K,2) pairs; each pair shares the 16-bit prefix with probability 2^-16, so
the model predicts per-trial success
1 - exp(-K^2 / 2^17) = 1 - exp(-2) ~= 0.865, i.e. about 221 of 256 trials.
The measured success frequency on the real fixed target is directly
comparable to this prediction.

What it supports and what it does not. Agreement between the measured
frequency and the prediction is relevant supporting evidence that H1 and H2
describe the real f; material disagreement would refute them at this scale.
The experiment does NOT establish full-size 128-bit trajectory behavior:
small-scale prefix experiments do not prove independence or uniformity across
the full digest space, per-trial success is not an iid probability estimate
(the runner's own caveat), and the organizer seeds are public (the runner's
selection-bias warning applies). It is supporting evidence only, disclosed
under the review policy; the score-critical content of H1 remains the
analytic premise of Section 5.

Development rehearsal. A local rehearsal of the identical program with 256
non-organizer test seeds returned 218 of 256 successful pairs (model
prediction about 221), each returned pair verified against the organizer
reference digest; this rehearsal is development context, not evidence. The
official result is the organizer's seeded run in the review workflow, whose
report binds the manifest, source, seeds, and checked outcomes.

## 7. Explicit 256-bit word-RAM resource ledger

Every primitive listed by `collision-frontier-v3` costs one unit, as does one
selected 63-step target compression. One evaluation of f is one such
compression plus the wrapper counted below. Padding, loading the IV and input,
packing and unpacking, calls and returns, address arithmetic, loop counters,
comparisons, branches, and storage outside that primitive are charged
separately. No multiplication, unbounded integer, dynamic library, hash-table
primitive, or unit-cost sort is used: the table is a plain array with linear
scan and append. Every index, pointer, length, address, and counter is less
than 2^80 and fits in a single 256-bit word. As in the initial candidate, use a
direct RAM instruction encoding with an opcode and at most three operand or
immediate words, at most four 256-bit words per instruction, and allow the
five-operation scratch expansion of every simple statement (two operand loads,
the primitive, one result store, one transfer of control), even where registers
would avoid it.

Per-iteration cost. One main-loop iteration executes: four word extractions
M[j] = (w >> (32*j)) AND 0xffffffff with stores (4 statements); one target
compression (1 unit); packing H(w) from A,B,C,D (2 statements); the
distinguished test w < 2^72 with its branch (2); increments of t, ell, g (3);
the evaluation-guard test with branch (2); the abandonment test with branch
(2). That is 15 simple statements, at most 75 expanded operations, plus one
compression: at most 76 units, charged as 112 per iteration for margin.
Distinguished-point iterations add the event-cap test, a linear scan of at most
C = 2^14 records (per record: one word load, one half-word compare, one branch;
at most 3 * 2^14 expanded operations), and at most one two-word append with a
count update (at most 8 expanded operations): at most 2^15.6 units per event.
Distinguished-point event processing is hard-capped at E = 2^20 events total,
so this extra work is at most 2^15.6 * 2^20 <= 2^35.6 units in the entire run,
regardless of f. Walk abandonment costs one random word, one mask, and a few
stores per restart; restarts number at most Q/G + 1 <= 2^7, contributing less
than 2^11 units. Recovery performs at most ell1 + ell2 evaluations, each
charged the same 112 units through the shared counter t, and the final
verification costs 2 evaluations and a few comparisons. Static setup -
installing fewer than 4096 encoded instructions (at most 2^19 bytes of code),
the 63 K constants, rotations, IV, masks, the block template, and zeroing the
table region (2^15 word stores with loop overhead) - costs at most 2^20
operations.

Total time. The evaluation guard caps all f evaluations, including recovery and
verification, at Q = 2^66.1. Hence

    T <= 112 * Q + 2^35.6 + 2^11 + 2^20
       <= 2^72.81 + 2^35.6 + 2^11 + 2^20
       < 2^73.

All randomness draws, abandoned walks, scans, recovery, verification, and
initialization are included; there is no restart of the whole search to average
away. `time_log2: 73` is this deterministic upper bound on total charged work,
not the exponent of the expected productive evaluations (which is about 2^64.4
under H1).

Peak memory. The table holds at most C = 2^14 records of two words each:
2^15 words = 2^20 bytes, including all retained walk starts and lengths. Code
occupies at most 2^19 bytes; the constants, block template, walk state
(w, s, ell, g, t, e), recovery registers, and the two output messages occupy at
most 2^13 bytes. Thus M <= 2^20 + 2^19 + 2^13 < 2^21 bytes, justifying
`memory_log2_bytes: 21`. No recursive stack, no retained random tapes, and no
unbounded structure are used; the caps make this bound independent of H1 and
H2. Byte addresses need at most 21 bits.

Data. The number of complete input-message evaluations supplied to the fixed
digest operation is at most Q + 2 <= 2^66.1 + 2 < 2^67, justifying
`data_log2: 67`. Each evaluation hashes a 16-byte message padded to one 64-byte
block; these volumes are generated and charged, not stored. No external corpus
is provided.

Preprocessing. Static setup plus table zeroing costs at most 2^20 < 2^21
operations, justifying `preprocessing_log2: 21`; it is included in T. There is
no hash search before the charged run and no input-dependent compilation or
advice search.

Advice. `nonuniform_advice_log2_bytes: 0` means an upper bound of one byte,
consistent with actual zero bytes of nonuniform advice (the schema does not
permit log(0)). Fixed public code and constants are counted in memory and
setup even though they are uniform, not advice. No stored collision is given
free of construction cost.

Scalar. The proposed scalar is 73 + 21 = 94, emitted only if the selected lane
qualifies; it is not an already emitted score and does not by itself assert
Pareto dominance or improvement over the nominal reference identifier.

## 8. Evidence, applicability, and limitations

The analytic evidence consists of the exact target definition (Section 1), the
concrete algorithm and its correctness lemma (Sections 3-4), the
heuristic-conditional probability analysis including the post-repeat
cycle-occupancy bound (Section 5), the declared small-scale experiment
(Section 6), and the resource ledger (Section 7). The claim's heuristic list
contains exactly H1 and H2; there are no further implicit premises: the
resource bounds are deterministic, the table has no hashing or probing
distribution to assume, and the success probability is conditional on H1 and
H2 alone. The package contains an empty certificate manifest and declares one
experiment manifest with one executable probe; no full-scale execution or
concrete collision certificate is reported, so the heuristics rest on the
stated analytic support plus the small-scale measured consistency of Section 6.
Known
MD5 cryptanalysis (practical differential collisions for the full 64-step
function) is context showing the target family is weak; this construction uses
no differential structure and remains correct without it. As a deterministic
mechanics check, the packaged evidence was run through the organizer's
paired-review pipeline with a stub client returning schema-valid reviews that
cover the declared heuristic IDs: gating, binding, context validation,
heuristic coverage, and lane aggregation all completed without infrastructure
failures, so the package exercises no pipeline path that a heuristic-free
package would not. An exploratory qualification of this package would be an AI
review outcome under paired-lanes-v1, not mathematical proof, human
acceptance, or a rigorous-lane result.
