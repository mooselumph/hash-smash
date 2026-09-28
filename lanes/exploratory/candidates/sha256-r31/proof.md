# SHA-256, 31 prefix rounds: memory-efficient distinguished-point collision search

The scalar below is `time_log2` under `collision-frontier-v5`. Memory is a
separately reported resource bound with no scalar contribution.

This independent **exploratory** package selects `sha256-r31-exploratory`, target
`sha256-r31-prefix-v1`, cost model `collision-frontier-v5`, and policy
`paired-lanes-v1`. It submits a complete analytic algorithm, not an already
computed collision. Readiness requests review; it does not assert an AI outcome
or human acceptance.

It is the classical van Oorschot--Wiener parallel collision search with
distinguished points, applied to a single-block SHA-256-r31 iteration. It
reaches `time_log2 = 129` using only about `2^47` bytes of memory, instead of
the `2^138` bytes a stored birthday table needs. Unlike the unconditional
birthday construction, its running-time bound rests on **one declared,
score-critical heuristic**: that the fixed single-block iteration behaves as a
random mapping for the purpose of expected rho collision time. That heuristic is
disclosed in full below and in `claim.json`. The required `baseline_improved`
value `sha256-r31-nominal-v2` only identifies the organizer's nominal display
reference; this package does not claim improvement over that 128-bit reference
and uses no property of the round reduction.

## 1. Exact message and complete-hash definition

Write BE_k(v) for the k-byte big-endian encoding of integer v. Messages are
exactly 55 bytes, so under FIPS 180-4 padding each pads to a single 512-bit
block (55 content bytes = 440 bits, then 0x80, then zero bytes to offset 56,
then the 64-bit big-endian length 440). Thus H of a 55-byte message is exactly
one selected-round compression from the fixed IV, with feed-forward and the full
256-bit output.

Initialize the eight 32-bit chaining words once:

    6a09e667 bb67ae85 3c6ef372 a54ff53a  510e527f 9b05688c 1f83d9ab 5be0cd19

Parse the padded block as sixteen big-endian 32-bit words W[0..15]. Additions
are modulo 2^32; rotations and NOT are 32-bit.

    s0(z)=ROTR(z,7)^ROTR(z,18)^(z>>3)     s1(z)=ROTR(z,17)^ROTR(z,19)^(z>>10)
    S0(z)=ROTR(z,2)^ROTR(z,13)^ROTR(z,22) S1(z)=ROTR(z,6)^ROTR(z,11)^ROTR(z,25)
    Ch(e,f,g)=(e&f)^(~e&g)                Maj(a,b,c)=(a&b)^(a&c)^(b&c)
    W[t]=W[t-16]+s0(W[t-15])+W[t-7]+s1(W[t-2]),  t=16..30.

Constants K[0..30], hexadecimal, original index order:

    428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
    d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
    983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351

Copy chaining words into (a..h), run t=0..30:

    T1=h+S1(e)+Ch(e,f,g)+K[t]+W[t];  T2=S0(a)+Maj(a,b,c);
    (a,b,c,d,e,f,g,h)=(T1+T2,a,b,c,d+T1,e,f,g).

After round 30, add the eight working words to the incoming chaining words
modulo 2^32, then serialize BE_4 of the eight results in order. This 32-byte
string is H(m), read as a 256-bit integer big-endian. Equality of that integer
is equality of the complete digest. The model charges one such compression at
one unit.

## 2. Iteration function and distinguished-point search

Fix an injective encoding `embed: {0,1}^256 -> {55-byte messages}` that writes a
256-bit state s into 32 of the 55 content bytes and fills the remaining 23 bytes
with a fixed public constant. Define

    f(s) = H(embed(s)),   f: {0,1}^256 -> {0,1}^256.

Because `embed` is injective, any two states s != s' with f(s) = f(s') give two
distinct 55-byte messages `embed(s)`, `embed(s')` with equal complete digests,
i.e. an ordinary collision. Evaluating f is one compression plus the fixed
`embed` and serialization wrapper.

Call a state *distinguished* if its low 88 bits are zero; the distinguishing
probability is theta = 2^-88. The search maintains a table T keyed by
distinguished state, holding (start_state, steps).

Repeat until a collision is located:

1. Pick the next start state s0 from a fixed enumerator (a counter expanded into
   256 bits), set s = s0, c = 0.
2. Iterate s = f(s), c = c + 1 until s is distinguished or c reaches the cap
   L_max = 20 / theta = 20 * 2^88 (the cap bounds rare long trails; see below).
3. If the cap was hit without a distinguished point, discard the trail and go to
   step 1. Otherwise let d = s be the trail's distinguished endpoint.
4. If d is not in T, store T[d] = (s0, c) and go to step 1.
5. If d is in T as (s0', c'), the two trails from s0 and s0' meet at d. Re-walk
   the longer trail forward so both have the same number of steps remaining to
   d, then step both in lockstep until their next states coincide; the two
   states just before coincidence are s != s' (if equal, this start pair yields
   only a repeated point, so discard and continue) with f(s) = f(s'). Recompute
   both complete hashes, confirm digest equality and message inequality, and
   return `embed(s)`, `embed(s')`.

All start states are distinct by the enumerator, every state is fully charged,
and there is no stored random tape. A returned pair is always two distinct valid
55-byte messages with identical complete sha256-r31 digests, verified by
recomputation.

## 3. Declared heuristic and expected running time

**H1 (score-critical).** For counting the expected number of f-evaluations to
the first collision, the single-block iteration f defined in section 2 behaves
as a uniform random mapping on the 2^256-point state space.

Under H1, the standard van Oorschot--Wiener analysis (Pollard rho with
distinguished points) gives an expected number of evaluations to the first
collision of

    E[evaluations] ~ sqrt(pi * N / 2) = sqrt(pi/2) * 2^128 < 2^128.33,

independent of theta; theta only trades stored distinguished points against the
per-collision re-walk cost. Choosing a budget of B = 2^128.5 evaluations, the
probability that the visited trajectory has produced a colliding f-image is, to
the same random-mapping approximation,

    Pr(collision within B evaluations) ~ 1 - exp(-B^2 / (2N))
                                       = 1 - exp(-2^257 / 2^257) = 1 - exp(-1)
                                       > 0.63.

The trail-length cap L_max = 20/theta discards at most an exp(-20) fraction of
trails (a geometric tail), changing the constants negligibly and keeping every
discarded step charged. Locating the collision from a repeated distinguished
point costs at most about 2/theta = 2^89.3 extra evaluations, incurred a
constant number of times, which is negligible beside B.

H1 is used only to bound the *expected running time*; it is not used to argue
correctness. Correctness (section 2) is unconditional: if the search returns a
pair, that pair is a verified ordinary collision, and if f ever repeats an image
along the walked trails the located pair is genuine. H1 could in principle fail
for a pathological fixed f with anomalously long tails or short cycles; see
section 6.

## 4. Success probability

Set the budget B = 2^128.5 evaluations and stop with FAIL if it is exhausted.
Under H1, Pr(success) > 0.63 by section 3, comfortably above the required 0.39.
The repeated-start-point degenerate case in step 5 is discarded and does not
count as success; its probability is the chance that the first meeting is at the
immediate predecessor of d, an O(theta) event, absorbed in the constants. The
declared `success_probability = 0.6` is a lower bound under H1, not equality,
confidence in the proof, or confidence in a review.

## 5. Resource accounting

On the 256-bit word RAM of `collision-frontier-v5`, one compression costs one
unit and every other primitive word operation costs 1/C, C = 2140.

- Evaluation term: at most B = 2^128.5 evaluations of f, each one compression
  plus at most 200 core operations (embed, distinguished-point test, table
  probe amortized, counter update), charged at up to 8 word operations each:

      time <= B * (1 + 1600/C) < 2^128.5 * (1 + 2^-0.42... )
      more precisely B compressions = 2^128.5 units and
      B * 1600 / C = 2^128.5 * 2^-0.42 < 2^128.1 units,
      plus <= 2^89.3 collision-location evaluations,
      so T < 2^128.5 + 2^128.1 + 2^89.3 < 2^129 units.

  Hence `time_log2 = 129` is a valid upper bound on the charged total.

- Memory: the table holds at most B * theta = 2^128.5 * 2^-88 = 2^40.5
  distinguished points, each a start state and a count, at most 3 words = 96
  bytes: 2^40.5 * 96 < 2^47.1 bytes. Fixed code, IV, constants, the encoder
  template, and a constant number of working states occupy under 2^20 bytes. So
  peak memory M < 2^47.1 + 2^20 < 2^48 bytes. `memory_log2_bytes = 48` is the
  declared bound; memory is reported only and does not affect the score. This is
  about 2^90 times smaller than a stored birthday table.

- Preprocessing: a loader writes code, constants, and base addresses in under
  2^20 charged instructions, included in the total and dominated by the 2^128.5
  term. `preprocessing_log2 = 20`. Nonuniform advice is zero bytes; the search
  uses no precomputed collision, favorable seed, or target-dependent advice.

## 6. Evidence, scope, and limitations

This package declares exactly one heuristic, H1, and marks it score-critical
because the `time_log2` bound depends on it; correctness and the collision
verification do not. H1 is the standard basis for all practical collision-search
cost estimates against cryptographic hash iterations, is supported by the
extensive empirical record of rho and distinguished-point methods behaving as
predicted on real hash functions, and is consistent with the absence of any
known structural anomaly (fixed points, short cycles, or large tails) in
31-round SHA-256 that would distort rho collision time. Its limitation is that
it is an average-case random-mapping premise about a specific fixed function, not
a worst-case theorem; a pathological f could in principle deviate, which is why
this is an exploratory rather than a rigorous claim, and why a companion
unconditional birthday construction exists at the same time with much larger
memory.

The certificate manifest is valid and empty; there is no experiment manifest or
executable source, so H1's evidence references point to the analysis in
sections 2 and 3 rather than to a run. A finite toy rho experiment would
illustrate but could not certify full-scale behavior. This is an astronomically
expensive theoretical construction, not a computed collision, practical attack,
or new SHA-256 security result. An exploratory `plausible_not_refuted` outcome,
if reached, is an AI review outcome distinct from mathematical proof or human
acceptance.
