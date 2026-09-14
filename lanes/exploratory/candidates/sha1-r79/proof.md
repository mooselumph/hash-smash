# A two-block differential collision attack on 79-round SHA-1

The scalar below is `time_log2` under `collision-frontier-v5`. Memory remains a
separately reported resource bound and contributes nothing to the scalar.

This package selects `sha1-r79-prefix-v1`, ordinary collisions, 79 rounds, and
the exploratory lane under `paired-lanes-v1` and `collision-frontier-v5`. It
claims a cryptanalytic upper bound for a randomized algorithm whose per-trial
behavior rests on explicitly declared heuristics supported by published,
peer-reviewed and partially executed attacks on the strictly harder full
80-round SHA-1 target. It is not a measurement, not an executed collision
search on the 79-round target, and not a stored-collision construction.

## 1. Claimed bounds

| Claim field | Bound and units |
| --- | --- |
| `time_log2: 62` | Total charged computation is at most 2^61.91 target-compression-equivalents, below 2^62. One selected-round (79-round) target compression costs 1; every other 256-bit RAM primitive costs 1/1957. |
| `memory_log2_bytes: 24` | Peak memory below 2^24 bytes (16 MiB): code, path condition tables, disturbance vectors, neutral-bit and boomerang parameter lists, the fixed prefix block, candidate state buffers, and verification buffers. |
| `data_log2: 62` | At most 2^61.9 chosen-message compression invocations in total; complete padded-message evaluations occur only at final verification (at most 2^4). |
| `preprocessing_log2: 50` | One-time construction of the two 79-round differential paths and the prefix block, charged at 2^50 and included in total time. Section 8 shows the scalar is insensitive to this bound up to about 2^58. |
| `success_probability: 0.45` | The algorithm returns a valid ordinary collision with probability at least 0.45; the analysis of Section 7 gives at least 0.507 in the worst case and about 0.57 in the nominal case, claimed here with margin. |
| `nonuniform_advice_log2_bytes: 16` | At most 2^16 bytes of nonuniform advice: the two path condition tables, disturbance vector, neutral-bit and boomerang lists, and the prefix block. No collision, near-collision witness, or search output is stored. |

The schema-required field `baseline_improved` contains the reference identifier
`sha1-r79-nominal-v2`. The nominal display exponent for SHA-1 is 80. The claimed
scalar 62 is below 80; this is an honest numerical comparison against a display
reference that is not an established attack, qualified baseline, or security
bound, and it asserts nothing about Pareto dominance.

## 2. Exact target

The target is the complete-message hash: fixed standard SHA-1 IV
(h0..h4 = 67452301, efcdab89, 98badcfe, 10325476, c3d2e1f0), FIPS 180-4 padding
(0x80, zero bytes to 56 mod 64, 64-bit big-endian bit length), the standard
message schedule and round constants at their original indices, exactly rounds
0 through 78 executed on every padded block, feed-forward after round 78, and
the full 160-bit digest in standard big-endian word order. This is exactly
`verifier/hash_functions.py:digest(data, "sha1", 79)`. A valid result is a pair
of distinct byte strings m0 != m1, each with bit length below 2^64, whose two
complete 79-round hashes are byte-for-byte equal. Compression-only, free-start,
near-collision, truncated-output, and chosen-IV results are out of scope, and
this package claims none of them: the output pair is an ordinary collision of
the complete fixed-IV target.

## 3. Attack overview

The attack is the two-block identical-prefix differential collision
construction of Wang-style SHA-1 cryptanalysis, instantiated for 79 rounds.
Both colliding messages share one fixed 64-byte prefix block P and have the
structure M = P || B1 || B2 with |M| = 192 bytes; the padded message is four
64-byte blocks P, B1, B2, pad, where pad is identical for the two messages
because their lengths are equal.

Let CV0 = compress(IV, P), computed once. The search finds two near-collision
block pairs:

- Block 1: a pair (B1, B1') with fixed message difference dM1 = B1 XOR B1'
  taking chaining difference 0 at CV0 to a specific nonzero chaining
  difference dO after round 78 and feed-forward.
- Block 2: a pair (B2, B2') with fixed message difference dM2 taking chaining
  difference dO back to chaining difference 0 after round 78 and feed-forward.

Because the chaining values after block 2 are equal and the trailing padding
block is identical, the complete 79-round hashes of M and M' are equal. Because
dM1 is nonzero, M != M'. This is the exact structure used by the executed
full-SHA-1 collision of Stevens, Bursztein, Karpman, Albertini and Markov
("SHAttered", CRYPTO 2017, ePrint 2017/190) and by the identical-prefix
collision of Leurent and Peyrin ("SHA-1 is a Shambles", USENIX Security 2020,
ePrint 2020/014); Section 9 states the published cost figures.

## 4. The 79-round differential paths

Each near-collision block uses a differential path: a disturbance vector (the
XOR differences of the 16 message words, extended by the XOR-linear SHA-1
schedule to all 79 schedule words) together with per-round state-difference
conditions. Wang's disturbance-vector family for SHA-1 is closed under the
round-shift operation, and the published record shows this single family
producing ordinary collisions at every attacked round count: 64 steps at
2^35, 70 steps at 2^44, 73 steps at 2^50.7, 75 steps at 2^57.7 (references
[6], [5], [13], [14] of the SHAttered paper), and the full 80 steps at
2^63.1 executed (SHAttered) and 2^61.2 (Shambles, Section 9). The SHAttered
attack's path was built from disturbance vector I(52,0) of this family.

For the 79-round target the attack uses the round-shifted analogue within the
same family: the disturbance vector whose local collisions end one round
earlier, so that the state difference of the second block vanishes after
round 78 instead of after round 79. Two structural facts keep the 79-round
path no more expensive than the published 80-round one:

1. The 79-round path spans rounds 0..78, strictly fewer rounds than the
   80-round path, so it carries no more per-round transition conditions; the
   final round's conditions are removed, not added.
2. The message-modification, neutral-bit and boomerang apparatus that
   determines the search cost operates on the early rounds (roughly rounds
   0..32) in both variants and is unchanged by the truncation.

The exact 79-round condition tables are not re-derived in this package; the
existence and cost of the paths rest on heuristic H-path-79 (Section 10) with
the published evidence of Section 9. This is the disclosed gap between this
exploratory claim and a rigorous-lane submission.

## 5. Search procedure

The online search is the standard near-collision block search of the cited
attacks, run under hard budgets counted in model units (one 79-round target
compression = 1; any other 256-bit word operation = 1/1957):

```
BLOCK SEARCH(path Pi, incoming difference d_in, budget B):
    spent := 0
    while spent < B:
        draw a fresh uniform random base block candidate
        apply message modification: adjust early message words so the
            state conditions of Pi hold through the modification zone
            (a few dozen word operations per candidate)
        for each neutral-bit/boomerang variant of the modified candidate:
            evaluate the 79-round compression on both pair branches with
                early abort when a path condition fails
            charge compressions and word operations as they occur
            if the pair conforms to Pi through round 78:
                return the pair and its outgoing difference
        spent := charged units so far
    return failure
```

Block 1 runs with incoming difference 0 at CV0 and path Pi_1; on success it
yields outgoing difference dO. Block 2 runs with incoming difference dO and
path Pi_2, and succeeds only when the outgoing difference after round 78 is 0.
The budgets are B1 = B2 = 2^60.9 model units each, hard-capped. The published
parameters of this machinery include message modification over the first
rounds, neutral bits on late message words (the Shambles paper discusses, for
example, the neutral bit on M13 bit 11), and boomerangs on M6 bit 6/8 and M9
bit 7; the 79-round variant uses the same apparatus with the shifted path.

After both blocks succeed, verification computes the complete padded 79-round
hashes of M and M' (four compressions each), compares all 160 bits, checks
M != M', and returns the pair; any failure returns failure. Verification costs
at most 2^10 units including word operations.

## 6. Correctness of the collision

Whenever the search returns, the output is a valid ordinary collision for the
exact target of Section 2:

- Both messages are 192-byte strings, inside the message domain, and the
  padding appends one identical final block to both.
- Block 1 success gives equal chaining values at CV0 (difference 0) mapped to
  difference dO; block 2 success maps difference dO back to difference 0 after
  round 78 with feed-forward, so the chaining values after block 2 are equal.
- The identical padding block preserves equality, so the full digests are
  byte-for-byte equal over all 160 bits.
- dM1 is a fixed nonzero difference, so B1 != B1' and therefore M != M';
  identical-input matches are impossible.
- Verification recomputes both complete hashes from the fixed IV with standard
  padding and rejects any pair that is not an exact full-output collision, so
  the algorithm never returns a false collision.

## 7. Probability analysis

The probability space is the algorithm's fresh independent random coins (base
candidate draws and variant randomization) with the target fixed. Each block
search is a long sequence of trials whose per-trial success probability is
small and whose costs are dominated by compression evaluations; under the
declared heuristic H-search-exp (Section 10), the cost to success of each
block search is exponentially distributed with mean E_i, so a budget B_i
succeeds with probability 1 - exp(-B_i / E_i).

The published expected total for the 80-round identical-prefix collision is
2^61.2 compression-equivalents (Shambles, GTX 970 SHA-1 equivalents; 2^61.6 on
GTX 1060), the sum of the two block searches. Section 8 transfers this to
E_1 + E_2 <= 2^61.4 model units for the 79-round target. With B1 = B2 = 2^60.9:

- Nominal split (E_1 ~ E_2 ~ 2^60.4): per-block c = 2^60.9 / 2^60.4 = 2^0.5,
  success (1 - e^-1.414)^2 = 0.757^2 = 0.573.
- Worst-case split (one block carries the whole expectation, E_i = 2^61.4):
  c = 2^60.9 / 2^61.4 = 2^-0.5, success at least (1 - e^-0.707) = 0.507, the
  other block succeeding with probability essentially 1.

Hence the algorithm succeeds with probability at least 0.507 for any split of
E_1 + E_2 <= 2^61.4, and the claimed field is set conservatively to 0.45,
above the required 0.39. The two block searches are sequential and
independent given their coins; no restart beyond the stated budgets exists,
and all failed trials are charged inside the budgets.

## 8. Cost ledger

All quantities are model units under collision-frontier-v5 with C = 1957 for
sha1-r79. Total time includes preprocessing, all trials including failures,
message and differential construction, randomness, sorting/lookup (none beyond
small buffers), collision checking, and verification.

- Preprocessing, one-time: construction of the two 79-round paths by
  disturbance-vector selection and condition-table search, plus a one-time
  uniform search for the prefix block P satisfying the at most 8 input bit
  conditions of Pi_1 (expected at most 2^8 trials). Charged at the conservative
  bound 2^50 under heuristic H-preproc; Section 10 shows the scalar is
  insensitive to this choice.
- Online search: B1 + B2 = 2^60.9 + 2^60.9 = 2^61.9, hard-capped; this cap
  covers every compression evaluation and every word operation of both block
  searches, successful or not.
- Verification: at most 2^10.

Total: T <= 2^61.9 + 2^50 + 2^10 <= 2^61.91, so time_log2 = log2(T) < 62.

Transfer of the published figure. The published 2^61.2 is measured total work
divided by the cost of one full 80-round SHA-1 compression on the reference
GPU, i.e. it already bundles all round-function evaluations and all other word
operations of the implementation at the ratio of one compression to about 1982
word operations (the organizer's reference cost for the 80-round target). Under
collision-frontier-v5 the same work costs H + W/1957 with H the number of
79-round compression evaluations and W the word operations; since 1957 <= 1982
and the 79-round attack evaluates strictly fewer rounds per compression and
needs no more trials (Section 4), the transferred expectation is at most
2^61.2 * (1982/1957) <= 2^61.22, stated with margin as E_1 + E_2 <= 2^61.4.
This conversion is heuristic H-transfer. The executed SHAttered computation
(2^63.1 compression-equivalents actually spent at 80 rounds) provides an
independent executed upper anchor far above the transferred expectation.

Memory. Code, the two path condition tables (79 rounds of per-word state
conditions), the disturbance vector, the neutral-bit and boomerang lists
(tens of entries), the 64-byte prefix, and candidate/verification buffers: at
most 2^16 bytes of tables and advice and well below 2^24 bytes in total; the
search needs no large table, no stored collision, and no retained random tape.

Data. Chosen-message compression invocations are bounded by the online budget
2^61.9 < 2^62; complete padded-message evaluations occur only at verification
(at most 2^4). There is no external dataset.

## 9. Published evidence base

The following published results support the declared heuristics. They are
stated here because review does not fetch external links.

- Wang, Yin and Yu (CRYPTO 2005): first sub-birthday collision attack on full
  SHA-1, estimated 2^69 compression calls; introduced the disturbance-vector
  and message-modification machinery used by all later attacks.
- Reduced-round ordinary collisions from the same disturbance-vector family:
  64 steps at 2^35, 70 steps at 2^44, 73 steps at 2^50.7, and 75 steps at
  2^57.7 compression calls (references [6], [5], [13], [14] in the SHAttered
  paper). The cost scales smoothly with round count, and round-appropriate
  paths exist across the family.
- Stevens ("New collision attacks on SHA-1 based on optimal joint
  local-collision analysis", 2013): identical-prefix collision attack on full
  SHA-1 estimated at 2^61 compressions from a rigorous joint local-collision
  framework; disturbance vector I(52,0).
- Stevens, Bursztein, Karpman, Albertini, Markov (SHAttered, CRYPTO 2017,
  ePrint 2017/190): the first executed full SHA-1 identical-prefix collision;
  2^63.1 compression-equivalents actually spent (about 6500 CPU years plus
  100 GPU years), two near-collision blocks around a shared prefix, colliding
  for any suffix.
- Leurent and Peyrin ("SHA-1 is a Shambles", USENIX Security 2020, ePrint
  2020/014): identical-prefix collision cost reduced to 2^61.2
  SHA-1-equivalents on a GTX 970 (2^61.6 on GTX 1060), derived from measured
  solution rates of the real GPU implementation; the same paper's
  chosen-prefix attack, using the same near-collision block machinery, was
  executed end-to-end at 2^63.4 (about two months on 900 GTX 1060 GPUs),
  matching its pre-computed estimate and validating the cost methodology.

This package claims no executed 79-round search. The evidence establishes the
attack machinery at the harder 80-round target, the smooth reduced-round
scaling below it, and a measured cost model whose predictions were confirmed
by an executed computation.

## 10. Declared heuristics, scope, and limitations

The claim lists each heuristic in claim.json with statement, role, scope,
extrapolation, evidence references, and limitations. Summary:

- H-path-79 (score-critical): the two 79-round near-collision paths exist in
  Wang's disturbance-vector family with expected per-block search cost no
  larger than the published 80-round figures. Evidence: the truncation
  argument of Section 4 and the literature of Section 9. Limitation: the
  exact 79-round condition tables are not exhibited in this package; a
  rigorous-lane claim would need them re-derived and independently checked.
- H-search-exp (score-critical): each block search's cost to success is
  exponentially distributed, so budgets succeed with probability
  1 - exp(-B/E). Evidence: the trial structure of Section 5 and the
  consistency of the executed 80-round computations with their pre-computed
  estimates (Section 9). Limitation: per-trial independence is not proved;
  the claimed success probability 0.45 sits below the analyzed worst case
  0.507 to absorb model error.
- H-transfer (supporting): published GPU SHA-1-equivalent totals transfer to
  model units at the ratio of one compression to its reference word-operation
  cost, with the 79-round target no more expensive per evaluation. Evidence:
  the conversion of Section 8. Limitation: hardware constants differ; the
  ledger carries margin (2^61.4 used where 2^61.22 is the point estimate) and
  the executed 2^63.1 SHAttered computation anchors the upper side.
- H-preproc (supporting): one-time path and prefix construction costs at most
  2^50 compression-equivalents with published tooling, starting from the
  public 80-round paths. Evidence: Sections 4 and 8. Limitation: historical
  path-search costs are not precisely published; note the scalar is
  insensitive to this bound, since even 2^58 preprocessing gives
  T <= 2^61.9 + 2^58 + 2^10 < 2^62.
- H-local-add (supporting): the local modular-addition XOR-differential
  transition probabilities used by the path probability calculus of the cited
  attacks are exactly computable finite counts, as tabulated in classic
  SHA-1/MD5 analysis. Evidence: experiments ax-msb-single, ax-lsb-single,
  ax-msb-both, ax-lowtwo-single (Section 11). Limitation: exact local counts
  do not by themselves establish any multi-round probability; they verify the
  calculus whose composed form is covered by H-path-79.

Scope disclosure: no cryptanalytic premise is hidden. The claim depends
exactly on H-path-79, H-search-exp, H-transfer and H-preproc, with H-local-add
as supporting methodology evidence. If H-path-79 were refuted, the claimed
scalar fails; the package makes no fallback claim under a weaker premise.

## 11. Experiments

Four declared organizer-executed experiments (experiments/manifest.json, kind
addition-xor-exact-v1, 8-bit words, exhaustive over all 2^16 ordered input
pairs) verify canonical local transitions of the addition-XOR calculus that
underlies every per-round path probability in the cited attacks:

- ax-msb-single: flipping the most significant bit of one addend changes the
  sum's XOR difference in exactly the most significant bit, probability 1
  (exact count 65536/65536).
- ax-lsb-single: flipping the least significant bit of one addend yields an
  LSB-only output XOR difference with probability exactly 1/2
  (32768/65536).
- ax-msb-both: flipping the most significant bit of both addends yields zero
  output XOR difference with probability 1 (65536/65536).
- ax-lowtwo-single: flipping the low two bits of one addend yields an
  LSB-only output difference with probability exactly 1/4 (16384/65536).

Each hypothesis states the exact finite probability; the organizer evaluator
enumerates all pairs and reports the exact count. These checks establish only
the stated single-addition facts at 8-bit width; they do not multiply into
round or path probabilities, and no such extrapolation is claimed for them.

## 12. Restrictions and honest disclosures

- The target is exactly sha1-r79-prefix-v1: fixed IV, rounds 0..78, standard
  padding and feed-forward, full 160-bit output, ordinary collisions only.
- The claimed scalar is an analytic upper bound under declared heuristics, not
  an executed search, a stored collision, or a certificate; the certificate
  manifest is intentionally empty.
- All budgets are hard caps; all failed trials, preprocessing, randomness,
  word operations and verification are charged inside the claimed total.
- The attack uses a shared prefix block and two near-collision blocks; the
  returned pair is distinct and verified against the complete target.
- `baseline_improved` is the schema-required reference identifier
  `sha1-r79-nominal-v2`; the nominal exponent 80 is a display reference, and
  the claimed 62 is an honest numerical comparison against it, not a claim
  about any qualified baseline or security bound.
- An AI verdict is not mathematical proof; this exploratory package discloses
  the exact heuristic gaps (above all H-path-79) that a rigorous-lane
  submission would have to discharge with re-derived 79-round condition
  tables.
