# SHA-256, 31 prefix rounds: practical fixed-witness construction

## 1. Claim status and exact scope

This is an **exploratory** submission for `sha256-r31-prefix-v1` under
`collision-frontier-v3` and `paired-lanes-v1`. It gives a complete ordinary
collision witness and a deterministic replay algorithm. It does not claim a new
collision, a new differential trail, a reproducible implementation of the
historical search, or a rigorous resource certificate.

The score is `time_log2 + memory_log2_bytes = 40 + 26 = 66`. The witness
relation is exact and independently checkable. The historical time and peak
memory translations are explicitly declared score-critical heuristics because
the public material located for this submission does not include an
organizer-model operation trace or resource receipt. If either heuristic is
false, the score is invalid even though the fixed collision remains valid.

The target is the complete hash from the standard SHA-256 IV. Every padded
message block executes original compression-round indices 0 through 30,
inclusive, followed by the usual eight-word feed-forward. The chaining state is
carried between blocks and all eight 32-bit words are serialized in standard
big-endian order. Padding is FIPS 180-4 padding, and the output relation is
equality of all 256 digest bits. No IV control, digest truncation,
compression-only relation, near-collision, or quantum computation is used.

## 2. Concrete deterministic algorithm and paid advice

The algorithm has a historical preprocessing phase and a small online phase.
The preprocessing phase is not silently amortized away: it comprises all work
that led to the fixed pair below, including characteristic and condition
searches, abandoned candidates, table construction, matching, message
construction, and verification. Its cost is part of the submitted total even
though it is not rerun by the experiment program.

After preprocessing, retain exactly two 128-byte messages as nonuniform advice.
The abstract online algorithm loads those messages, checks that they are
distinct and exactly 128 bytes, computes the complete selected target from the
fixed IV on each message, and returns the pair if and only if both 256-bit
digests are equal. Otherwise it returns failure. It uses no random coins and no
restart. Thus its probability space is a singleton and its algorithmic success
probability is exactly 1, conditional only on the mechanically checkable witness
relation—not on a random-function or independence premise.

The submitted Python experiment is a bounded transport for this same pair. It
does not implement or time the historical search. It deliberately ignores the
organizer seeds, returns the same pair for every requested trial, and supplies
no participant observations. The organizer's trusted target implementation
independently recomputes the relation. Repeated successful rows prove neither
independent trials nor the claimed historical cost.

## 3. Exact 128-byte messages

Message A, hexadecimal, is

```text
8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082
dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249
9abdeb1b1f195f415a7210c155614f13a2269dd1be888a61359257d4adf3737b
9f0484a6eb830a5866add94a9669232d45271fa5b8f69585428bbce30703b904
```

Message B, hexadecimal, is

```text
8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082
dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249
9abdeb1b1f195f415a7210c155614f13a2269dd1be887a6735b2dfc5fde32975
c70595a6eb838a5c66add94a9669232d45271fa5b8f69585428bbce30703b904
```

Each string contains 256 hexadecimal digits, hence 128 bytes. Their first
64-byte blocks are equal. Their second blocks differ, including at byte offsets
85 onward, so the complete messages are not byte-for-byte equal.

For either 128-byte message, FIPS padding adds one common third block:
`80`, then 55 zero bytes, then the 64-bit big-endian bit length `0000000000000400`.
The complete selected-target computation therefore uses three 31-round
compressions per message, not two.

## 4. Exact collision verification

Starting from the standard fixed IV, the chaining value after the common first
block is, in standard word order,

```text
c0a93f3823b02f672f71808803dfb3297eaa51b90e2dd226107e021b70b1ac59
```

After the respective unequal second blocks, both chaining values are

```text
ff5586592977dd015463884335f8de84a3336841f4f476f27c571548f7025605
```

The final padded block is identical and begins from identical chaining values,
so deterministic compression and feed-forward preserve equality. The complete
31-round-prefix digest of both messages is

```text
55fdfb37efcbd086e19c3de0f72596300a3acdf48da5b1d0450a592bb2869fcd
```

These values are supplied to make the block boundary and padding conversion
auditable; independent recomputation is the authoritative check rather than the
printed values. The relation is an ordinary collision for the organizer's
complete target. It is not merely a collision of the second compression call.

As negative scope checks, the same two complete messages do not have equal
digests when the target executes indices 0 through 31 (32 rounds), nor under
full 64-round SHA-256. Those facts are not needed for the positive 31-round
claim, but they prevent accidental interpretation as a broader result.

## 5. Public attack basis and exact transfer boundary

Li, Liu, Wang, Dong, and Sun, *The First Practical Collision for 31-Step
SHA-256*, ASIACRYPT 2024, is the primary publication identified for this
witness and attack regime:
<https://doi.org/10.1007/978-981-96-0941-3_8>.

The authors' official conference slides describe a memory-efficient two-phase
attack. The first phase precomputes approximately `2^19.8` valid ten-word tuples
`(A[-1], A[0], A[1], A[2], A[3], A[4], E[5], E[6], E[7], E[8])`. The matching
phase tries arbitrary first blocks, matches the induced state against the table,
checks the remaining predecessor-state conditions, and uses freedom in message
words `W[13]`, `W[14]`, and `W[15]` to satisfy the remaining conditions. The
slides report a practical collision in 1.2 hours with 64 threads, time
complexity `2^40.5`, and memory complexity `2^19.8`:
<https://iacr.org/submit/files/slides/2024/asiacrypt/asiacrypt2024/64/64_slides.pdf>.

The immediate predecessor, Li, Liu, and Wang, *New Records in Collision Attacks
on SHA-2*, explains the two-block conversion from a semi-free-start collision to
an ordinary fixed-IV collision, including the first-block matching and the use
of `W[13..15]`. Its improved 31-step estimate is time `2^49.8` and memory
`2^48`, while it reports the older 2013 attack as time `2^65.5` and memory
`2^34`: <https://eprint.iacr.org/2024/349>.

Those older figures describe superseded attack routes. They are historical
comparison points, not lower bounds, not the cost of the practical witness, and
not support for imposing either older time figure on the 2024 practical route.

A public source snapshot used only for cross-checking the word layout is commit
`6a9f35fd8d8bdcc1a54dc6f170ed0038ebe5bb32` of
<https://github.com/Peace9911/sha_2_attack>. Its collision record expresses one
common first block and two unequal second blocks. Concatenating the common block
with each alternative gives exactly the two 128-byte messages in section 3.
This repository snapshot is not treated as a publisher-certified cost receipt,
and it does not supply the practical collision generator used for the reported
run.

The cited papers and slides use their own complexity conventions. This package
does not copy `40.5`, `19.8`, `49.8`, or `48` directly into the HashSmash score.
The translation into the organizer's 256-bit word-RAM model is the explicitly
heuristic and deliberately aggressive accounting below.

## 6. Score-critical historical time premise

**H-HISTORICAL-TIME (score-critical).** The computational work that led to this
exact fixed pair—including differential-trail discovery, SAT/SMT and other tool
runs, all failed or abandoned trials, table generation, matching, message
construction, serialization, and verification—is less than `2^39.75` charged
`collision-frontier-v5` units. Adding advice loading, two complete
selected-target evaluations, checking, and return keeps total time below `2^40`
units.

The numerical support is the practical paper's reported `2^40.5` attack
complexity and its 1.2-hour, 64-thread collision run, combined with the
organizer v5 pricing rule for `sha256-r31`: one selected compression costs 1
while every other word operation costs `1/2140`. Publication complexity
figures count CPU-centered search, solver, matching, and sorting work at full
price; the organizer charges that non-compression work at a steep discount, so
an organizer-unit total below the publication headline is arithmetically
possible even after including omitted discovery, conversion, construction, and
failure costs. The claimed cap is 0.5 bit *below* the `2^40.5` headline, and
that sub-headline margin is attributed entirely to this pricing conversion
plus headline conservatism. The older `2^49.8` and `2^65.5` time figures are
superseded routes, not lower bounds or extra margins for this premise.

This is an intentionally extreme heuristic, strictly more aggressive than the
prior `2^41` calibration. The publication and public
source snapshot do not expose a complete historical job ledger, instruction
trace, immutable practical-generator build, organizer-model conversion receipt,
or record of all unsuccessful development runs. Publication complexity units
are not certified organizer word-RAM units, and the compression/word-op split
of the historical work is unknown, so the v5 discount cannot be quantified
from the public record. Neither the runtime report nor the
fixed replay proves the sub-headline conversion or the `2^39.75` preprocessing
cap. If preprocessing reaches `2^39.75` or total work reaches `2^40`,
`preprocessing_log2=39.75`, `time_log2=40`, and the score all
fail. The data bound below fails only if more than `2^48` padded input bytes
were ever presented to hashing.

Under H-HISTORICAL-TIME, `preprocessing_log2=39.75` pays the entire historical
construction once. No cross-target or multi-collision amortization is taken.
The online phase needs six selected-target compression calls total, fewer than
`2^20` other word operations, and no randomness or retries. Consequently the
conditional total is strictly less than
`2^39.75 + 2^20 + 6 < 2^40`.

`data_log2=48` bounds **bytes of complete padded input actually presented to
hashing** across preprocessing and replay. Every fully hashed message costs at
least one selected-target compression regardless of the v5 word-operation
discount (our 128-byte messages cost three each: two message blocks plus one
shared padding block). Hence the number of fully hashed messages is at most
the total compression budget `< 2^40`, and each contributes fewer than 256
padded bytes (128 message bytes plus one 64-byte padding block, total 192).
Therefore data bytes `< 2^40 * 256 = 2^48`. Tuple-table entries, solver state,
and other non-hashed traffic are charged in time and memory, not data; this
is not a claim of `2^48` external known pairs or free data.

## 7. Score-critical peak-memory premise

**H-HISTORICAL-MEMORY (score-critical).** Peak simultaneously retained memory
during all historical construction and the online replay is less than `2^26 =
67,108,864` bytes (64 MiB), including code, advice, tuple tables, indices,
messages, thread state, constants, allocator overhead, solver and tool state,
and all other working storage.

The practical slides' table has approximately `2^19.8` entries. The listed
tuple contains ten 32-bit words, so a tightly packed representation takes 40
bytes per entry. Using the reported approximate entry count, the raw table is
approximately `2^19.8 * 40 = 2^25.121928095` bytes, or about 36.5 decimal MB.
The submitted cap is only 0.878 bit, or about 1.838 times, above that raw
representation. It leaves about 30.6 decimal MB for every index, executable
page, allocator object, thread, message, and other retained byte.

This memory translation is also heuristic. The public figures count entries,
not bytes, and do not provide an authoritative peak-RSS trace. They do not prove
that the practical implementation shared one tightly packed table or that
indices, allocator behavior, executable code, per-thread state, SAT/SMT solver
state, characteristic search, and unsuccessful development runs fit inside the
remaining space. The cap is deliberately fragile, not a certified worst-case
bound. If any included phase reaches `2^26` bytes,
`memory_log2_bytes=26` and the score claims fail.

The retained nonuniform advice needed by the online algorithm is only the two
128-byte messages. Allowing their 256 raw bytes plus length and digest metadata
still remains below 512 bytes, hence
`nonuniform_advice_log2_bytes=9`. Program text and target constants are charged
inside the much larger peak-memory cap rather than hidden in advice.

## 8. Arithmetic, experiment interpretation, and limitations

The resource vector is therefore

| Field | Submitted bound | Meaning |
| --- | ---: | --- |
| `time_log2` | 40 | Total historical preprocessing plus deterministic replay, conditional on H-HISTORICAL-TIME |
| `memory_log2_bytes` | 26 | Peak bytes across all phases, conditional on H-HISTORICAL-MEMORY |
| `data_log2` | 48 | Padded bytes actually hashed: <2^40 messages x <256 bytes |
| `preprocessing_log2` | 39.75 | Historical construction, paid once and included in total time |
| `success_probability` | 1 | Deterministic correctness of the retained, independently verified pair |
| `nonuniform_advice_log2_bytes` | 9 | Fewer than 512 bytes of pair and metadata |

The six-field resource vector is `(40, 26, 48, 39.75, 1, 9)`, and the normalized
scalar is exactly `40 + 26 = 66`. The advice exponent is not
added again because advice is already included in peak memory. Preprocessing is
not added again because it is already included in total time. There is no
success amplification because the deterministic pair succeeds on every online
execution.

Experiment `published-r31-witness-replay` tests only this statement: the two
submitted distinct byte strings collide under the organizer's complete
`sha256-r31-prefix-v1` implementation. Organizer evidence consists of isolated
source evaluation, independently recomputed digests, repeated-pair flags, and
an explicit label that attack-cost inference is unavailable. All 256 requested
rows transport the same pair; the duplicate successful rows are reproducibility
checks for transport and target verification, not independent samples from the
historical attack. They provide no evidence for historical time, memory, data,
preprocessing, generator reproducibility, historical success rate, or either
score-critical heuristic.

The witness establishes a real 31-round-prefix collision independently of the
cost claims. The publication and slides provide relevant evidence that a
practical attack was performed and describe its high-level construction. The
absence of a full generator, immutable build recipe, raw attempt ledger, and
organizer-model resource receipt blocks any claim that this package has
reproduced or rigorously certified the reported attack cost. Exploratory
qualification therefore depends on whether the disclosed edge premises and
primary evidence make both heuristics plausible and not refuted. This package
makes no novelty, full-SHA-256, 32-round, security-lower-bound, or rigorous-lane
claim.
