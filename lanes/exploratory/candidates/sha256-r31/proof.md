# SHA-256, 31 prefix rounds: practical fixed-witness construction

## 1. Claim status and exact scope

This is an **exploratory** submission for `sha256-r31-prefix-v1` under
`collision-frontier-v3` and `paired-lanes-v1`. It gives a complete ordinary
collision witness and a deterministic replay algorithm. It does not claim a new
collision, a new differential trail, a reproducible implementation of the
historical search, or a rigorous resource certificate.

The proposed score is `time_log2 + memory_log2_bytes = 41 + 25.25 = 66.25`. The witness
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
construction, serialization, and verification—is less than `2^40.75` charged
`collision-frontier-v3` units. Adding advice loading, two complete
selected-target evaluations, checking, and return keeps total time below `2^41`
units.

The numerical support is the practical paper's reported `2^40.5` attack
complexity and its 1.2-hour, 64-thread collision run. The preprocessing cap is
only 0.25 bit above that headline, and the total cap is only 0.5 bit above it.
The transfer therefore assumes that publication-specific operations plus every
omitted discovery, conversion, construction, and failure cost fit within a
factor `2^0.25` in the organizer's word-RAM preprocessing account. The older
`2^49.8` and `2^65.5` time figures are superseded routes, not lower bounds or
extra margins for this premise.

This remains a deliberately fragile heuristic. The publication and public
source snapshot do not expose a complete historical job ledger, instruction
trace, immutable practical-generator build, organizer-model conversion receipt,
or record of all unsuccessful development runs. Publication complexity units
are not certified organizer word-RAM units. Neither the runtime report nor the
fixed replay proves the factor-`2^0.25` conversion or the `2^40.75` preprocessing
cap. If preprocessing reaches `2^40.75` or total work reaches `2^41`,
`preprocessing_log2=40.75`, `time_log2=41`, `data_log2=41`, and the score all
fail.

Under H-HISTORICAL-TIME, `preprocessing_log2=40.75` pays the entire historical
construction once. No cross-target or multi-collision amortization is taken.
The online phase needs six selected-target compression calls total, fewer than
`2^20` other word operations, and no randomness or retries. Consequently the
conditional total is strictly less than
`2^40.75 + 2^20 + 6 < 2^41`.

`data_log2=41` bounds all candidate blocks, tuple records, messages, and other
attack data generated or examined across preprocessing and replay. This follows
under the same time premise because materializing or inspecting each separate
item requires at least one charged operation; it is not a claim of `2^41`
external known pairs or free data.

## 7. Score-critical peak-memory premise

**H-HISTORICAL-MEMORY (score-critical).** Peak simultaneously retained memory
during all historical construction and the online replay is less than `2^25.25`
bytes, approximately 39,903,169.27 decimal bytes, including code, advice, tuple
tables, indices, messages, thread state, constants, allocator overhead, solver
and tool state, and all other working storage.

The practical slides' table has approximately `2^19.8` entries. The listed
tuple contains ten 32-bit words, so a tightly packed representation takes 40
bytes per entry. Using the reported approximate entry count, the raw table is
approximately `2^19.8 * 40 = 2^25.121928095` bytes, or 36,513,537.10 decimal
bytes. The submitted `2^25.25` cap is approximately 39,903,169.27 decimal bytes,
only 0.128071905 bit, or about 1.092832 times, above that raw representation.
It leaves approximately 3,389,632.17 decimal bytes for every index, executable
page, allocator object, thread, message, constant, solver or tool state, advice
byte, and other retained storage.

This memory translation is also heuristic. The public figures count entries,
not bytes, and do not provide an authoritative peak-RSS trace. They do not prove
that the practical implementation shared one tightly packed table or that
indices, allocator behavior, executable code, per-thread state, SAT/SMT solver
state, characteristic search, and unsuccessful development runs fit inside the
remaining space. The cap is deliberately fragile, not a certified worst-case
bound. If any included phase reaches `2^25.25` bytes,
`memory_log2_bytes=25.25` and the score claims fail. Section 10 replaces the
rounded headroom calculation with an integer allocation audit and explicit
counterexamples to several common storage choices.

The retained nonuniform advice needed by the online algorithm is only the two
128-byte messages. Allowing their 256 raw bytes plus length and digest metadata
still remains below 512 bytes, hence
`nonuniform_advice_log2_bytes=9`. Program text and target constants are charged
inside the much larger peak-memory cap rather than hidden in advice.

## 8. Arithmetic, experiment interpretation, and limitations

The resource vector is therefore

| Field | Submitted bound | Meaning |
| --- | ---: | --- |
| `time_log2` | 41 | Total historical preprocessing plus deterministic replay, conditional on H-HISTORICAL-TIME |
| `memory_log2_bytes` | 25.25 | Peak bytes across all phases, conditional on H-HISTORICAL-MEMORY |
| `data_log2` | 41 | All materialized or inspected attack items under the time premise |
| `preprocessing_log2` | 40.75 | Historical construction, paid once and included in total time |
| `success_probability` | 1 | Deterministic correctness of the retained, independently verified pair |
| `nonuniform_advice_log2_bytes` | 9 | Fewer than 512 bytes of pair and metadata |

The six-field resource vector is `(41, 25.25, 41, 40.75, 1, 9)`, and the proposed
scalar is exactly `41 + 25.25 = 66.25`. The advice exponent is not
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

## 9. Revised evidence assessment

This revision retains the fixed pair, algorithm and resource vector of the
earlier unsuccessful 66.25 package. It adds an integer memory audit, a
parameterized time-conversion budget, direct public-source anchors, and the
negative limits of a separately developed reference implementation. These
additions improve the specificity of the analysis; they do not convert either
historical-resource premise into a measurement.

The prior experimental findings were that historical construction was not
executed and historical memory was not measured. Those observations remain
true. A new review must assess the relevant source support together with the
unresolved transfer below. No inference here depends on a previous score being
accepted, a majority of reviewers, or repeatedly rerunning the same package.

The source support is localized as follows:

| Source location | Relevant observation | Limit on its use |
| --- | --- | --- |
| Authors' ASIACRYPT slides, page 7 | Their contribution focuses on message-pair construction after choosing a differential trail | Earlier trail discovery is not thereby measured or free |
| Slides, pages 10-13 | Starting points, inverse-round relations, stored states and first-block matching provide a concrete construction outline | They do not disclose an allocator or a complete operation ledger |
| Slides, page 14 | Approximately `2^19.8` ten-word table entries, complexity `2^40.5`, and a 1.2-hour run using 64 threads | Entries are not peak bytes; runtime is not organizer RAM units |
| Slides, page 15 | The public two-block message pair | Establishes a concrete target for independent digest recomputation |
| Publisher abstract and note 3 | The runtime is corroborated; an unusually fast initial success was followed by further experiments and another pair | The number and total cost of those experiments are not given |

The public publisher page is
<https://link.springer.com/chapter/10.1007/978-981-96-0941-3_8>.
The slides URL is given in section 5; the locally inspected 17-page file has
SHA-256 `6a7247c13503511934c60ea38869d13318d35c6c3c10376ff2c8523e77014e29`.
The publisher's public abstract and notes were inspected; access to the full
subscription chapter is not claimed. No source file is redistributed here.
The source summaries and arithmetic needed for this assessment are included
in this proof, so following external links is not necessary to read the claim.

The additional reported experiments are relevant contrary pressure on a narrow
all-history time budget. They cannot be silently replaced by the single
1.2-hour run. Nor does the witness's deterministic replay success establish a
success distribution for the original search.

## 10. Integer memory audit and implementation sensitivity

For a concrete sensitivity calculation, round the reported approximate table
size upward to `N0 = ceil(2^19.8) = 912839`. This is an illustrative cardinality,
not a measurement or an upper bound on the authors' actual table. The largest
integer byte count strictly below the submitted cap is
`B = floor(2^25.25) = 39903169`.

At `N = N0`, a single contiguous array of ten unsigned 32-bit words per record
uses exactly `40*N = 36513560` bytes. Thus all other simultaneously live storage
must fit in `B - 40*N = 3389609` bytes. This includes any allocator metadata and
code; neither the public tuple count nor the following arithmetic hides it.

| Storage choice at N0 | Bytes before other working storage | Within B? |
| --- | ---: | --- |
| One packed 40-byte array | 36513560 | Only if other storage is at most 3389609 |
| Array plus a 4-byte index for every record | 40164916 | No |
| Array plus an 8-byte pointer for every record | 43816272 | No |
| Records individually padded to 64 bytes | 58421696 | No |
| Two simultaneously live packed arrays | 73027120 | No |

An index-free layout is possible at the representation level: store `A[-1]`
as the first word of each record, order the single array by that unsigned key,
locate the lower and upper bounds of a matching key by binary search, and visit
every matching record. Duplicates remain separate records. In-place heapsort
permits ordering without a second N-record array. Accessing a 40-byte record in
the organizer's 256-bit RAM takes more than one word access; sorting, lookup,
packing, boundary handling and regeneration must all be charged to time.
This describes a feasible layout choice, not the authors' observed code or a
substitute collision generator.

For a shared table with 64 workers, write the peak at the table-heavy phase as

```text
M_table_phase = 40*N + F + 64*S + I + Q,
```

where `F` is all other shared storage, `S` bounds each worker's live state,
`I` is any separately allocated index, and `Q` is any additional simultaneously
retained data, including sorting/checkpoint buffers. For example, the allowances
`F = 2097152`, `S = 16384`, `I = Q = 0` give `39659288` bytes at N0, leaving
`243881` bytes below B. These are explicit hypothetical allowances. There is
no evidence that historical code, allocator and thread state met them, that
checkpointing needed zero extra bytes, or that an OS runtime fits them. They
show the arithmetic constraint has a solution, not that history realized it.

More generally, for actual non-table overhead H, the necessary cardinality
condition is `N <= floor((B-H)/40)`. Every extra record consumes another 40
bytes of the finite headroom. Approximate `2^19.8` reporting cannot establish
that inequality. For disjoint phases the overall peak is the maximum of their
individual peaks; for overlapping phases all simultaneously retained state
must be added. Every historical solver or trail-search phase independently has
to respect B as well. The table audit supplies no bound on those phases.

This sharpens H-HISTORICAL-MEMORY: it requires an implementation at least as
space-efficient as a suitable single-table layout, modest aggregate overhead,
a compatible actual cardinality, and no larger peak elsewhere. The four
over-budget layouts in the table are explicit failure cases. The premise is
still unmeasured and remains score-critical.

## 11. Time conversion and omitted-work sensitivity

Let `C = 2^40.5` denote the reported publication-scale complexity. Define `c`
as the conversion from one unit of that reported work into charged organizer
units, and `D >= 0` as all charged work omitted by that accounting. D includes
trail discovery, additional experiments, abandoned trials, setup, data
conversion, tooling and verification to the extent those costs are not already
included in c*C. Nothing is counted twice, and nothing is silently discarded.

H-HISTORICAL-TIME then requires

```text
T_pre = c*C + D < 2^40.75
c + D/C < 2^0.25 = 1.189207115002721...
```

| Assumed conversion c | Remaining budget D, approximately |
| --- | ---: |
| 1.0 | less than 294206516665 charged units |
| 1.1 | less than 138712091067 charged units |
| at least 1.189207115002721... | No nonnegative D can satisfy the preprocessing cap |

These rows are sensitivity calculations, not estimates of c or D. No precise
conversion follows from counting a SHA-256 compression as one organizer unit:
partial-round algebra, table accesses, comparisons, branches and random draws
are separately charged. The sources inspected do not bind c or D at the
required values. The new reference prototype also does not supply that
conversion, since it follows a different exhaustive enumeration.

The 64-thread 1.2-hour report corresponds to 276480 nominal thread-seconds.
Dividing `2^40.75` by that figure gives about 6688190 charged units per
thread-second, but neither utilization nor the mapping from processor
instructions to organizer units is known. That quotient is not a benchmark or
calibration. In particular, the publisher's report of additional experiments
prevents treating this one runtime as the complete historical ledger.

For the online phase retain the deliberately generous bound
`T_online < 2^20 + 6` from section 6. Conditional on the preprocessing premise,
`T_pre + T_online < 2^40.75 + 2^20 + 6 < 2^41`.
Preprocessing is included once in total time. A violated preprocessing
bound invalidates the submitted vector even if the looser total cap happens
to hold. This analysis supplies exact failure thresholds, not a new measured
historical time result.

## 12. What the separate reference work actually adds

A separate reference implementation was developed after the earlier rejection.
Its source checkpoint is `5636b363af4be025e73a762c9c7ac3d60251e7b4`;
the tested executable SHA-256 is
`98ed0b2a2e34f2380a772c9f62786fa57681d3653df2fde4d71bc75a8d480e40`.
The retained R6 campaign summary SHA-256 is
`b95841d22116038948f47d2f8fb29a8cd4df82f7c0ab75342c19fe07011c8a08`.
These identifiers identify local research records, not organizer certificates;
the full source and traces are not part of this submitted package.

Nine recorded pilot attempts exercised direct execution, deliberate midpoint
interruption, and checkpoint resumption at each of three domain sizes. The
summary reports matching counters and digests for direct versus resumed runs
and native cgroup-v2 peak measurements. Direct runs reported:

| Raw assignments | Accepted table records | New collision candidates | Peak bytes |
| ---: | ---: | ---: | ---: |
| 4096 | 0 | 0 | 104464384 |
| 65536 | 0 | 0 | 104517632 |
| 1048576 | 0 | 0 | 104730624 |

The largest measured peak is about `2^26.642108` bytes, exceeding B. The tested
domain varied only the first starting-point axis; the remaining axes were
singletons. Empty tables mean no measured bytes-per-accepted-record slope,
no successful matching or fulfillment sample, and no collision-probability
estimate. The summary explicitly has probability and score authority false.
The interrupted attempts are retained; they are not silently dropped successes.

Thus the prototype demonstrates parts of execution and measurement machinery
but does not support either historical-resource cap. No subtraction of runtime
overhead is used to bring its peak under B. Its larger peak concerns a different
implementation and cannot by itself establish the authors' historical peak.
Conversely, semantic conformance and checkpoint correctness do not establish
that the prototype reproduces the authors' practical generator or complexity.

All nine pilots are research diagnostics, not runs of the claimed historical
construction or repetitions supplying the deterministic online success value.
Were this prototype to become the submitted construction, its work and memory
would require their own fully charged claim; the present bounds could not
simply be attached to it. The advanced work is retained for that later route.

## 13. Result of this analytical revision

The exact witness remains independently verifiable. The proposed 66.25 vector
remains conditional on both named historical-resource heuristics. This revision
provides concrete compatible and incompatible storage choices, exact conversion
and omitted-work inequalities, and adverse diagnostic observations. It does
not claim the prior experimental objections have been experimentally resolved.

No fresh historical peak trace, complete historical attempt ledger, calibrated
organizer conversion, or new generated collision is supplied. Accordingly this
is a revised exploratory proposal for assessment of the explicitly bounded
premises, with a real possibility of another `not_evaluable` result. The measured
prototype is not presented as evidence that 66.25 has already been achieved.
