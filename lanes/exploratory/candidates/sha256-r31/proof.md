# SHA-256, 31 prefix rounds: practical fixed-witness construction (conservative v5 envelope)

## 1. Claim status and exact scope

This is an **exploratory** submission for `sha256-r31-prefix-v1` under
`collision-frontier-v5` and `paired-lanes-v1`. It gives a complete ordinary
collision witness and a deterministic replay algorithm. It does not claim a new
collision, a new differential trail, a reproducible implementation of the
historical search, or a rigorous resource certificate.

The proposed scored scalar is `time_log2 = 49.81`. Under v5, memory is reported
and reviewed but does not enter the scalar. The witness relation is exact and
independently checkable. The historical time and peak memory translations are
explicitly declared score-critical heuristics because the public material
located for this submission does not include an organizer-model operation trace
or resource receipt. If `H-HISTORICAL-TIME` is false, the score is invalid even
though the fixed collision remains valid.

This package anchors preprocessing on the EUROCRYPT 2024 published complete
constructive complexity `2^49.8` and declares total `time_log2 = 49.81` after a
negligible online term (`log2(2^49.8 + 2^20 + 6) ≈ 49.8000000015`). It still
refuses the knife-edge ASIACRYPT matching-phase headline `2^40.5` used by some
awaiting-review packages at declared `time_log2 ≈ 41`. Relative to the prior
qualified `time_log2 = 50` package, this only removes the previous 0.1-bit
padding above `2^49.8`; it does not newly rely on undefended matching-only accounting.

The target is the complete hash from the standard SHA-256 IV. Every padded
message block executes original compression-round indices 0 through 30,
inclusive, followed by the usual eight-word feed-forward. The chaining state is
carried between blocks and all eight 32-bit words are serialized in standard
big-endian order. Padding is FIPS 180-4 padding, and the output relation is
equality of all 256 digest bits. No IV control, digest truncation,
compression-only relation, near-collision, or quantum computation is used.

This is **not** a birthday attack. Generic birthday search at success ≥ 0.39
cannot honestly land meaningfully under `time_log2 ≈ 128` under v5. The
structure used here is the published two-block differential construction.

## 2. Concrete deterministic algorithm and paid advice

The algorithm has a historical preprocessing phase and a small online phase.
The preprocessing phase is not silently amortized away: it comprises all work
that led to the fixed pair below, including characteristic and condition
searches, abandoned candidates, table construction, matching, message
construction, and verification. Its cost is part of the submitted total even
though it is not rerun by the experiment program. Cost-model rule: a stored
precomputed collision is not a cheap construction.

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

Starting from the standard fixed IV, after the respective unequal second blocks,
both chaining values are

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

**How this package uses those figures (the honesty boundary):**

| Figure | Role in this package |
| --- | --- |
| ASIACRYPT `2^40.5` / `2^19.8` / 1.2 h | Supporting evidence for a practical matching phase; **not** taken as total historical cost |
| EUROCRYPT `2^49.8` | **Published complete constructive upper bound** for ordinary 31-step collision cost; anchors preprocessing under `H-HISTORICAL-TIME` |
| Mendel et al. `2^65.5` | Historical comparison only; not used as the declared envelope |

A public source snapshot used only for cross-checking the word layout is commit
`6a9f35fd8d8bdcc1a54dc6f170ed0038ebe5bb32` of
<https://github.com/Peace9911/sha_2_attack>. Its collision record expresses one
common first block and two unequal second blocks. Concatenating the common block
with each alternative gives exactly the two 128-byte messages in section 3.
This repository snapshot is not treated as a publisher-certified cost receipt,
and it does not supply the practical collision generator used for the reported
run.

The cited papers and slides use their own complexity conventions. This package
does not copy `40.5` into the HashSmash score. The translation into the
organizer's 256-bit word-RAM model is the explicitly heuristic accounting below,
with a deliberately large margin relative to the matching-phase headline.

## 6. Score-critical historical time premise

**H-HISTORICAL-TIME (score-critical).** The computational work that led to this
exact fixed pair—including differential-trail discovery, SAT/SMT and other tool
runs, all failed or abandoned trials, table generation, matching, message
construction, serialization, verification, and the publisher's disclosed
additional experiments—is at most `2^49.8` charged `collision-frontier-v5`
target-compression units. Adding advice loading, two complete selected-target
evaluations, checking, and return keeps total time below `2^49.81` units.

Numerical support: Li–Liu–Wang EUROCRYPT 2024 publish a **complete** constructive
complexity of `2^49.8` for ordinary 31-step SHA-256 collisions. Under this
heuristic, that figure is read as an upper bound on all-history work needed to
emit some (hence this) ordinary 31-step colliding pair when measured in
selected-target compression equivalents. No extra 0.1-bit padding is added on
top of that published figure (unlike the prior `time_log2 = 50` package).

What this premise **refuses**: equating total historical cost with the ASIACRYPT
matching-phase headline `2^40.5` alone. That headline omits an organizer ledger
for characteristic discovery, tooling, and the publisher's note that an
unusually quick initial success was followed by further experiments. Declaring
`time_log2 ≈ 41` from that headline is the high-refutation-risk pattern this
package avoids.

What this premise **does not** do: apply the v5 factor `1/2140` to shave
publication figures on the grounds that some work might be non-compression RAM
or SAT. The compression/word-op split is unknown; taking the discount would be
fabrication. Publication units are charged as compression equivalents.

Under H-HISTORICAL-TIME, `preprocessing_log2=49.8` pays the entire historical
construction once. No cross-target or multi-collision amortization is taken.
The online phase needs six selected-target compression calls total, fewer than
`2^20` other word operations, and no randomness or retries. Consequently the
conditional total satisfies

```text
T <= 2^49.8 + 2^20 + 6
log2(T) ≈ 49.8000000015 < 49.81.
```

If preprocessing exceeds `2^49.8` or total work reaches `2^49.81`,
`preprocessing_log2=49.8`, `time_log2=49.81`, and the score all fail, while the
collision itself remains valid.

## 7. Score-critical peak-memory premise

**H-HISTORICAL-MEMORY (score-critical).** Peak simultaneously retained memory
during all historical construction and the online replay is less than `2^30`
bytes, including code, advice, tuple tables, indices, messages, thread state,
constants, allocator overhead, solver and tool state, and all other working
storage.

The practical slides' table has approximately `2^19.8` entries. The listed
tuple contains ten 32-bit words, so a tightly packed representation takes 40
bytes per entry. Using the reported approximate entry count, the raw table is
approximately `2^19.8 * 40 ≈ 2^25.12` bytes. The submitted `2^30` cap is more
than an order of magnitude above that raw representation, leaving large
headroom for indices, executable pages, allocator objects, threads, messages,
constants, solver/tool state, advice, and other retained storage.

This memory translation remains heuristic. The public figures count entries,
not bytes, and do not provide an authoritative peak-RSS trace. The cap is
intentionally comfortable rather than knife-edge: under v5, memory is reported
only and does not enter the scored scalar, but it is still a reviewed bound.
If any included phase reaches `2^30` bytes, `memory_log2_bytes=30` fails.

Integer sensitivity at an illustrative cardinality
`N0 = ceil(2^19.8) = 912839`:

| Storage choice at N0 | Approx bytes | Within `2^30`? |
| --- | ---: | --- |
| One packed 40-byte array | 36513560 | Yes |
| Array plus 4-byte index per record | ≈40164916 | Yes |
| Array plus 8-byte pointer per record | ≈43816272 | Yes |
| Records padded to 64 bytes | ≈58421696 | Yes |
| Two simultaneously live packed arrays | ≈73027120 | Yes |
| Pathological multi-GB solver heaps | unknown | Must still fit under `2^30` |

The table shows that common table layouts fit easily under `2^30`; it does not
prove historical peaks. SAT/SMT and characteristic-search phases independently
have to respect the same cap.

The retained nonuniform advice needed by the online algorithm is only the two
128-byte messages. Allowing their 256 raw bytes plus length and digest metadata
still remains below 512 bytes, hence
`nonuniform_advice_log2_bytes=9`. Program text and target constants are charged
inside the peak-memory cap rather than hidden in advice.

## 8. Arithmetic, experiment interpretation, and limitations

The resource vector is therefore

| Field | Submitted bound | Meaning |
| --- | ---: | --- |
| `time_log2` | **49.81** | Total historical preprocessing plus deterministic replay, conditional on H-HISTORICAL-TIME (scored) |
| `memory_log2_bytes` | 30 | Peak bytes across all phases, conditional on H-HISTORICAL-MEMORY (reported only) |
| `preprocessing_log2` | 49.8 | Historical construction, paid once and included in total time |
| `success_probability` | 1 | Deterministic correctness of the retained, independently verified pair |
| `nonuniform_advice_log2_bytes` | 9 | Fewer than 512 bytes of pair and metadata |

Deprecated `data_log2` is omitted. Under v5 the scored scalar is exactly
`time_log2 = 49.81`. The advice exponent is not added again because advice is
already included in peak memory. Preprocessing is not added again because it is
already included in total time. There is no success amplification because the
deterministic pair succeeds on every online execution.

Experiment `published-r31-witness-replay` tests only this statement: the two
submitted distinct byte strings collide under the organizer's complete
`sha256-r31-prefix-v1` implementation. Organizer evidence consists of isolated
source evaluation, independently recomputed digests, repeated-pair flags, and
an explicit label that attack-cost inference is unavailable. All requested rows
transport the same pair; the duplicate successful rows are reproducibility
checks for transport and target verification, not independent samples from the
historical attack. They provide no evidence for historical time, memory,
preprocessing, generator reproducibility, historical success rate, or either
score-critical heuristic.

The certificate manifest is empty. Correctness evidence is the experiment
replay plus the hex messages in section 3, not a `hash-collision-witness-v2`
certificate file.

The witness establishes a real 31-round-prefix collision independently of the
cost claims. The publication and slides provide relevant evidence that a
practical attack was performed and describe its high-level construction. The
absence of a full generator, immutable build recipe, raw attempt ledger, and
organizer-model resource receipt blocks any claim that this package has
reproduced or rigorously certified the reported attack cost. Exploratory
qualification therefore depends on whether the disclosed conservative premises
and primary evidence make both heuristics plausible and not refuted. This
package makes no novelty, full-SHA-256, 32-round, security-lower-bound, or
rigorous-lane claim.

## 9. Source-by-source evidence map

| Source location | Relevant observation | Limit on its use |
| --- | --- | --- |
| Authors' ASIACRYPT slides, construction pages | Starting points, inverse-round relations, stored states and first-block matching provide a concrete construction outline | They do not disclose an allocator or a complete operation ledger |
| Slides, complexity slide | Approximately `2^19.8` ten-word table entries, complexity `2^40.5`, and a 1.2-hour run using 64 threads | Entries are not peak bytes; runtime is not organizer RAM units; matching headline is not all-history cost |
| Slides, message-pair slide | The public two-block message pair | Establishes a concrete target for independent digest recomputation |
| Publisher abstract and notes | Runtime corroborated; an unusually fast initial success was followed by further experiments and another pair | The number and total cost of those experiments are not given |
| EUROCRYPT 2024 / ePrint 2024/349 | Complete constructive estimate time `2^49.8`, memory `2^48` for ordinary 31-step SHA-256 | Uses its own units; anchors the conservative envelope, not a measured organizer ledger |

The public publisher page is
<https://link.springer.com/chapter/10.1007/978-981-96-0941-3_8>.
The slides URL is given in section 5; a locally inspected copy of the 17-page
slide PDF has SHA-256
`6a7247c13503511934c60ea38869d13318d35c6c3c10376ff2c8523e77014e29`.
The publisher's public abstract and notes were inspected; access to the full
subscription chapter is not claimed. No source file is redistributed here.
The source summaries and arithmetic needed for this assessment are included
in this proof, so following external links is not necessary to read the claim.

The additional reported experiments are relevant contrary pressure on any
narrow all-history time budget near `2^40.5`. They are one reason this package
uses the larger EUROCRYPT envelope instead. Nor does the witness's deterministic
replay success establish a success distribution for the original search.

## 10. Time conversion sensitivity under the EUROCRYPT 2^49.8 bound

Let `C_ec = 2^49.8` denote the EUROCRYPT complete constructive figure, read
under this package as a compression-equivalent upper bound on preprocessing.
Define `c` as the conversion from one unit of that reported work into charged
organizer compression units, and `D >= 0` as all charged work omitted by that
accounting beyond what `C_ec` already covers. H-HISTORICAL-TIME requires

```text
T_pre = c * C_ec + D <= 2^49.8
c + D/C_ec <= 1
```

| Assumed conversion c | Remaining budget for extra D |
| --- | --- |
| 1.0 | D must be 0 (published figure used as a hard preprocessing cap) |
| < 1.0 | Positive D budget opens (if publication units overcount organizer units) |
| > 1.0 | Cap fails for every nonnegative D |

These rows are sensitivity calculations, not estimates of c or D. Relative to
the prior `time_log2 = 50` package, the 0.1-bit padding above `2^49.8` is
removed; the premise is therefore tighter and still ~9 bits above the
ASIACRYPT matching headline. This analysis supplies failure thresholds, not a
new measured historical time result.

For the online phase retain the deliberately generous bound
`T_online < 2^20 + 6`. Conditional on the preprocessing premise,
`T_pre + T_online <= 2^49.8 + 2^20 + 6` and
`log2(2^49.8 + 2^20 + 6) ≈ 49.8000000015 < 49.81`.
Preprocessing is included once in total time.

## 11. What is proved versus what is conditional

**Proved / mechanically checkable (independent of heuristics):**

- The two 128-byte messages are distinct.
- Under `sha256-r31-prefix-v1`, both digests equal `55fdfb37…`.
- The same messages do not collide at 32 rounds or full 64-round SHA-256.
- Online success probability is 1 on the singleton probability space.

**Conditional on score-critical heuristics:**

- `time_log2 = 49.81` and `preprocessing_log2 = 49.8` require `H-HISTORICAL-TIME`.
- `memory_log2_bytes = 30` requires `H-HISTORICAL-MEMORY`.

**Explicit non-claims:**

- No new cryptanalysis or new differential characteristic.
- No reproduced practical generator with an organizer-unit ledger.
- No claim that `2^40.5` is a safe total-history bound.
- No birthday improvement; no 32-round or full-SHA-256 result.
- No rigorous-lane qualification; no human acceptance; no security lower bound.
- `baseline_improved = sha256-r31-nominal-v2` is the required nominal reference
  identifier, not an assertion of proved improvement over that nominal.

## 12. Comparison to other packages on this track

| Route | Typical declared `time_log2` | Notes |
| --- | ---: | --- |
| Generic birthday under v5 | ≈128.2–136 | No differential structure |
| Knife-edge fixed witness using only ASIACRYPT `2^40.5` | ≈41 | High refutation risk on discovery ledger |
| **This package** | **49.81** | Fixed witness; EUROCRYPT `2^49.8` preprocessing bound + online; empty certs + replay experiment |

## 13. Result of this revision

The exact witness remains independently verifiable via organizer experiment
replay. The proposed `time_log2 = 49.81` remains conditional on
`H-HISTORICAL-TIME`. Memory `30` remains conditional on `H-HISTORICAL-MEMORY`
and is unscored under v5.

This revision adopts the review-passing fixed-witness presentation style
(empty certificate manifest, deterministic `experiments/replay.py`, named
`H-HISTORICAL-TIME` / `H-HISTORICAL-MEMORY`, source-by-source evidence map,
proved-vs-conditional separation, explicit limitations) while tightening from the prior qualified 50 to 49.81 by removing only the
0.1-bit pad above EUROCRYPT `2^49.8`, rather than fabricating a knife-edge near 41.

No fresh historical peak trace, complete historical attempt ledger, or
calibrated organizer conversion is supplied. Accordingly this is an exploratory
proposal for assessment of the explicitly bounded premises. An AI
`plausible_not_refuted` outcome, if reached, is distinct from mathematical proof
or human acceptance under manual promotion.
