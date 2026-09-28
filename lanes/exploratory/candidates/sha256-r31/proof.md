# Practical 31-step SHA-256 ordinary collision (fixed witness, conservative v5 envelope)

This package is **not** a birthday attack. It reuses the published
Li–Liu–Wang–Dong–Sun practical ordinary collision for 31-step SHA-256
(ASIACRYPT 2024), as a fixed nonuniform-advice witness under
`collision-frontier-v5`, with an honest cost envelope deliberately above the
authors' matching-phase headline.

Declared resources (exploratory):

| Field | Value |
| --- | ---: |
| `time_log2` | **50** |
| `memory_log2_bytes` | 30 (reported only) |
| `preprocessing_log2` | 50 (inside total time) |
| `success_probability` | 1 |
| `nonuniform_advice_log2_bytes` | 9 |

Score is `time_log2` only. Memory does not enter the scalar.

## 1. Exact target

The selected profile is `sha256-r31-prefix-v1`:

- Algorithm: SHA-256 (FIPS 180-4).
- Fixed IV from the specification (no chosen IV / free-start / semi-free-start
  as the *target relation*).
- On every padded 512-bit block, execute compression rounds with original
  indices `0..30` inclusive, then the standard eight-word feed-forward.
- FIPS padding: append `0x80`, zero bytes to 56 (mod 64), then the 64-bit
  big-endian bit length.
- Compare all 256 digest bits in standard big-endian chaining order.

Out of scope for the claim: compression-only collisions, free-start collisions
as the accepted relation, near-collisions, truncation, 32-round or full-64
results, and quantum algorithms.

Each submitted message is exactly 128 bytes = two 64-byte blocks. FIPS padding
adds a third 64-byte block (bit length 1024). A complete selected-target hash
therefore uses **three** `sha256-r31` compressions per message.

## 2. Witness (certificate)

The organizer certificate `li-asiacrypt2024-r31-pair` stores two distinct
128-byte messages. Hex (32 bytes per line):

Message A:

```text
8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082
dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249
9abdeb1b1f195f415a7210c155614f13a2269dd1be888a61359257d4adf3737b
9f0484a6eb830a5866add94a9669232d45271fa5b8f69585428bbce30703b904
```

Message B:

```text
8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082
dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249
9abdeb1b1f195f415a7210c155614f13a2269dd1be887a6735b2dfc5fde32975
c70595a6eb838a5c66add94a9669232d45271fa5b8f69585428bbce30703b904
```

They share the first 64-byte block and differ in the second. The third padded
block is identical. Independently recomputed digests under the selected target
are equal:

```text
55fdfb37efcbd086e19c3de0f72596300a3acdf48da5b1d0450a592bb2869fcd
```

Negative delimiters (same complete messages): they do **not** collide at 32
rounds and do **not** collide under full 64-round SHA-256. Those checks bound
the claim; they are not higher-round results.

## 3. Online algorithm and success probability

Advice: the two raw 128-byte messages (256 bytes). Even with trivial length and
digest metadata, advice stays under 512 bytes, so
`nonuniform_advice_log2_bytes = 9` is a valid one-byte-exponent upper bound.

Online steps (deterministic; no algorithmic coins):

1. Load message A and message B from advice.
2. Reject if lengths differ from 128 or if `A == B`.
3. Compute `dA = sha256-r31(A)` and `dB = sha256-r31(B)` (three compressions
   each).
4. Accept iff `dA == dB`; otherwise fail.

The organizer certificate checker already verifies the same digest equality on
the immutable certificate bytes before review. Conditional on that verification,
the online algorithm's success event is certain, so
`success_probability = 1 >= 0.39`.

Probability space: a singleton (no random tape). This is algorithmic success
probability, not confidence that the historical-cost heuristics are true.

Cost-model note: a stored collision is **not** free. Section 6 charges the
historical construction that produced the pair inside preprocessing and total
time.

## 4. Why this is the practical 31-step route (not birthday)

Generic birthday collision search on a 256-bit digest needs on the order of
`2^128` hashes at the 0.39 success floor and cannot honestly go meaningfully
below `time_log2 ≈ 128` under v5. Prior packages on this track that declared
`≈128.2–128.5` are that generic route.

This package instead uses the **published differential cryptanalytic
construction** for ordinary 31-step SHA-256 collisions:

1. **EUROCRYPT 2024** (Li, Liu, Wang; ePrint 2024/349), Section 4.2: a
   two-block method converting a semi-free-start differential characteristic
   into a fixed-IV ordinary collision, with published complexity
   **time `2^49.8`, memory `2^48`** for 31-step SHA-256 (improving Mendel et
   al. EUROCRYPT 2013 time `2^65.5`).
2. **ASIACRYPT 2024** (Li, Liu, Wang, Dong, Sun): a memory-efficient replacement
   for the meet-in-the-middle matching stage. Official conference slides report
   precomputation of about **`2^19.8` valid tuples**, matching-phase
   **time complexity `2^40.5`**, memory complexity **`2^19.8`**, and a
   practical colliding pair in **1.2 hours on 64 threads**. DOI
   `10.1007/978-981-96-0941-3_8`. Slides:
   `https://iacr.org/submit/files/slides/2024/asiacrypt/asiacrypt2024/64/64_slides.pdf`.

High-level attack shape (restated for the judge; no external fetch required):

- Fix a 31-step signed differential characteristic with local collision
  structure in the message expansion (nonzero differences among early expanded
  words such as `W5..W9`, `W16`, `W18` in the EUROCRYPT characteristic family).
- **Block 0:** search for a first message block that maps the fixed IV to a
  chaining value compatible with the characteristic's connecting conditions
  (especially a prescribed `A_{-1}` class).
- **Precomputation:** build a table of valid intermediate tuples satisfying the
  characteristic's middle conditions (ASIACRYPT: ~`2^19.8` entries).
- **Matching:** try first blocks, match induced state against the table, then
  use remaining freedom in late message words (`W13`, `W14`, `W15`) to finish
  uncontrolled conditions and output a colliding second-block pair.

The retained certificate pair is an output of that constructive route. The
online algorithm does not re-run the search; it replays the pair and charges
the search historically.

## 5. Public complexity facts used as evidence

The following facts are restated from the cited public sources. They are
evidence for the heuristics, not a substitute for v5 accounting.

| Source | Claimed ordinary 31-step complexity | Notes |
| --- | --- | --- |
| Mendel et al., EUROCRYPT 2013 | time `2^65.5`, memory `2^34` | Prior best theoretical |
| Li–Liu–Wang, EUROCRYPT 2024 | time `2^49.8`, memory `2^48` | Complete constructive estimate |
| Li–Liu–Wang–Dong–Sun, ASIACRYPT 2024 slides | time `2^40.5`, memory `2^19.8` | Memory-efficient matching phase; practical 1.2 h / 64 threads |

Additional public caveat (Springer abstract / chapter notes as discussed in
prior public HashSmash notes): an unusually quick initial success is distinct
from later timed experiments. Expected attack-phase cost near `2^40.5` is
therefore not automatically equal to one lucky wall-clock sample, and
**characteristic-search / tooling cost is not itemized inside the `2^40.5`
figure**.

Under heuristic `H-PUB-UNITS`, both `2^49.8` and `2^40.5` are read as
compression-equivalent counts for `sha256-r31`. This package **does not** apply
the v5 factor `1/2140` to shave those figures.

## 6. Resource accounting under collision-frontier-v5

Model: classical probabilistic 256-bit word RAM. One selected-round target
compression costs `1` unit. Every other primitive word operation costs
`1/C` with `C = 2140` for `sha256-r31`. Total time includes preprocessing,
failed trials, randomness, sorting/lookup, verification, and success
amplification. Parallelism charges total work, not wall-clock. Quantum is out
of scope.

### 6.1 Online phase (exact)

- Compressions: `6` (three per message × two messages).
- Word operations: a few hundred loads/compares/branches, charged `< 2^10 / 2140`
  compression-equivalents.
- Online total: `< 2^4` units.

### 6.2 Historical / preprocessing phase (heuristic)

Let `T_hist` be all charged work that produced the retained pair.

- The ASIACRYPT matching-phase headline alone is about `2^40.5` under
  `H-PUB-UNITS`.
- Characteristic discovery, SAT/SMT search, starting-point work, failed
  candidates, and extra experimental runs are **not** given as an organizer
  ledger. Declaring `time_log2 ≈ 41` from the matching headline alone is the
  knife-edge pattern this package refuses.
- The same authors' EUROCRYPT 2024 **complete** constructive complexity
  `2^49.8` already prices a full ordinary 31-step collision route (including a
  heavier matching stage). Under `H-FULL-ATTACK-ENVELOPE` we treat

  `T_hist ≤ 2^49.9`

  as a conservative public upper envelope on everything historical needed to
  emit some (hence, this) ordinary 31-step colliding pair, with the ASIACRYPT
  practical run used only as supporting evidence that a cheaper matching engine
  exists inside that envelope—not as a measured total for discovery+matching.

### 6.3 Total time

`T ≤ T_hist + T_online ≤ 2^49.9 + 2^4 < 2^50`.

Therefore `time_log2 = 50` is a valid declared upper bound under the stated
heuristics. `preprocessing_log2 = 50` bounds setup inside that same total (it
is not added a second time beyond `time_log2`).

Arithmetic check: `2^49.9 + 16 < 2^49.9 (1 + 2^-45.9) < 2^50`.

### 6.4 Memory (reported only)

Peak historical memory is dominated by the ASIACRYPT precomputation table of
about `2^19.8` tuples. Even allowing ~40–64 bytes per tuple plus code and
scratch, the footprint is far below `2^30` bytes. Online advice is 256 bytes.
Declare `memory_log2_bytes = 30`. Memory is reviewed but unscored.

### 6.5 What we are *not* claiming

- We do **not** claim `time_log2 = 40.5`, `41`, or any value below `50`.
- We do **not** claim a new differential characteristic, a reproduced generator
  with a measured organizer-unit trace, or rigorous-lane qualification.
- We do **not** claim that exploratory `plausible_not_refuted` (if awarded) is
  mathematical proof or human acceptance.
- We do **not** assert that `baseline_improved` means this beats a proved
  security bound; it is the required nominal reference identifier
  `sha256-r31-nominal-v2`.

## 7. Heuristic summary

| ID | Role | Score effect if false |
| --- | --- | --- |
| `H-PUB-UNITS` | score-critical | Publication figures might not map 1-1 to compression units; envelope could understate. |
| `H-FULL-ATTACK-ENVELOPE` | score-critical | If true historical work `> 2^49.9` compression-equivalents, `time_log2=50` fails. |
| `H-WITNESS-IDENTITY` | supporting | Bibliographic only; certificate still checks digests. |

Epistemic judgment of a heuristic is distinct from `success_probability=1`.

## 8. Comparison to birthday packages on this track

| Route | Typical declared `time_log2` | Structure used |
| --- | ---: | --- |
| One-block / two-block birthday + sorting | ≈128.2–136 | None (generic) |
| Knife-edge fixed-witness using only ASIACRYPT `2^40.5` | ≈41 | Differential, under-charging discovery risk |
| **This package** | **50** | Differential fixed witness, EUROCRYPT `2^49.8` envelope |

## 9. Limitations and further work

- Stronger scores require either (a) a reproducible generator with an auditable
  v5 operation ledger, or (b) organizer experiments that estimate local
  probabilities for a fully specified randomized search, not only a stored pair.
- Human promotion review may still reject historical-cost heuristics even when
  AI exploratory review passes; that is expected under `promotionMode: manual`.
- A future package could implement the memory-efficient matching algorithm as a
  randomized search with explicit per-step heuristics and charge expected
  `≈2^40.5` matching cost **plus** a separately evidenced discovery bound,
  possibly landing between 45 and 50 without relying on a fixed public pair.

