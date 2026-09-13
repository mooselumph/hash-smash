# Published single-block collision transferred to MD5-s63

This package targets `md5-s63-prefix-v1`: complete finite byte strings,
the standard MD5 IV, RFC 1321 padding, steps 0 through 62 on every padded
block, feed-forward after every reduced compression, and all 128 output bits.
It retains a published 64-byte single-block MD5 collision and asks the
organizer to recompute it under the selected 63-step target. It does not claim
a new collision attack, a fresh generator, rigorous qualification, or human
acceptance.

The required `baseline_improved` value `md5-s63-nominal-v2` is an organizer
reference identifier. It is not an implemented attack, a security bound, or
evidence that this package improves a qualified baseline. The submitted scalar
is `60 + 32 = 92`, emitted only if exploratory review qualifies the evidence.

## 1. Exact target and retained messages

For a finite byte string `m`, define `MD5-63(m)` as follows. Start from the
standard four-word MD5 IV. Append byte `80`, then the minimum number of zero
bytes that makes the length 56 modulo 64, then the original bit length as an
eight-byte little-endian integer. On every resulting 64-byte block execute the
original MD5 steps with indices 0 through 62, without renumbering the message
schedule or constants, and add all four working words to the incoming state.
Serialize the final state as little-endian A, B, C, D. Equality means equality
of all 16 output bytes.

The retained messages are the pair in Table 5 of Marc Stevens,
*Single-block collision attack on MD5* (2012). Each is exactly 64 bytes.

Message A:

```text
4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87
d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18
af bf a2 00 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75
93 d8 49 67 6d a0 d1 55 5d 83 60 fb 5f 07 fe a2
```

Message B:

```text
4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87
d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18
af bf a2 02 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75
93 d8 49 67 6d a0 d1 d5 5d 83 60 fb 5f 07 fe a2
```

They differ at two bytes, so the ordinary-collision distinctness precondition
holds. Organizer reference evaluation of the selected target gives, for both,

```text
01cf5206724db1753a8bc3518e21a51b
```

The two 64-byte binaries downloaded from the author's result page have SHA-256
hashes `54bcb9a4fda31e4f254303e3959acd5e420ad18a80949d56a3000c3716fbd1a0`
and `90774a6455a2bdb7d106e533923ecbefe81392ca55bed0ce81cfab2c1a7f0afe`,
respectively. Their bytes match the constants in the replay source exactly.

The deterministic experiment recomputes that equality from the retained bytes;
the participant does not supply a trusted digest or success flag.

## 2. Why a full-MD5 single-block result solves this target

The paper writes the cyclic MD5 working variables as `Q_t`. With identical
incoming chaining states, a 64-step compression returns

```text
(a + Q_61, b + Q_64, c + Q_63, d + Q_62) mod 2^32.
```

After only 63 steps, indices 0 through 62, the same state convention returns

```text
(a + Q_60, b + Q_63, c + Q_62, d + Q_61) mod 2^32.
```

The published partial differential path gives zero difference in every late
state word `Q_60`, `Q_61`, `Q_62`, `Q_63`, and `Q_64` for the displayed
single-block collision. Its only input-word differences are
`delta m_8 = 2^25` and `delta m_13 = 2^31`; all other words are equal.
Consequently, after the first 64-byte block the two MD5-s63 chaining states are
equal. This is not an inference from final full-MD5 digest equality alone; it
uses the published late-state differential and is independently checked on the
exact bytes by the selected-target verifier.

Because both unpadded messages have the same 64-byte length, RFC 1321 appends
the same second block to both: byte `80`, 55 zero bytes, and the little-endian
bit length 512. That identical padding block starts from equal MD5-s63 chaining
states. Determinism therefore preserves equality through its reduced
compression and feed-forward. The resulting equality is a complete-message,
standard-IV, all-128-bit ordinary collision, not a compression-only,
free-start, near-collision, or truncated-output result.

## 3. Published construction represented by the package

Stevens' construction searches for a pair of 512-bit blocks from the fixed MD5
IV. It uses the two message differences above, a differential path with a low
number of first-round conditions, a lookup precomputation, and the three known
tunnels denoted T4, T9, and T14. Candidate blocks satisfying conditions through
the early steps are completed and checked against the compression relation.

The paper reports an experimentally determined average cost of `2^15.96` MD5
compression equivalents to obtain a candidate pair satisfying its conditions
through `Q_29`. It reports a conditional collision probability of `2^-33.85`
for such a pair. Its stated average construction cost is therefore

```text
2^15.96 * 2^33.85 = 2^49.81
```

full-MD5 compression equivalents. The paper says that the displayed Table 5
pair was found by the implemented construction after three weeks, earlier than
the five-week estimate. This package uses the reported average rather than
discounting the claim to the favorable realized wall time.

The author's published source exposes the main lookup as a mapping from two
32-bit masks to vectors of records. Each record contains five 32-bit values
(`Q3`, `Q6`, `Q7`, `Q13`, and `F15`). The implementation proceeds to its main
loop only after at least `2^24` records have been accepted. It also states that
independent instantiations can be freely parallelized.

The package does not execute that infeasible historical search. It represents
the work as preprocessing that produced nonuniform advice. The online algorithm
is finite and deterministic:

1. Load the two retained 64-byte messages.
2. Check that their lengths are 64 bytes and that their bytes differ.
3. Evaluate complete `MD5-63` on each message.
4. Return the pair only if the full 16-byte digests agree; otherwise fail.

The canonical binary advice is below 256 bytes: the two messages use exactly
128 bytes, and bounded lengths plus verification metadata fit in the remainder.
The experiment's hexadecimal transport representation does not change the
canonical advice; its source text and decoded buffers are charged to memory.
Historical construction is not hidden by the replay; its work and storage are
charged by the resource fields and explicit premises below.

## 4. Submitted resource envelope

The vector is `(60, 32, 60, 60, 1, 8)` for total time, peak memory bytes, data,
preprocessing, success probability, and nonuniform advice bytes. The scalar is
`60 + 32 = 92`.

### Time and preprocessing

The published `2^49.81` value is an average expressed in full-MD5 compression
equivalents. The claim allows fewer than `2^60` collision-frontier-v3 units, a
factor of about `2^10.19` (more than one thousand) above that reported work.
The margin covers conversion from measured compression equivalents to the v3
256-bit word-RAM operations, differential-path preparation, lookup creation and
access, condition tests, random choices, failed instantiations represented by
the published average, message construction, target conversion, padding, and
final verification.

The pair was produced before online replay, so this entire construction charge
is also preprocessing: `preprocessing_log2 = time_log2 = 60`. The online loads,
two complete target evaluations, comparisons, and output are included inside
the same bound rather than treated as free.

This is a score-critical historical envelope, not a fresh instruction ledger.
It depends on H-HISTORICAL-WORK. The paper does not enumerate every v3 word
operation or every unsuccessful historical development run. If total work that
must be attributed to constructing this pair reached `2^60` units, the time and
preprocessing fields would fail.

### Peak memory

The claimed peak is below `2^32` bytes, or 4 GiB, for a serial schedule of the
published construction. At the source's threshold of `2^24` accepted lookup
records, five 32-bit payload words per record occupy about 320 MiB before
container and allocator overhead. The 4-GiB envelope additionally includes map
nodes, vector capacity, code, constants, differential-path data, random state,
buffers, the retained messages, and output.

Parallelism is not used to hide storage. Since the paper describes different
instantiations as independently parallelizable, the same trials can be
scheduled serially and their storage reused, retaining total charged work while
bounding peak live state by one instantiation. Aggregate RAM installed across
historical machines is not the memory claim.

The source does not impose a hard 4-GiB cap, and neither a peak-RSS trace nor the
exact accepted-record count of the successful instantiation is retained here.
The bound therefore depends on H-HISTORICAL-MEMORY. If a serial schedule needs
`2^32` bytes or more at any point, the memory field and scalar fail.

### Data and advice

`data_log2 = 60` is a deliberately broad cap. Every selected-target
compression or complete-message evaluation costs at least one unit, so the
`2^60` total-time premise also bounds their count below `2^60`. Internal
candidate items and failed construction attempts are included rather than
treated as free external data.

`nonuniform_advice_log2_bytes = 8` permits the retained advice envelope below
256 bytes. The messages occupy 128 bytes; bounded length and digest metadata
fit in the remaining space. Public algorithm code, MD5 constants, and path data
are charged to construction time and peak memory, not hidden as advice.

### Success probability

The online algorithm is deterministic after its retained advice is fixed. The
organizer independently checks message distinctness and complete digest
equality, so its success probability is one. This does not assert that a fresh
random execution of the historical generator succeeds with probability one or
finishes inside the submitted bound on every random tape. Expected failed work
is represented by the paper's average and the historical-work premise.

## 5. Declared heuristics

### H-HISTORICAL-WORK

Statement: all work attributable to constructing the retained pair, including
path preparation, lookup operations, failed instantiations represented by the
published average, model conversion, assembly, and verification, fits below
`2^60` v3 units, with fewer than `2^60` data or construction items.

Support: the primary publication reports an implemented average cost of
`2^49.81` full-MD5 compression equivalents and binds its displayed pair to the
run. The submitted exponent leaves about `2^10.19` of conversion and accounting
margin and uses the average instead of the favorable three-week realization.

Limitation: no fresh full generator, historical instruction trace, complete job
ledger, or accounting of every development attempt is available. The replay
experiment measures none of these resources. Compression-equivalent work is
not definitionally the v3 word-RAM cost. This premise is score-critical and
suitable only for exploratory review.

### H-HISTORICAL-MEMORY

Statement: a serial schedule producing the retained pair has peak simultaneous
algorithm memory below `2^32` bytes, including all lookup structures and
overhead.

Support: the source identifies five-word lookup payloads, the `2^24`-record
threshold, and independent instantiations. The raw threshold payload is about
320 MiB; 4 GiB leaves more than an order of magnitude over that payload for
container capacity, allocation overhead, code, constants, path data, working
state, and output. Independent worker trials can reuse one allocation when
serialized.

Limitation: there is no peak-RSS measurement, allocation ledger, exact record
count for the successful trial, submitted hard memory guard, or retained seed
schedule. Source structure makes the bound plausible but does not prove it.
The replay consumes little memory and cannot establish construction memory.
This premise is score-critical and exploratory only.

### H-PUBLISHED-PAIR-BINDING

Statement: the paper's reported construction and resource regime apply to the
exact Table 5 messages retained here.

Support: the paper presents the method, complexity calculation, late-state
differential, exact messages, common full-MD5 digest, and statement that its
implemented search found the pair in the same result. The author's research
page also publishes the source and the two binary messages. Organizer hashing
independently verifies the selected s63 collision on those bytes.

Limitation: a fixed witness establishes collision existence and target
compatibility, not historical work or peak memory. The package summarizes the
generator rather than reproducing a `2^49.81` search. This premise is supporting
and exploratory only.

## 6. Experiment interpretation

Experiment `published-single-block-s63-replay` returns the same retained pair
for every organizer trial. The organizer runs the source twice in fresh,
networkless, read-only containers, requires byte-identical output, checks that
the two 64-byte messages differ, and computes both complete MD5-s63 digests with
its trusted reference.

Successful rows are duplicate transport and target checks. They are not
independent collisions, a fresh-generation success sample, an estimate of
expected runtime, or a construction-memory measurement. The participant source
reports no trusted cost or success count. Its relevance is confined to the
exact retained bytes, deterministic replay, and selected-target equality.

## 7. Claim boundary and provenance

The evidence supports an exploratory request with scalar 92 only if paired
review finds the historical work, memory, and pair-binding premises plausible
and not refuted. Mechanical validity and repeated checked rows do not by
themselves qualify the score. A qualifying score would remain an AI review
outcome, not a fresh collision-generation record, proof of the historical
resource envelopes, rigorous-lane qualification, or human acceptance.

Primary provenance is Marc Stevens, *Single-block collision attack on MD5*,
Cryptology ePrint Archive Report 2012/040, especially its MD5 definition,
Table 2 late-state path, Algorithm 1, Section 3.4 complexity analysis, and
Table 5 retained messages. The corresponding author research page supplies
the source archive and exact binaries. All facts needed for review are
summarized above; the judge need not retrieve an external resource.
