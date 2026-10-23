# Published single-block chosen-prefix collision for full MD5

This package targets `md5-s64-prefix-v1`: complete finite byte strings,
standard MD5 IV, RFC 1321 padding, steps 0 through 63 on every padded block,
feed-forward after every compression, and all 128 output bits. It packages a
published 128-byte collision for exploratory review. It does not claim a new
attack, fresh generation, rigorous qualification, or human acceptance.

The required `baseline_improved` value `md5-s64-nominal-v2` is an organizer
reference identifier. It is not an assertion that the nominal value is an
implemented attack or a proved security bound. The submitted scalar is
`62 + 30 = 92`; it is emitted only if the exploratory review qualifies.

## 1. Exact target and retained messages

Let `MD5-64(m)` be RFC 1321 MD5 on the complete byte string `m`. The initial
state is the standard four-word IV. Padding appends byte `80`, then zero bytes
until the length is 56 modulo 64, then the original bit length as a 64-bit
little-endian integer. Every padded block executes the original 64 steps and
feed-forward, and the result is serialized as little-endian A, B, C, D.

The retained messages below each contain 128 bytes. They therefore receive a
third, identical padding block during complete hashing; the padding bytes are
not part of the retained messages.

Message A:

```text
4f64656420476f6c6472656963680a4f
64656420476f6c6472656963680a4f64
656420476f6c6472656963680a4f6465
6420476fd8050d0019bb9318924caa96
dce35cb835b349e144e98c50c22cf461
244a4064bf1afaecc5820d428ad38d6b
ec89a5ad51e29063dd79b16cf67c1297
8647f5af123de3acf844085cd025b956
```

Message B:

```text
4e65616c204b6f626c69747a0a4e6561
6c204b6f626c69747a0a4e65616c204b
6f626c69747a0a4e65616c204b6f626c
69747a0a75b80e0035f3d2c909af1bad
dce35cb835b349e144e88c50c22cf461
244a40e4bf1afaecc5820d428ad38d6b
ec89a5ad51e29063dd79b16cf6fc1197
8647f5af123de3acf84408dcd025b956
```

They differ in both their 52-byte chosen prefixes and their suffixes. Direct
evaluation by the organizer reference and an independent standard-library MD5
implementation gives, for both messages,

```text
d320b6433d8ebc1ac65711705721c2e1
```

Thus the retained pair satisfies the exact ordinary-collision relation. The
declared experiment asks the organizer to recompute this fact; the participant
does not supply an authoritative digest or success flag.

## 2. Published construction represented by the package

The retained pair is the single-block chosen-prefix example in Section 6.5.4
and Table 6-7 of Marc Stevens' thesis. Each message consists of a 52-byte
chosen prefix followed by a 76-byte collision suffix. The construction first
compresses the chosen prefixes, then performs an 84-bit birthday search for a
pair of intermediate states whose difference is eliminable by one
near-collision block.

The birthday map selects between the two prefix states and projects the
resulting MD5 compression state to an 84-bit search value. The allowed
intermediate-state-difference family contains approximately `2^23.3` members
inside a space of `2^44` relevant differences. Requiring the two birthday
endpoints to originate from different prefixes contributes a further factor
of two. The source therefore estimates a useful birthday collision probability
of approximately `2^-21.7` per ordinary birthday collision.

The same source reports approximately `2^53.2` MD5 compression-function calls
for the useful birthday search and 400 MB of storage. It bounds construction
of the actual near-collision block by approximately `2^40.8` MD5 compression
equivalents, negligible relative to the birthday phase. It reports that the
displayed pair was produced by this construction and supplies the followed
differential path with the pair.

The package does not reinterpret those estimates as a measured v3 trace. It
represents the historical workflow as preprocessing that produced the retained
nonuniform advice. The online algorithm is finite and simple:

1. Load the two 128-byte retained messages.
2. Check that their lengths are 128 and their bytes differ.
3. Evaluate complete `MD5-64` on both messages.
4. Return the pair only when the full 16-byte digests agree; otherwise fail.

The advice is fewer than 512 bytes: 256 message bytes plus bounded lengths and
digest metadata. Historical construction is not hidden by this online replay;
the submitted time, memory, data, and preprocessing fields charge it through
the explicit premises below.

## 3. Submitted resource envelope

The raw paper arithmetic is

```text
53.2 + log2(400,000,000) = 81.775424759...
```

That number is only a documentary proxy. The submission instead uses the
wider vector `(62, 30, 55, 62, 1, 9)` for time, peak bytes, data,
preprocessing, success probability, and advice bytes respectively.

### Time and preprocessing

The paper's approximately `2^53.2` figure is expressed in MD5 compression
equivalents and dominates its approximately `2^40.8` near-collision phase.
The v3 envelope allows a factor below `2^8.8` over the dominant figure:

```text
2^53.2 * 2^8.8 = 2^62.
```

This margin covers conversion from historical compression-equivalent work to
v3 units, prefix processing, differential-path work, unsuccessful internal
trials included by the published average, table operations, message assembly,
the final six full-message compression calls, and verification. Because the
retained collision was constructed before online replay, all of that work is
also charged as preprocessing; hence `preprocessing_log2 = time_log2 = 62`.

This is a score-critical historical envelope, not a reconstructed instruction
ledger. It depends on heuristic H-HISTORICAL-WORK. If total historical work,
including attempts omitted from the publication, reached `2^62` v3 units, both
time fields would fail and the score would not be supported.

### Peak memory

The publication reports 400 MB of storage for the dominant birthday search.
The submitted limit is `2^30 = 1,073,741,824` bytes. It therefore leaves more
than 673 million decimal bytes for code, constants, prefix and path data,
working state, message buffers, allocator effects, and output beyond the
reported storage. The 256-byte retained pair is included.

This is not a peak-RSS measurement or a sum over physical memory installed in
the historical cluster. It is an abstract peak for one implementation of the
published algorithm. It depends on H-HISTORICAL-MEMORY. If simultaneous live
algorithm state reached `2^30` bytes, the memory field and score would fail.

### Data and advice

`data_log2 = 55` permits fewer than `2^55` construction items or selected
compression inputs, exceeding the dominant `2^53.2` estimate by a factor above
three. This is not external oracle data: every target computation remains in
the time charge. The field shares H-HISTORICAL-WORK because no complete item
ledger from the historical run is available.

`nonuniform_advice_log2_bytes = 9` permits fewer than 512 retained bytes. The
two messages occupy exactly 256 bytes; bounded length and digest metadata fit
inside the remainder. Code and public MD5 constants are charged to memory,
not hidden as advice. Construction of the advice is charged in preprocessing.

### Success probability

The online algorithm is deterministic once the retained advice is fixed. The
organizer independently verifies distinctness and complete digest equality, so
its success probability is one. This does not assert that a fresh execution of
the historical randomized generator succeeds with probability one, or that its
expected cost has been freshly measured.

## 4. Declared heuristics

### H-HISTORICAL-WORK

Statement: all work that produced the retained pair, including differential
path preparation, birthday search, near-collision construction, failed internal
attempts charged by the published average, assembly, and verification, fits
below `2^62` v3 charged units, and fewer than `2^55` construction items were
processed.

Support: the primary construction reports approximately `2^53.2` MD5
compression calls for the dominant phase and approximately `2^40.8` for the
near-collision phase. The submission adds a factor of approximately `2^8.8`
for model conversion and otherwise unitemized work.

Limitation: there is no executable fresh generator, complete historical job
ledger, instruction trace, or accounting of every unsuccessful development
run. Compression-equivalent estimates are not definitionally identical to v3
word-RAM units. The experiment verifies only the retained output. This premise
is suitable only for exploratory review and is score-critical.

### H-HISTORICAL-MEMORY

Statement: peak simultaneous algorithm memory during construction of the
retained pair was below `2^30` bytes, including tables, code, constants, path
data, buffers, working state, allocator overhead, and the retained output.

Support: the publication states 400 MB of storage for the birthday phase; the
claim supplies more than 673 million additional decimal bytes of headroom.

Limitation: the published figure is not accompanied here by a peak-RSS trace or
a phase-by-phase allocation ledger. The premise concerns algorithmic peak, not
aggregate installed RAM across parallel machines. The experiment measures no
construction memory. This premise is suitable only for exploratory review and
is score-critical.

### H-METHOD-TRANSFER

Statement: the published single-block chosen-prefix workflow and its reported
resource regime apply to the exact Table 6-7 pair retained here, rather than to
an unrelated MD5 variant or collision class.

Support: the publication identifies the messages as its 128-byte example,
states their shared digest, and reports the construction and path in the same
section. Independent organizer hashing verifies the full standard-IV MD5
collision on those exact bytes.

Limitation: fixed-witness agreement establishes target compatibility and
existence, not a replay of the generator or its resource use. The proof
summarizes rather than reimplements the full differential-path search. This
supporting premise is suitable only for exploratory review.

## 5. Experiment interpretation

Experiment `published-single-block-cpc-replay` returns the same retained pair
for every organizer trial. The organizer runs the source twice in fresh,
networkless, read-only containers, requires byte-identical output, and computes
both complete MD5 hashes independently. Expected successful rows are duplicate
transport checks, not independent generated collisions or a success-frequency
sample.

The program does not report trusted time, memory, preprocessing, data, or
success counts. The experiment cannot support H-HISTORICAL-WORK or
H-HISTORICAL-MEMORY by itself. Its relevance is confined to exact bytes,
complete-target correctness, and deterministic replay of the retained advice.

## 6. Claim boundary

The evidence supports an exploratory request with scalar 92 only if the paired
review finds the historical work and memory envelopes plausible and not
refuted. Mechanical validity and 256 checked replay rows do not themselves
qualify the score. A qualifying score would remain an AI review outcome, not a
new cryptanalytic record, proof of the reported historical costs, rigorous-lane
qualification, or human acceptance.

Primary provenance is Marc Stevens, *Attacks on Hash Functions and
Applications*, Section 6.5.4 and Table 6-7, and the corresponding Crypto 2009
work *Short Chosen-Prefix Collisions for MD5 and the Creation of a Rogue CA
Certificate*. All facts needed to interpret this candidate are summarized
above; external retrieval is not required by the judge.
