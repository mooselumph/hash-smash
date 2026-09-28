# SHA-256, 31 prefix rounds: unconditional single-block birthday collision

The scalar below is `time_log2` under `collision-frontier-v5`. Memory is a
separately reported resource bound with no scalar contribution.

This independent **exploratory** package selects target `sha256-r31-prefix-v1`,
cost model `collision-frontier-v5`, and policy `paired-lanes-v1`. It submits a
complete analytic algorithm, not an already computed collision. Readiness
requests review; it does not assert an AI outcome or human acceptance.

The construction is an unconditional, distribution-free birthday collision
search on single-block messages, with linear-pass radix-sort detection. It
declares **`time_log2 = 130`** with a fully summed cost accounting. It uses **no
heuristic**: no random-mapping or random-oracle assumption, no differential
characteristic, no round-independence assumption, no experiment, and no computed
witness. Its success probability is taken over the algorithm's own random
message draws for the single fixed target function, not over any ensemble of
functions. The required `baseline_improved` value `sha256-r31-nominal-v2` only
identifies the organizer's nominal display reference; this package claims no
improvement over that 128-bit reference, makes no comparison to any other
construction, and uses no property of the round reduction.

## 1. Exact message and complete-hash definition

Write BE_k(v) for the k-byte big-endian encoding of integer v. Messages are
exactly 55 bytes, so under FIPS 180-4 padding each pads to a single 512-bit
block (55 content bytes = 440 bits, then 0x80, then zero bytes to offset 56,
then the 64-bit big-endian length 440). Thus H of a 55-byte message is exactly
one selected-round compression from the fixed IV, with feed-forward and the full
256-bit output. Each hash is therefore exactly one target compression; no second
block is ever processed.

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

## 2. Algorithm

Set q = 2^129 and N = 2^256.

1. Draw q messages m_1, ..., m_q. Each m_i is a single 55-byte string whose
   440-bit content is an independent uniform draw from the algorithm's own
   randomness (a random seed expanded by a counter-mode stream). The 440-bit
   content space has size D = 2^440.
2. For each i compute the complete digest h_i = H(m_i) (one compression each)
   and store a three-word record (h_i as the 256-bit key, plus the two-word
   content of m_i) in a pre-allocated array A of exactly q records.
3. Sort A by the 256-bit key h_i with an eight-pass least-significant-digit
   radix sort over 32-bit digits: for each of the 8 digit positions run a stable
   counting sort using a 2^32-slot count array and a second pre-allocated array
   B of q records, ping-ponging A and B. Radix sort performs a fixed number of
   linear passes independent of the data, so it is data-oblivious and
   distribution-free.
4. Scan the sorted array once; if two adjacent records share the same key h,
   and their messages differ, output that pair. Verify the pair by recomputing
   both complete hashes and checking digest equality and message inequality.
   Otherwise report FAIL.

All q draws and all sort passes are charged even when the run fails; there is no
restart and no amplification. A returned pair is always two distinct valid
55-byte messages with identical complete sha256-r31 digests, verified by
recomputation.

## 3. Success probability (over the algorithm's own coins, fixed target)

The randomness here is the algorithm's own uniform content draws; the target f =
(55-byte message -> complete sha256-r31 digest) is a single fixed function. No
random-function, random-oracle, or random-mapping assumption is made or needed.

Drawing a uniform content induces a fixed output distribution p on the 2^256
digests, p(y) = |{contents mapping to y}| / D. For i.i.d. draws from any fixed
distribution p on n = 2^256 points,

    Pr(all q keys distinct) = sum over distinct-tuples ... <= prod_{i=0}^{q-1} (1 - i * Cmin)

is bounded using the pairwise collision probability C = sum_y p(y)^2. By
Cauchy-Schwarz, C = sum_y p(y)^2 >= (sum_y p(y))^2 / n = 1/n = 2^-256, with
equality iff p is uniform; a non-uniform p only increases C and hence increases
the collision probability. Using the uniform lower bound on C, the standard
inequality 1 - x <= exp(-x) gives, for the fixed target,

    Pr(all q keys distinct) <= exp( - q(q-1)/2 * C ) <= exp( - q(q-1)/(2n) ).

With q = 2^129 and n = 2^256,

    q(q-1)/(2n) = (2^258 - 2^129) / 2^257 = 2 - 2^-128 < 2,

so Pr(all q keys distinct) <= exp( -(2 - 2^-128) ) = exp(-2) * exp(2^-128)
< 0.13534 * (1 + 2^-127) < 0.13535. Hence a key collision occurs with
probability at least 1 - 0.13535 = 0.86465.

A key collision is a valid ordinary collision unless the two messages are
identical. Two identical 55-byte contents are drawn with probability at most
q(q-1)/(2D) < 2^258 / 2^441 = 2^-183. Subtracting this,

    Pr(success) > 0.86465 - 2^-183 > 0.86.

The declared `success_probability = 0.8` is a robust lower bound over the
algorithm's coins, well above the 0.39 minimum. It is not confidence in the
proof or in a review.

## 4. Resource accounting (fully summed)

On the 256-bit word RAM of `collision-frontier-v5`, one target compression costs
one unit and every other primitive word operation costs 1/C, C = 2140. Every
term below is included; nothing is neglected.

Per-record non-compression work, counted explicitly:

- Generation wrapper per message: expand the counter-mode stream and write the
  55-byte content and fixed padding into the buffer, at most 64 word operations
  (14 words for 55 bytes, a few for the stream and the length field, with
  headroom).
- Radix sort: 8 passes; each pass touches every record twice (count, then
  place). Per record per pass: extract the current 32-bit digit (<= 4), update
  the count or position (<= 4), and move a three-word record (<= 8), so <= 16
  word operations; over 8 passes <= 128 word operations per record. Clearing and
  prefix-summing the 2^32-slot count array costs 2 * 2^32 per pass, i.e.
  8 * 2^33 = 2^36 word operations total, independent of q.
- Final scan: extract and compare adjacent keys, <= 16 word operations per
  record.

So total non-compression work is at most W_total = (64 + 128 + 16) q + 2^36
= 208 q + 2^36 word operations. Note 208 < 2140 = C.

Charged totals, in units of one compression:

- Compression term: q + 2 compressions (generation plus at most two verification
  hashes) = 2^129 * (1 + 2^-128) units.
- Non-compression term: W_total / C = (208 q + 2^36) / 2140
  = (208/2140) q + 2^36/2140 < 0.09720 q + 2^25.4
  < 0.09720 * 2^129 + 2^25.4 units.
- Preprocessing: a loader writes code, IV, K constants, and base addresses in
  under 2^20 charged instructions.

Summing:

    T <= 2^129 (1 + 2^-128) + 0.09720 * 2^129 + 2^25.4 + 2^20
      < 2^129 * (1 + 0.09720 + 2^-103)
      < 2^129 * 1.09721
      = 2^129 * 2^0.13390
      = 2^129.134 units.

Because 2^129.134 < 2^130, the declared **`time_log2 = 130`** is a valid upper
bound on the total charged time, with about a 2^0.866 ~ 1.82x margin. The bound
holds for any per-record non-compression envelope below C = 2140 word
operations; the explicit envelope 208 is far below that.

- Memory (hard maximum, pre-allocated): arrays A and B each hold exactly q
  three-word (96-byte) records, 2 * 96 q = 192 q bytes; the 2^32-slot count
  array holds one word (<= 32 bytes) per slot, 2^37 bytes; fixed code, IV,
  constants, and scratch under 2^20 bytes. So peak memory is exactly at most
  192 * 2^129 + 2^37 + 2^20 = 2^129 * 192 + 2^37 + 2^20 < 2^136.59 + 2^37 + 2^20
  < 2^137 bytes. This is a fixed allocation and a true maximum, not an
  expectation. `memory_log2_bytes = 137` is the declared bound; memory is
  reported only and does not affect the score.

- `preprocessing_log2 = 20`; it is inside the total above. Nonuniform advice is
  zero bytes; the search uses no precomputed collision, favorable seed, or
  target-dependent advice.

## 5. Scope and limitations

This is an astronomically expensive theoretical RAM construction, not a computed
collision, a practical attack, or a new SHA-256 security result. It is an
ordinary generic birthday collision that uses no property of the 31-round
reduction and therefore does not approach or beat the nominal 128-bit reference,
which is a display value and not a qualified baseline. There are no heuristics
and no experiments; the certificate manifest is valid and empty. The success
probability, the time sum, and the memory maximum are all established above
without any unproven assumption. A tighter variant reduces q to 2^128 and
reaches the 0.39 success floor at a lower time, but this package deliberately
submits the robust q = 2^129 setting with a large success margin. An exploratory
`plausible_not_refuted` outcome, if reached, is an AI review outcome distinct
from mathematical proof or human acceptance.
