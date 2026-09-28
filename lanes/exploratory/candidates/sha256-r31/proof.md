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
heuristic**: no random-mapping, random-oracle, or pseudorandom-generator
assumption, no differential characteristic, no round-independence assumption, no
experiment, and no computed witness. Its randomness is the true independent
uniform coins of the randomized RAM model, so the input draws are independent
and identically distributed by construction, not by assumption. Its success
probability is taken over those coins for the single fixed target function, not
over any ensemble of functions. The required `baseline_improved` value
`sha256-r31-nominal-v2` only identifies the organizer's nominal display
reference; this package claims no improvement over that 128-bit reference, makes
no comparison to any other construction, and uses no property of the round
reduction.

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

## 2. Algorithm and its random source

Set q = 2^129, N = 2^256, D = 2^440.

The randomness is the randomized RAM model's random tape: a stream of mutually
independent, uniform random bits, available on demand. Reading a bit is an
ordinary word operation (counted in section 4); the tape is consumed streaming
and never retained, so it is not stored memory. No pseudorandom generator, seed,
or expansion is used; there is nothing to seed or to derandomize.

1. For i = 1..q, read 440 fresh independent uniform bits from the tape and place
   them as the 440-bit content of a single 55-byte message m_i. Because the bits
   are independent and uniform and disjoint across i, the contents c_1..c_q are
   independent and identically uniform on the content space of size D by
   construction (this is a property of the model's coins, not an assumption
   about any function).
2. For each i compute the complete digest h_i = H(m_i) (one compression each)
   and store a three-word record (h_i as the 256-bit key, plus the two-word
   content c_i) in a pre-allocated array A of exactly q records.
3. Sort A by the 256-bit key with an eight-pass least-significant-digit radix
   sort over 32-bit digits: for each of the 8 digit positions run a stable
   counting sort using a 2^32-slot count array and a second pre-allocated array
   B of q records, ping-ponging A and B. Radix sort performs a fixed number of
   data-oblivious linear passes, independent of the data.
4. Scan the sorted array once; if two adjacent records share the same key and
   their contents differ, output that pair, and verify it by recomputing both
   complete hashes and checking digest equality and message inequality.
   Otherwise report FAIL.

All q draws and all sort passes are charged even when the run fails; there is no
restart and no amplification. A returned pair is always two distinct valid
55-byte messages with identical complete sha256-r31 digests, verified by
recomputation.

## 3. Success probability (over the algorithm's own coins, fixed target)

The randomness is the algorithm's own coins from section 2; the target f =
(55-byte content -> complete sha256-r31 digest) is one fixed function. The
contents c_1..c_q are i.i.d. uniform, so the keys h_i = f(c_i) are i.i.d. draws
from the fixed output distribution p on the n = 2^256 digests, where
p(y) = |f^{-1}(y)| / D. No random-function, random-oracle, or
pseudorandomness assumption is used.

**Claim.** For q i.i.d. draws from any fixed distribution p = (p_1,...,p_n),

    Pr(all q keys distinct) <= exp( - q(q-1) / (2n) ).

*Proof.* For i.i.d. draws, the probability that all q are distinct is

    Pr(all distinct) = q! * e_q(p_1,...,p_n),

where e_q is the q-th elementary symmetric polynomial (sum over all size-q
subsets S of the product of p_i over i in S: each unordered set of q distinct
outcomes contributes q! ordered assignments, each of probability the product of
its p_i). The function e_q is symmetric and concave along any direction that
moves mass from a larger coordinate to a smaller equal-total pair, hence
Schur-concave on the simplex; it is therefore maximized at the uniform point
p_i = 1/n. This is the standard Schur-concavity of elementary symmetric
polynomials (equivalently, Maclaurin/Newton inequalities), and it does not
depend on any property of f beyond p being a probability vector. Thus

    Pr(all distinct)_p <= Pr(all distinct)_uniform
                        = n! / ((n-q)! * n^q)
                        = prod_{i=0}^{q-1} (1 - i/n)
                        <= exp( - sum_{i=0}^{q-1} i/n )
                        = exp( - q(q-1) / (2n) ),

using 1 - x <= exp(-x). This bounds the fixed target's distribution directly;
the pairwise quantity sum_y p(y)^2 is not needed. QED.

With q = 2^129 and n = 2^256,

    q(q-1)/(2n) = (2^258 - 2^129) / 2^257 = 2 - 2^-128 < 2,

so Pr(all q keys distinct) <= exp( -(2 - 2^-128) ) = exp(-2) * exp(2^-128)
< 0.13534 * (1 + 2^-127) < 0.13535. Hence a key collision occurs with
probability at least 1 - 0.13535 = 0.86465.

A key collision is a valid ordinary collision unless the two contents are
identical. Two identical 440-bit contents are drawn with probability at most
q(q-1)/(2D) < 2^258 / 2^441 = 2^-183. Subtracting this,

    Pr(success) > 0.86465 - 2^-183 > 0.86.

The declared `success_probability = 0.8` is a robust lower bound over the
algorithm's coins, well above the 0.39 minimum, and it is unconditional and
distribution-free. It is not confidence in the proof or in a review.

## 4. Resource accounting (fully summed)

On the 256-bit word RAM of `collision-frontier-v5`, one target compression costs
one unit and every other primitive word operation costs 1/C, C = 2140. Every
term below is included; nothing is neglected. All counts are per record unless
stated, with q = 2^129 records.

Generation, per message: read 440 random bits as 14 thirty-two-bit words from
the tape (14 loads) and write them into the buffer's content region (14 stores);
the padding byte and 64-bit length are written once into the persistent buffer,
not per message. At most 48 word operations (28 used, headroom to 48).

Radix sort, per record per pass, itemized: counting phase -- extract the current
32-bit digit (1 key load, 1 shift, 1 mask = 3), increment its count (1 load,
1 add, 1 store = 3), addressing and loop branch (2), total 8; placement phase --
extract the digit (3), read the output position (1 load), compute the target
address (1), move the three-word record (3 loads + 3 stores = 6), advance the
position (1 store), addressing and loop branch (2), total 14. So at most 22 word
operations per record per pass; declare 32 per pass with headroom. Over 8 passes
that is at most 256 word operations per record. Clearing and prefix-summing the
2^32-slot count array costs 2 * 2^32 per pass, i.e. 8 * 2^33 = 2^36 word
operations total, independent of q.

Final scan, per record: extract the key (3), compare with the previous key (1),
branch (1), advance (1); declare 12 with headroom.

Total non-compression work is therefore at most

    W_total = (48 + 256 + 12) q + 2^36 = 316 q + 2^36 word operations,

and 316 < C = 2140. Charged totals, in units of one compression:

- Compression term: q + 2 compressions = 2^129 * (1 + 2^-128) units.
- Non-compression term: W_total / C = (316 q + 2^36) / 2140
  = (316/2140) q + 2^36/2140 < 0.14767 q + 2^24.9
  < 0.14767 * 2^129 + 2^24.9 units.
- Preprocessing: a loader writes code, IV, K constants, the buffer padding, and
  base addresses in under 2^20 charged instructions.

Summing:

    T <= 2^129 (1 + 2^-128) + 0.14767 * 2^129 + 2^24.9 + 2^20
      < 2^129 * (1 + 0.14767 + 2^-104)
      < 2^129 * 1.14768
      = 2^129 * 2^0.19871
      = 2^129.199 units.

Because 2^129.199 < 2^130, the declared **`time_log2 = 130`** is a valid upper
bound on the total charged time, with about a 2^0.80 ~ 1.74x margin. The bound
holds for any per-record non-compression envelope below C = 2140 word
operations; the explicit envelope 316 is far below that.

- Memory (hard maximum, pre-allocated): arrays A and B each hold exactly q
  three-word (96-byte) records, 2 * 96 q = 192 q bytes; the 2^32-slot count
  array holds one word (<= 32 bytes) per slot, 2^37 bytes; fixed code, IV,
  constants, and scratch under 2^20 bytes. The random tape is consumed streaming
  and is not retained. So peak memory is exactly at most
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
probability (over the algorithm's true coins, via the Schur-concavity of the
elementary symmetric polynomial), the time sum, and the memory maximum are all
established above without any unproven assumption. A tighter variant reduces q
to 2^128 and reaches the 0.39 success floor at a lower time, but this package
deliberately submits the robust q = 2^129 setting with a large success margin
and a clean, fully summed 130. An exploratory `plausible_not_refuted` outcome,
if reached, is an AI review outcome distinct from mathematical proof or human
acceptance.
