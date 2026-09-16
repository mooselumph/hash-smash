# Full-round SHA-1 collision search with stable radix sorting

Selected track: **sha1-r80-exploratory**. Target: **sha1-r80-prefix-v1**.
Cost model: **collision-frontier-v5**, with one full target compression costing
1 and each other primitive 256-bit RAM operation costing 1/1982.

This is a uniform, generic birthday-search algorithm, with a worst-case total
charged time bound of **2^80.404** target-compression equivalents and success
probability at least **0.39**. Peak memory is bounded by **2^88 bytes**.
It replaces the inherited candidate's 80 comparison-mergesort passes with
10 stable 16-bit counting-sort passes. No SHA-1 differential attack, execution
at the full resource scale, actual collision witness, or cryptanalytic novelty
is claimed. In particular this is not a reproduction of SHAttered or SHAmbles.
The substantial memory requirement is explicit and does not affect ranking
under the selected time-only model.

The finite-domain probability argument and exact one-block message family are
adapted from the repository's initial candidate at commit
657effa83c277a1d68476a667686960439a9db07. The new algorithm, sorting argument and
current-model cost accounting are specified below. No external reference is
needed to establish a mathematical or cost step of this package.

## 1. Exact hash and message family

Let N = 2^80, M = 2^160, and D be all 32-byte strings, with |D| = 2^256.
Each message is the big-endian encoding of one unsigned 256-bit integer x,
including leading zero bytes. Its original bit length is 256, below 2^64.
Let h(x) be its complete selected-profile hash, interpreted as an unsigned
160-bit integer with 96 leading zero bits in a 256-bit storage word.

The complete padded block is the 32 message bytes, byte 0x80, 23 zero bytes,
and the eight-byte big-endian encoding of 256. Thus it is exactly 64 bytes.
Represented by two consecutive big-endian 256-bit words, it is
`(x, (1 << 255) OR 256)`. No second block is used.

For completeness the selected compression is defined here. Parse that block as
16 big-endian 32-bit words W[0],...,W[15]. For t = 16,...,79 set
W[t] = ROL32(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16], 1).
Initialize (a,b,c,d,e) from the fixed IV
(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0).
For each original index t = 0,...,79, choose:

| t | f(b,c,d), with NOT restricted to 32 bits | K[t] |
| --- | --- | --- |
| 0 through 19 | (b AND c) OR ((NOT b) AND d) | 0x5a827999 |
| 20 through 39 | b XOR c XOR d | 0x6ed9eba1 |
| 40 through 59 | (b AND c) OR (b AND d) OR (c AND d) | 0x8f1bbcdc |
| 60 through 79 | b XOR c XOR d | 0xca62c1d6 |

Compute v = (ROL32(a,5) + f(b,c,d) + e + K[t] + W[t]) modulo 2^32,
then simultaneously replace (a,b,c,d,e) by (v,a,ROL32(b,30),c,d).
After index 79, add the five working words respectively to the five original
IV words modulo 2^32. Concatenate all five resulting words in their original
order, each in big-endian byte order, to obtain all 20 digest bytes.
Each message and each verification starts anew with that same fixed IV.
This is all 80 prefix rounds, full feed-forward and full output; there is no
free-start choice, compression-only target, truncation or altered padding.
The organizer model charges this selected target compression one unit; its
internal schedule/round arithmetic is part of that primitive. The outer block
construction, IV loading, serialization and call bookkeeping are also charged.

## 2. Algorithm and concrete RAM layout

N = 2^80, B = 2^16, mask = B-1. There are ten passes, at shifts
s = 0,16,...,144. Each complete digest is the unsigned 160-bit value defined
in section 1; all shifts and masks act on a zero-extended 256-bit word.

Use two disjoint arrays A and Z, each containing N records of two 256-bit
words. The first word is the complete digest and the second is the complete
32-byte message integer. A record occupies 64 bytes. Use a third array C
of B single-word entries (32B bytes), reused for counts and destination pointers.
All pointers in the pseudocode are **word addresses**; incrementing a record
pointer by 2 advances 64 bytes. Address space is the specified 256-bit RAM,
not a finite physical-machine memory assumption.

Reserve disjoint address ranges, with fixed code and scratch outside them.
Do not read unwritten array words. Generation writes all of A. Every sorting
pass initializes every C entry and writes all of its destination array before
that destination becomes the next source. No exponential zeroing, virtual-memory
service, hash table, allocator, sorting oracle, division or multiplication is used.
C is explicitly initialized; reserving a RAM address range itself does not
provide precomputed values. All actual reads and writes are counted below.

LOAD and STORE each access one 256-bit word. h is the complete one-block
hash from section 1. Registers, including copies and loop counters, are included
in the operation budgets. The following is inert mathematical pseudocode;
no participant executable or experiment is submitted.

```text
N := 1 << 80
B := 1 << 16
mask := B-1
p := base(A)
end := p + (N << 1)
while p < end:
    x := FRESH_UNIFORM_256_BIT_WORD()
    d := h(x)
    STORE(p,d)
    STORE(p+1,x)
    p := p+2

src := base(A)
dst := base(Z)
s := 0
while s < 160:
    j := 0
    while j < B:
        STORE(base(C)+j,0)
        j := j+1

    p := src
    end := src+(N << 1)
    while p < end:
        d := LOAD(p)
        k := (d >> s) AND mask
        z := base(C)+k
        u := LOAD(z)
        STORE(z,u+1)
        p := p+2

    pos := dst
    j := 0
    while j < B:
        z := base(C)+j
        u := LOAD(z)
        STORE(z,pos)
        pos := pos+(u << 1)
        j := j+1

    p := src
    while p < end:
        d := LOAD(p)
        x := LOAD(p+1)
        k := (d >> s) AND mask
        z := base(C)+k
        q := LOAD(z)
        STORE(q,d)
        STORE(q+1,x)
        STORE(z,q+2)
        p := p+2

    temp := src
    src := dst
    dst := temp
    s := s+16

p := src
d_prev := LOAD(p)
x_prev := LOAD(p+1)
p := p+2
end := src+(N << 1)
while p < end:
    d := LOAD(p)
    x := LOAD(p+1)
    if d == d_prev and x != x_prev:
        e0 := h(x_prev)
        e1 := h(x)
        if x_prev != x and e0 == e1 and e0 == d:
            return SUCCESS, big_endian_32_bytes(x_prev), big_endian_32_bytes(x)
        else:
            return FAILURE
    d_prev := d
    x_prev := x
    p := p+2
return FAILURE
```

The algorithm makes exactly N fresh random draws and N complete hashes in
all executions, plus at most two complete verification hashes. Sorting and the
failure scan are bounded independently of the digest distribution. There is one
batch, no restart, no rejected trial, no offline table, and no discarded random
batch. Fresh model random words, not deterministic PRNG output, are its coins.

## 3. Collision-detection correctness

The count loop computes the exact number n[k] of records of each digit k.
All n[k] fit one word because they lie between 0 and N. The prefix loop
initializes C[k] to dst+2*sum(n[j], j<k). Therefore the output regions for
all B buckets are pairwise disjoint, collectively have N records, and lie
inside the destination array, including when all digests occupy one bucket.

The scatter loop reads each source record once in source order, writes both
words at that bucket's next unused address, and advances that address by two.
It never overwrites its source array. Exactly n[k] records go to bucket k,
so all destination words are initialized exactly once. Within each bucket,
source order is preserved. This proves that each pass is a stable permutation
of the input records, sorted by its selected 16-bit digit.

Inductively, after pass j (j starting at zero) records are ordered by their
lowest 16(j+1) digest bits. The new higher digit orders buckets, and stability
preserves the order of lower digits inside each bucket. After ten passes the
full 160-bit digest is sorted. The association between a digest and its original
message is preserved because the two words are always copied together.

All equal-digest records now form a contiguous group. A group containing two
distinct message words necessarily has some adjacent pair with distinct message
words: otherwise equality of every adjacent pair makes the entire group equal.
**Sorting the message words is unnecessary.** The adjacent scan therefore
finds a genuine collision if one exists among the sampled messages, even when
some sampled inputs are repeated. Repeated copies of one message alone never
count as success. Verification compares full messages and full digests and
cannot fail in the specified RAM computation because d=h(x) is invariant.
Every successful output meets the complete, fixed-IV, padded 80-round target.

## 4. Unconditional algorithmic success probability

The target h is fixed. The sole probability space is the N fresh independent
uniform 256-bit random words expressly provided and charged by the organizer's
model. This is not a claim that a seeded PRNG supplies independent words, nor
that SHA-1 is a random function. There is no randomness assumption about h.
For each possible digest y, put p[y] = |{x in D : h(x)=y}| / 2^256.
Applying a fixed function separately to independent input draws produces
independent output draws with this fixed distribution p; output uniformity,
balance and collision-event independence are not needed.

For N <= M, the probability that all N outputs are distinct is N! e_N(p),
where e_N is the sum of products over all N-element subsets of the M output
labels (include zero-probability labels). Its maximum over the probability
simplex is attained by the uniform vector. Here is a self-contained proof.
Fix all coordinates except a,b; the polynomial has the form
A + (a+b)B + ab C with C >= 0. Replacing a,b by their mean preserves a+b
and increases ab, so it cannot decrease the polynomial. The simplex is
compact; choose a maximizer with minimum sum of squared coordinates among
maximizers. If any two coordinates differ, averaging either strictly
increases the polynomial, contradicting maximality, or keeps its value and
strictly decreases that sum of squares, contradicting the tie-break.
Thus that maximizer is uniform, and

```text
P(no repeated output) <= N! binom(M,N) / M^N
                      = product from i=0 to N-1 of (1-i/M)
                      <= exp(-N(N-1)/(2M)).
```

The final inequality uses 1-u <= exp(-u) for 0 <= u < 1, proved for example
by integrating the inequality 1/(1-u) >= 1 for -log(1-u).
Let E be the event of a repeated output and R the event of a repeated input.
For each input-index pair, equality has probability exactly 2^-256, so the
union bound gives P(R) <= N(N-1)/(2*2^256) < 2^-97.
On E outside R there are two distinct colliding inputs. Section 3 therefore
implies, without asserting independence of E and R,

```text
P(SUCCESS) >= P(E) - P(R)
           >= 1 - exp(-N(N-1)/(2M)) - N(N-1)/(2*2^256).
```

Here N(N-1)/(2M) = 1/2 - 2^-81 > 499/1000. The positive exponential
series gives the following exact rational lower bound, so no floating-point
birthday approximation is being used:

```text
exp(499/1000) > 1 + 499/1000 + (499/1000)^2/2 + (499/1000)^3/6
             = 9865254499 / 6000000000.
6000000000 / 9865254499 < 609/1000
because 6000000000000 < 6007939989891.
```

Consequently P(SUCCESS) > 391/1000 - 2^-97 > 39/100, since 2^-97 < 1/1000.
The claim conservatively records success_probability = 0.39. It refers to
algorithmic success, not confidence in this argument or in a reviewing model.
The proof holds for every fixed function D -> {0,1}^160 and therefore for the
particular complete 80-round hash just defined, including nonuniform outputs.

## 5. Worst-case time under collision-frontier-v5

Let C_sha1=1982. Charge H target compressions and W other allowed primitive
operations as H+W/C_sha1. All input messages occupy one padded block. Their
internal SHA-1 message expansion, round operations and feed-forward are included
once in H; those same internals are not counted again in W. Outer block/IV
setup, serialization, memory access, randomness and loop work are in W.

The following budgets are for every random outcome, including maximal bucket
imbalance and complete failure. An arithmetic or load result can be assigned
to a destination register by that instruction; explicit register-only copies
are conservatively counted as one operation. A loop charges its comparison,
conditional branch, and backward branch. Constants and addresses fit one word.
There is no uncharged allocation/initialization of the exponential arrays.

| Component | Target compressions | Other primitive operations, upper bound |
| --- | ---: | ---: |
| Fixed code, constants and scratch initialization | 0 | 2^20 |
| Generate N records and hash each full message | N | 128N |
| Clear the B count words, per pass | 0 | 6B |
| Count N digits, per pass | 0 | 16N |
| Convert B counts to absolute destination pointers, per pass | 0 | 12B |
| Stable scatter of N two-word records, per pass | 0 | 32N |
| Loop setup, exits, pointer swap and shift update, per pass | 0 | 256 |
| Adjacent scan including the no-match case | 0 | 32N |
| Final verification, comparisons and result serialization | at most 2 | 256 |

Here is an explicit lowering justification for the table rather than an
assumption that a sorting library has unit cost.

* Generation: one fresh random word; at most 32 outer operations to initialize
  the fixed IV, form the padded block from x and the fixed second word, pass
  compression arguments, and assemble five 32-bit output words into one
  160-bit key (four shifts and four ORs suffice for assembly); two record
  stores, pointer arithmetic and loop control. Even charging explicit copies
  and scratch stores leaves this below 128 non-compression operations per
  record. The compression's core is charged separately as one target operation.
* Clear: per entry, one address addition, one zero store, one counter increment,
  one comparison, one conditional branch and one backward branch: 6 operations.
  The final loop exit and initial j assignment are inside the per-pass allowance.
* Count: one digest load; one shift and one AND; one C-address addition; one
  count load, increment and store; one record-pointer increment; comparison,
  conditional branch and backward branch. This is 11 operations, below 16.
* Prefix: one C-address addition, one count load, one pointer store, one shift
  of the count, one position addition, one counter increment, comparison,
  conditional branch and backward branch. This is 9 operations, below 12.
* Scatter: two record loads plus the p+1 addition; shift and AND; C-address
  addition and pointer load; two destination stores plus the q+1 addition;
  q+2 addition and C-pointer store; p+2 increment; comparison, conditional
  branch and backward branch. This is 16 operations, below 32, including
  ample room for scalar register copies. There are no hidden per-bucket lists.
* Scan: two record loads and p+1 address addition, at most four operations for
  digest/message comparisons and their branches, two explicit previous-record
  copies, p+2 increment, and loop comparison/branch/backward branch. This is
  below 32 per record. The initial previous-record loads and setup fit in
  the spare operations of the N (rather than N-1) record allowance. A candidate
  pair triggers only the separately charged final verification and then exits.
* Pass setup has fewer than 32 scalar operations, including final inner-loop
  tests and swap; 256 accounts for all those fixed overheads. Only ten passes
  occur. The final outer-loop test is included in the final allowance.
* Final handling has two compression calls plus at most 128 outer operations
  per call/message, including distinctness and three equality checks, full
  serialization, and the success/failure return.

The fixed program can be encoded in at most 4096 instructions with at most
four 256-bit words per instruction, hence at most 2^19 bytes. The pseudocode
has fewer than 128 scalar statements; each of its macros expands to fewer
than 32 instructions. Loops are not unrolled. The selected compression is the
charged primitive. Another 2^19 bytes covers constants, all registers, full
padded input blocks, two digest workspaces, current records, return buffers and
scratch. Initializing at most 2^15 words at at most 16 operations per word
costs at most 2^19, beneath the 2^20 allowance. Clearing C is charged per pass.
This includes loading code and constants; there is no external search advice.

Consequently H <= N+2 and

    W <= 2^20 + 128N + 10*(6B+16N+12B+32N+256) + 32N + 256
       = 640N + 180B + 2^20 + 2816.

The complete worst-case bound, in target-compression equivalents, is

    T <= N+2 + (640N + 180B + 2^20 + 2816)/1982.

This includes every failed draw, random-word request, initialization, load,
store, comparison and verification. It sums computation, not parallel time.
With N=2^80 and B=2^16, log2 of this explicit rational bound is less than
80.403711. We round upward to the declared **time_log2 = 80.404**.

A simple bound verifies the rounding without relying on machine floating point:
all the additive non-N terms in T are less than 7000, hence

    T/N < 1 + 640/1982 + 7000/2^80 < 1.323.

For comparison, log(2) > 0.6931 (e.g. the positive series
2*sum((1/3)^(2j+1)/(2j+1), j>=0), whose first four terms already exceed
0.6931). Thus 2^0.404 > exp(0.404*0.6931). The first five positive terms
of the exponential series at 0.404*0.6931 exceed 1.323. Therefore
T < 1.323*N < 2^80.404. These finite rational comparisons can be checked
independently; the decimal 80.403711 is informative, not needed for the proof.

## 6. Memory, data, preprocessing and advice

A and Z jointly hold 4N words, hence 128N=2^87 bytes. C has B words, hence
32B=2^21 bytes. Code, fixed constants, all live registers, hash scratch and
returned messages are bounded by the further 2^20 bytes justified in section 5.
Therefore peak memory is at most 2^87+2^21+2^20 < 2^88 bytes. All intermediate
addresses, including the last one-past-the-end pointer, fit within 256 bits.
All counts and shifts also fit; no modular wraparound occurs in pointer/count
arithmetic. This is a theoretical RAM construction with an enormous memory
requirement, not a claim that such memory is physically available.

N independent 32-byte messages are drawn and evaluated; at most two retained
messages are evaluated again. Hence data_log2=81 bounds the N+2 complete
message evaluations, not bytes. The chosen-message input volume is 32N bytes;
it is already represented in the retained records and charged memory traffic.
No external data or extra random tape is used.

Fixed preprocessing takes at most 2^20 ordinary RAM operations, which is
2^20/1982 target-compression equivalents, less than 2^10. Thus the declared
preprocessing_log2=10 is a conservative bound in the same computation units
as total T. This preprocessing is included once in total T. Bucket clearing is
online work included in each pass, not hidden preprocessing.

No nonuniform advice is used. In the schema, nonuniform_advice_log2_bytes=0
is the upper bound of one byte on actual zero advice because log2(0) is not
representable. Program text and public hash constants are included in code
memory and preprocessing, not counted as free advice. No precomputed collision
is stored or downloaded, and no historical collision-search work is omitted.

## 7. Evidence and comparison limits

The only algorithmic probability is over fresh independent model random words.
Section 4 proves the success bound for every fixed function from the declared
message domain to 160 bits. The proof does not assume SHA-1 behaves randomly,
that digest buckets are balanced, that pair-collision events are independent,
or that a PRNG provides ideal independent randomness. Accordingly heuristics
is empty. The algorithm always finishes within the declared worst-case bound;
no distributional assumption is needed for counting-sort costs.

No experiment is declared. No participant program is supplied, and the empty
version-2 certificate manifest claims no explicit collision witness. The proof
is analytic; a small toy run would not constitute execution of this search.
Mechanical validation is not cryptanalytic review or an official score.
A selected-lane review and subsequent manual acceptance are still required.

The required baseline_improved identifier is sha1-r80-nominal-v2. Its nominal
80 is not a measured or qualified attack. This proposal's score 80.404 is
**above** that nominal value and makes no claim to improve it. It does improve
the operation bound of the inherited comparison-sorting construction under
v5 by replacing its 80 merge passes with ten bounded stable radix passes.
Comparison with Yukon's live incumbent is a separate server decision. Memory
remains a declared resource, with no contribution to this time-only ranking.

This submission is an algorithm-engineering improvement to a generic complete
hash collision search. It is not a new weakness in SHA-1 and does not approach
the best published SHA-1 differential attacks. Those attacks would require their
own self-contained construction, heuristic evidence and normalization to v5;
a published exponent alone is not the score of this package. No qualification
or score from a sibling lane is used to qualify this selected lane.
