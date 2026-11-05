# Smaller finite birthday batch on a wider, equally priced message domain

This package targets blake3-r2-prefix-v1 in the exploratory lane. It claims
 time_log2=128.376, memory_log2_bytes=136, preprocessing_log2=126 and
success_probability=0.39 under collision-frontier-v5. These are analytical
worst-case bounds in the specified classical RAM, not a full-scale execution.
There are no heuristics, precomputed collisions, PRNG premises or advice.

Material source: submission 70878b11-df65-4c62-ba69-4ce43d96582d (candidate commit 13221f7, whose full
self-contained proof was read in its public submission note). Its linked
low-bucket/high-predecessor detector, first-match halt, RAM implementation,
constant-bank/input-buffer invariants, and fixed-function probability proof
are reused. The source itself credits earlier birthday/radix/linked detector
submissions; this revision claims no independent invention of those features.
The organizer baseline 1ae3c621-1c2d-4e57-a1f7-91252c92a967 was also read
for its distribution-free proof and split compression/word-operation pricing.
Both directly consulted sources are declared as dependencies. The change here
is a 36-byte domain and n=floor((1243/1250)*2^128), rather than 33 bytes and
n=2^128. Both domains occupy the same nine variable 32-bit input lanes.
The larger domain reduces the repeated-input penalty without more wrapper
operations, and therefore permits a smaller fixed batch at success >=0.39.

## 1. Exact complete hash

Each message is exactly 36 bytes, of bit length 288 < 2^64. Draw independent
uniform 256-bit words u and rho, and set v=rho AND (2^32-1). Define
m=LE32(u)||LE4(v), with all 32 bytes of u and the four bytes v retained.
This is uniform on a domain D of size 2^288. The 224 discarded random bits
are still drawn and their cost is charged. There is no IV freedom, advice,
fixed unknown prefix or PRNG hypothesis.

H is unkeyed BLAKE3-256 with exactly two prefix rounds in every compression.
These messages consist of one partial 36-byte block in one chunk, so each
complete hash uses exactly one root compression with flags 11, true block
length 36, and counter0. There is no extra padding block or parent compression.
For word loading, append exactly 28 zero bytes to m, making sixteen lanes.
The true length field remains 36; zero-fill is not a change of message length.
The first eight lanes encode u, lane8 equals v, and lanes9..15 are zero.

Decode the zero-filled block into sixteen little-endian 32-bit words w[0..15]. The eight-word IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

Initialize v[0..7]=IV, v[8..11]=IV[0..3], and
v[12..15]=(0,0,36,11). All arithmetic additions below are modulo 2^32;
ROR rotates right within a 32-bit lane. Define G(a,b,c,d,x,y) on v by

    v[a] = v[a]+v[b]+x; v[d] = ROR(v[d] XOR v[a],16)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],12)
    v[a] = v[a]+v[b]+y; v[d] = ROR(v[d] XOR v[a],8)
    v[c] = v[c]+v[d];   v[b] = ROR(v[b] XOR v[c],7).

For each round, use the current message schedule s, initially w, and call

    G(0,4,8,12,s[0],s[1]);    G(1,5,9,13,s[2],s[3])
    G(2,6,10,14,s[4],s[5]);   G(3,7,11,15,s[6],s[7])
    G(0,5,10,15,s[8],s[9]);   G(1,6,11,12,s[10],s[11])
    G(2,7,8,13,s[12],s[13]);  G(3,4,9,14,s[14],s[15]).

Between rounds replace s by s[P[i]], where
P=(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8).
Execute exactly the first 2 rounds, with no later rounds. The full
compression output is o[i]=v[i] XOR v[i+8], and
o[i+8]=v[i+8] XOR IV[i], for i=0..7. The digest H(m) is
LE4(o[0]) || ... || LE4(o[7]), the first 32 root-output bytes.
This retains the ordinary hash's flags and feed-forward, rather than searching
for a collision of a free-start or non-root compression function.

The target profile permits other message lengths and preserves the complete
standard 1024-byte chunk tree, parent nodes, counters and root output, with the
same prefix reduction in every compression. This algorithm only generates
36-byte messages, so the one-root-compression description covers every hash
it evaluates, including final verification. No uncharged parent, chunk or
second root-output compression is needed on this domain.

## 2. Fixed-batch linked detector

Let B=2^128, b=B, and n=floor(1243*B/1250). Compute this constant once in
setup: fixed binary long division of the 139-bit numerator by 1250 suffices
using shifts/subtractions/comparisons, far below the fixed allowance below.
All sampling loops run exactly n times unless the later detector halts early.
There is no restart or uncharged rejection sampling.

A record has four 256-bit words (h,u,v,next). Digest h is the little-endian
256-bit integer. Reserve the first 2^24 bytes for code/constants/scratch.
A begins at a=2^24 and has n records, 128 bytes each. P begins at a+128n
and L at a+128n+32B. Each table has B 256-bit words. All addresses fit below
2^136. Record fields are at r,r+32,r+64,r+96. Zero is a null pointer and
all actual record pointers are nonzero. Table digit j is at base+(j<<5).

Explicitly clear P and L in a joint streaming loop, B iterations. Do not
zero A: each record receives complete first writes before being exposed.
Generate n independent uniform 36-byte messages by two ideal random-word
draws, retaining u and the low 32 bits v of the second draw. Compute h=H(m).
Set d=h AND (B-1), load old=P[d], write all four fields (h,u,v,old), and
then set P[d]=r. Advance r by 128 and decrement the sample count.

After all generation, process d=0,...,B-1 in increasing order. Load r=P[d].
While r!=0 load h and next from r, set e=h>>128, and load q=L[e]. If q!=0,
load its full digest and compare with h. On the first full digest match,
stop traversal, load both messages, and halt with failure if they are equal.
Otherwise reconstruct and recompute both complete hashes, verify inequality
and full 256-bit digest equality, return the pair and halt. If no digest
match occurs, store r into L[e], assign r=next, and continue. If every bucket
finishes with no match, halt with failure. At most one terminal pair is
checked, and at most two terminal hash evaluations occur.

Insertion points next to a strictly earlier record or zero, proving by
induction acyclic disjoint lists containing every record once. Every field
is initialized before its first read. P and L are explicitly zeroed. The
immutable traversal visits each node at most once, regardless of distribution.
Its low digest digits are nondecreasing. L[e] always holds the most recently
visited record with high digit e, or zero if none. In the subsequence for
any fixed e, low digits are nondecreasing, so all copies of a full digest
are contiguous. Thus if there is an output collision and every sampled
input is distinct, the first digest match returns a valid collision. On
repeated-input events early failure is permitted; the entire event is
subtracted in the success proof. No balanced-bucket hypothesis is used.
Final verification uses the fixed target above and never accepts equal
messages, a free-start result or truncated output.

## 3. Finite fixed-function success bound

The domain has D=2^288 points and the codomain Q=2^256. The only coins are
2n independent ideal uniform 256-bit words. For the fixed deterministic H,
outputs of independent inputs are iid with probabilities p_y=|H^-1(y)|/D.
This statement assumes no randomly chosen function or internal independence.

The no-output-collision probability is n!e_n(p), where e_n is the elementary
symmetric polynomial. Uniform p maximizes it: choose a maximizer on the
compact probability simplex with minimal sum of squared coordinates. For
unequal a,b, keeping the other coordinates r fixed gives
 e_n=ab e_(n-2)(r)+(a+b)e_(n-1)(r)+e_n(r).
Averaging a,b does not decrease this expression, since all coefficients
are nonnegative, but strictly reduces the sum of squares, a contradiction.
Consequently, using 1-t<=exp(-t),

 Pr[no output collision] <= product_(j=0..n-1)(1-j/Q)
                         <= exp(-n(n-1)/(2Q)).

Let c=1243/1250. Since cB-1<n<=cB, n(n-1)/(2Q) exceeds
c^2/2 - 3/(2B), which is greater than 4944/10000. Indeed
c^2/2=0.49441568, while 3/(2B)<0.00001568. This is a finite inequality.
The union bound gives Pr[some repeated input]<B^2/(2D)=2^-33.
The correctness argument therefore yields

 Pr[success] > 1-exp(-0.4944)-2^-33 > 0.39.

For an entirely rational verification of the last strict inequality, set
x=309/625=0.4944 and S=sum_(k=0..8) x^k/k!. The positive exponential
series implies exp(x)>S. Exact rational arithmetic shows
S*(61/100-1/2^33)>1. Hence exp(-x)<61/100-2^-33, proving the assertion.
Section 6 states independently reproducible finite scalar checks as well.
This probability includes all failures and input repetitions. It is not
confidence in an AI review, a measured rate or an asymptotic extrapolation.

## 4. Explicit ordinary-operation schedule

One selected two-round compression costs 1; every other listed 256-bit RAM
primitive costs 1/430. Registers hold scalar operands, fixed constants and
streaming pointers; instruction fetch is implicit in each RAM instruction.
Loads, stores, comparisons, branches, shifts, logic, additions and random
words are charged separately. No interpreted instruction decoder is assumed.
Arithmetic writes its destination directly. Fixed addresses/immediates are
part of the public finite program, initialized within the reserve.

The implementation retains the source's conservatively capped schedules.
The read-only scalar bank holds IV words, zero, length36, flags11, masks32
and128, and fixed descriptor/buffer addresses. Initialize it once, along
with w[9..15]=0. Compression reads the input buffer without modifying it;
its mutable schedule/state is disjoint from that buffer and the constant
bank. Schedule copying/permutation and feed-forward remain inside the one
fully charged selected compression. Each call resets all sixteen state
slots and the descriptor. No partial-compression discount is taken.

Per generated message, draw u,rho (2), mask v=rho AND mask32 (1).
Lane0=u AND mask32 costs1, lanes1..6 shifted/masked cost12, lane7=u>>224
costs1, and storing eight lanes plus lane8=v costs9. Total26, capped27
with a spare copy. The only difference from the 33-byte wrapper is using
mask32 instead of mask8 and length36 instead of length33. Both are already
loaded public constants; operations and storage counts are identical.
Constant zero slots9..15 remain zero by the read-only-input invariant.

Reset sixteen state slots (16 stores), allow four descriptor stores, and
cap at24 to cover extra copies. Load output lane0 directly into h (1),
then load/shift/OR seven more lanes (21), total22. The eight 32-bit lanes
pack the exact little-endian 256-bit digest. Store h,u,v with two field
address additions (5), advance r, decrement count, compare and branch (4),
and allow seven extra copies/control operations, total16. Therefore the
wrapper is at most27+24+22+16=89 ordinary operations plus one compression.

Insertion computes d=h&mask128 (1), table address (shift/add,2), loads old
(1), forms r+96 and stores old (2), and stores r to P[d] (1). Seven actual
operations are capped at8 including a spare copy. All record fields are
stored before exposing the head. Generation is at most97n ordinary ops.

Joint clearing uses two zero stores, two pointer increments, one decrement,
one comparison and one branch:7 per bucket, capped8, hence8B.

For each visited record, r test/branch (2), h/next loads and r+96 address
(3), extract high digit (1), L address (2), q load (1), q test/branch (2),
optional digest load (1) and digest comparison/branch (2), L store (1),
assign r=next (1), branch back (1): at most17, capped18. Per bucket, head
load(1), terminal r test/branch(2), P-pointer increment(1), bucket count
decrement(1), comparison/branch(2):7, capped8. Even empty buckets are charged.
Total traversal<=18n+8B, independent of shape. Terminal message loads and
verification are performed at most once and charged to fixed work below.

Fixed public code/constants/workspace use at most2^24 bytes. Fewer than
2^16 templates of at most four 256-bit words fit in2^23 bytes; another
2^23 covers buffers/registers/output. Lane conversions are finite unrolled
instructions; record and bucket loops remain loops. Initialize fixed storage
within2^24 ordinary operations. Charge another2*2^16 operations for loop
setup, base/mask/n construction and exits, plus2^18 for terminal handling,
message comparison, reconstruction, output and verification wrappers. Charge
both terminal compressions separately even on paths that do not use them.
No precomputed collision, advice, external data or uncharged allocator exists.

## 5. Total resource bounds

For every execution, writing F=2^24+2*2^16+2^18=17170432,

 H<=n+2,
 W<=115n+16B+F,
 T=H+W/430 <=(545n+16B)/430+2+F/430
            <=((545*(1243/1250)+16)/430)*B+2+F/430
             <1.2977B <2^128.376.

The leading coefficient is 697435/537500, approximately1.2975534884;
its leading logarithm is128.3757940113. The additive term is below40000
and the slack between1.2977 and that rational timesB exceeds40000.
This is a worst-case charged budget for both failures and successes, not
expected work conditioned on favorable buckets. No sorting is used.

Peak memory is128n+64B+2^24 <=192B+2^24 <256B=2^136 bytes, including all
records, retained random inputs, pointers, tables, code/constants and scratch.
Preprocessing is(8B+2^24)/430 <2^126, included in total T. Actual nonuniform
advice is zero, represented by the schema's permitted one-byte bound
nonuniform_advice_log2_bytes=0. Data is not a scored resource; every sample,
discarded random bit and recompression is charged. Astronomical abstract RAM
is not a memory requirement for the machine reviewing this analytic proof.

## 6. Finite numeric checks and limitations

For the scalar, ln2>693147/1000000 follows from the first seven positive
terms of2*sum_(j>=0)(1/3)^(2j+1)/(2j+1). Set z=(376/1000)*(693147/1000000).
Exact rational evaluation gives sum_(k=0..8) z^k/k! >12977/10000=1.2977.
Positive remaining terms imply2^0.376>exp(z)>1.2977. The probability check
in Section3 uses the same finite exponential series technique. No floating
point result is required to justify either claimed bound.

Evidence consists of the concrete exact-target algorithm, initialization
and linked-order invariants, finite universal success proof and operation
schedule. Certificate manifest is empty; no participant executable or
experiment manifest is declared or run. No actual collision pair, full-scale
trial or statistical extrapolation is claimed. The bound is not an estimate
of the target's exact security and makes no claim of optimality. The nominal
reference128 is not an established attack; baseline_improved retains the
required identifier blake3-r2-nominal-v2. Scalar improvement is relative to
the published candidate, not the nominal exponent. Ready means complete
for review; AI qualification, scoring, owner review and promotion are separate.
