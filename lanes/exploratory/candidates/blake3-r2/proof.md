# Suffix-stratified birthday search with a readable null sentinel

Target blake3-r2-prefix-v1, exploratory lane, collision-frontier-v5.
Claim: time_log2=128.299003, memory_log2_bytes=136, preprocessing_log2=126,
success_probability=0.39. These are analytical worst-case abstract RAM
bounds. No heuristic or full-scale empirical execution is asserted.

Dependencies: Directly inherits the complete algorithm, target definition,
countdown-derived suffixes, probability coupling and primitive schedule from
Yukon submission fe8ff672-af0f-4b10-8815-c1b5cd960fde. The organizer baseline
1ae3c621-1c2d-4e57-a1f7-91252c92a967 also supplies the exact target,
fixed-function birthday lemma and v5 accounting framework used here.
This revision reduces c from 1243/1250 to 994281/1000000 and supplies fresh
finite probability and scalar certificates; the algorithmic schedule is unchanged.
No independent invention of the inherited construction is claimed.

## 1. Exact complete hash

Each message has36 bytes: m=LE32(u)||LE4(v), with u a fresh ideal uniform
256-bit word and v the negative deterministic generation index modulo K=2^32.
The block domain of all such messages has size2^288, but this algorithm
stratifies its samples by v; it does not claim its actual messages are iid
on that whole domain. Section3 supplies a coupling proof specifically for
these stratified samples. Each v occurs exactly m times in the fixed batch,
and all n random u words are mutually independent. No PRNG or advice is used.

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

## 2. Concrete stratified algorithm and record invariants

Set B=2^128, K=2^32, c=994281/1000000, m=ceil(cB/K), and n=mK. Here m is a
stratum size, not a message. Compute it once by bounded fixed-size binary
long division; ceil is implementable by adding999999 to994281*(B/K) and then
dividing by1000000. This is below the fixed setup reserve. We have
cB<=n<cB+K<B. Use two B-word tables P,L and one array A of n records.
Record i has three256-bit words (h,u,next), with stride96 bytes.
Reserve first2^24 bytes for code/constants/scratch; initialize the word at
address zero to digest zero and never overwrite it; A starts at a=2^24,
P at a+96n, and L at a+96n+32B. Record fields are r,r+32,r+64.
Table j is at base+(j<<5); all addresses are below2^136. Zero is a null
pointer, and every record address is nonzero. No address multiplication
is needed in loops: record and table pointers advance by fixed strides.

Explicitly clear P,L jointly. A receives complete first writes with no
separate zero-fill. Initialize record pointer r=a and count=n.
For i=0,...,n-1: set v=count&(K-1), draw u uniformly from256-bit words; set the current message
to LE32(u)||LE4(v), and compute its complete hash h. Use d=h&(B-1) to
load old=P[d]. Store (h,u,old) into the current record before setting
P[d]=r. Advance r by96, decrement count and
continue until n records exist. Thus v=(n-i) modK=(-i) modK without an index register.
The countdown is read before its decrement. Since n=mK, every suffix
still occurs exactly m times; reversing the cyclic order permutes the strata.
Exactly m independent prefixes are sampled for each suffix. All repeats
are retained and charged. The suffix need not be stored in a record.

Traverse buckets d=0,...,B-1 in order, following P[d]'s acyclic next links.
For each record r load h,next, extract e=h>>128 and load q=L[e].
Unconditionally load the digest at address q, including the initialized
sentinel word at address zero. Compare it with h. On equality, test q.
If q=0 this is a false sentinel match: resume with L[e]=r and follow next.
Otherwise stop traversal on this first genuine full digest equality. Recover
both suffixes from their addresses as described below, load their u words,
and halt with failure if the reconstructed messages are equal. Otherwise
recompute both complete hashes and verify full256-bit equality and input
inequality, return the pair, and halt. If no match occurs, set L[e]=r and
follow next. When every bucket completes without a match, halt with failure.
There is no restart and at most one terminal pair and two recompressions.

Insertion links only to earlier records, so lists are acyclic, disjoint,
and contain all records exactly once. Every field is initialized before
exposure and before its first read. P,L are explicitly zeroed. The stream
of visited records is nondecreasing in low digest digit. For each high
digit e, L[e] is its last visited record, and that high-digit subsequence
is nondecreasing in low digit. Therefore all equal full digests are
contiguous in the subsequence. If all actual sampled messages are distinct,
any output collision is discovered and the first full digest match succeeds.
If inputs repeat, early failure is allowed. The probability proof subtracts
the entire repeated-input event. No bucket balance or target uniformity
assumption is made.

For any valid r=a+96i, recover i exactly by binary long division of(r-a)
by96, then v=(0-i)&(K-1). The subtraction is modulo2^256;
masking its low32 bits equals the required (-i) modK because K divides2^256. These are one-time terminal operations, not performed
per record. Operands have fewer than137 bits; a bit-at-a-time long divider
uses fewer than256 iterations of fewer than32 primitive instructions per
pointer, well within the2^18 terminal reserve even for both pointers and
verification wrappers. The division is exact by the record layout; no
suffix ambiguity or random seed expansion exists. All word operations are
modulo2^256 with no overflow in these address arithmetic ranges.
The two u loads plus recovered suffixes reconstruct exactly the original
36-byte messages. Verification uses the fixed root target of Section1.

## 3. Finite success proof for stratified inputs

The actual coins are n independent uniform256-bit prefix words. To prove
a lower bound, organize them as independent per-suffix streams U[v,j],
0<=v<K,0<=j<m. This is exactly their joint distribution under the cyclic
generation order. Extend each stream with infinitely many independent
uniform words solely for the following mathematical coupling; no such
extension or auxiliary sampling is performed or charged by the algorithm.

Let delta=2^-30 and N=floor((1-delta)n). Draw N auxiliary independent
uniform suffixes V_t in{0,...,K-1}, independently of every U stream. On
the t-th suffix occurrence of a particular v use the next unused U[v,j]
as prefix. The resulting N messages are independent uniform points in
D={0,1}^288: all selected stream slots are distinct independent uniform
prefix words, independent of the auxiliary suffix sequence. These are
auxiliary iid messages for analysis; the actual stratified messages are
not asserted to be iid. If every suffix occurs at most m times among V_t,
all auxiliary messages belong to the actual stratified batch.

For a fixed deterministic target H and an iid uniform domain sample, the
no-output-collision probability is at most exp(-N(N-1)/(2Q)), Q=2^256.
Here is the distribution-free proof. Put p_y=|H^-1(y)|/D. Outputs are iid
with probabilities p_y. The probability of all distinct outputs is N!e_N(p).
A maximizer of e_N exists on the compact probability simplex. Among
maximizers choose one minimizing sum of squares. Averaging unequal a,b
cannot decrease e_N, since for other coordinates r,
 e_N=ab e_(N-2)(r)+(a+b)e_(N-1)(r)+e_N(r)
with nonnegative coefficients, but strictly decreases the sum of squares.
Thus uniform p maximizes e_N. The probability is bounded by
 product_(j=0..N-1)(1-j/Q)<=exp(-N(N-1)/(2Q)).
No random-function or internal-round independence premise is involved.

Because n>=cB, N>(1-delta)cB-1. Hence
 N(N-1)/(2Q)>((1-delta)c)^2/2-3/(2B)>494297/1000000=0.494297.
The last inequality is an exact finite rational comparison. So the
auxiliary sample has an output collision with probability>1-exp(-0.494297).

We now bound auxiliary occupancy overflow. Each suffix count C_v is
binomial with mean mu=N/K. The different counts need not be independent.
We have mu<=(1-delta)m and mu>2^95. For t=delta, Markov's inequality and
1+x<=exp(x) give
 Pr[C_v>=m] <= exp(mu*(exp(t)-1)-tm).
For0<=t<=1/2, exp(t)<=1+t+(2/3)t^2: the tail after1+t is at most
 t^2*(1/2+t/(6*(1-t)))<= (2/3)t^2,
using1/k!<=1/6 for k>=3 and the geometric series. Since
m>=mu/(1-delta)>=mu(1+delta), the exponent is at most
 -(mu*delta^2)/3 < -2^35/3 < -2^33.
Union over K suffixes bounds overflow by
 K*exp(-2^33)<2^(32-2^33)<2^-100.
Here e>2, immediate from its first three positive series terms, justifies
the middle inequality. The bound for>=m is conservative: only>m is an
actual failure of containment. The proof includes every occupancy pattern.

For actual repeated inputs, messages with different suffixes are distinct.
Within each stratum there are m independent256-bit prefixes. The union
bound over all within-stratum pairs gives
 Pr[actual repeated input]<=K*m(m-1)/(2*2^256)
                           <n^2/(K*2^257)<2^-33,
because n<B. This is a bound for the whole actual batch, not merely the
smaller auxiliary sample. It covers the detector's early failure rule.

Whenever the auxiliary output collision occurs, occupancy containment
holds, and actual inputs are all distinct, the actual detector succeeds.
Taking probabilities on the joint coupling space and then marginalizing
out auxiliary coins therefore proves the actual algorithm's success:
 Pr[success]>1-exp(-0.494297)-2^-100-2^-33>0.39.
Auxiliary coins are a proof device and do not form algorithmic work.

For a finite rational margin, let S=sum_(j=0..12)(494297/1000000)^j/j!.
Exact rational arithmetic gives S*(61/100-2^-33-2^-100)>1.
Since exp(494297/1000000)>S, its reciprocal is less than61/100-2^-33-2^-100.
This verifies the strict success bound without floating point, asymptotic
limits, empirical extrapolation, or any heuristic about the fixed target.

## 4. Direct primitive schedule without runtime descriptors

One complete selected two-round compression costs1 and every other listed
256-bit RAM primitive costs1/430. This implementation has direct, unrolled
selected-compression instructions, with fixed input/state/output addresses.
It has no function call, runtime descriptor, dynamic dispatch, interpreter,
or register save convention. Its source equations are in Section1. The
compression's state/schedule temporaries are disjoint from input slots,
retained u,v, streaming pointers and the public constant register bank.
Constant immediates and addresses belong to the finite public program.
Each listed load/store/arithmetic/comparison/branch/random operation is
charged, and instruction fetch is implicit in a RAM primitive. Arithmetic
writes its destination directly. A move between existing scalar registers
is charged where needed. No participant program is executed as evidence.

The source used conservative spare instructions in its per-loop caps.
Here every primitive below has a concrete destination; the new envelopes
sum these explicitly enumerated operations rather than adding unused spares.
Additionally the four descriptor stores in the inherited wrapper are removed:
all inputs they described are already fixed in the inlined code, public IV
bank, and the sixteen state slots reset below. No instruction reads a
runtime counter/length/flags/IV-address descriptor. Counter0, length36 and
flags11 are directly stored into state slots12..15. The input CV=IV is a
fixed public operand in both initialization and feed-forward. All sixteen
state resets and the complete selected compression remain charged.

Initialize public scalar registers once: eight IV words, zero, length36,
flags11, masks32 and128, n,B, array/table bases and fixed buffer addresses.
Also write w[9..15]=0 once. This is within fixed initialization below.
Compression reads w without modifying it; mutable schedule copies and
message permutation are inside its complete selected-compression unit.
Thus w[9..15] remain initialized zero for every sample. Generation writes
w[0..8] afresh, without uninitialized reads or free zero allocation.

The sample wrapper consists of the following disjoint instruction groups:

* Input construction and countdown suffix,25: draw u (1); lane0 AND (1);
  six shift/AND pairs for lanes1..6 (12); lane7 shift (1); store eight
  lanes and lane8=v at fixed addresses (9); compute v=count&maskK before writing lane8 (1). Total25. The suffix stays
  live through hashing; the existing sample-count decrement supplies the
  next iteration without a separate suffix update. The original u remains in a disjoint retained register.
* Reset state,16: sixteen stores to fixed state addresses, each sourcing
  the appropriate already-live IV/zero/length/flag scalar. These are the
  entire state initializer in Section1. No dynamic descriptor is created.
* Complete selected compression,1 target unit, charged separately from W.
  Internal message-schedule management and feed-forward are part of this
  full unit, not omitted or discounted. Its code does not modify u,v or
  the scalar bank/pointers/counters. There is no call/return wrapper.
* Pack full digest,22: load output lane0 into h (1); for each lane1..7,
  load into temporary, shift by32j, OR into h (21). Each lane is32 bits.
* Store message/digest record,3: store h at r; add r+32, store u there.
  Keep r live. The suffix is recovered from the record address at terminal
  handling, so no per-record suffix store or its field address is needed.
* Advance generation,4: add96 to r, subtract1 from sample count,
  compare count with0, conditional branch to the next sample. Initial
  r/count setup is charged once in fixed work. The last iteration's
  failed branch is charged as well.

These groups total25+16+22+3+4=70 ordinary operations per sample, besides
one complete selected compression. Insert the following7 operations before
advancing r: AND d=h&mask128; shift t=d<<5; add t=Pbase+t; load old from t;
add s=r+64; store old to s; store r to t. This writes all three record fields
before exposing r. Retained digest/message scalars need no copying. Total
ordinary generation work is77n. All temporary destinations are distinct
from values still needed later. Instructions can freely reuse a temporary
after its last use; its next assignment directly writes the destination.

Joint P,L initialization uses exactly6 instructions per bucket: store zero
at current P pointer; store zero at current L pointer; add32 to P pointer;
add32 to L pointer; compare P pointer with Pend; conditional branch back
while unequal. Pend=Pbase+32B is computed once in fixed setup and retained
in a disjoint public scalar. Both tables have exactly B entries, so this
visits each entry once and charges the final failed branch. The advancing
P pointer itself is the loop variable; no decrementing bucket counter is
maintained. Total6B. Pointer/count setup is covered by fixed work.

Traversal uses a guarded, bottom-tested loop and at most13 instructions per
visited record on its ordinary path. Per bucket, load r=P[d], compare r
with zero and branch to the bucket epilogue if empty. This initial guard
is charged per bucket, including nonempty buckets. At the record-body label:
load h from r (1); add s=r+64 (1); shift e=h>>128 (1); shift t=e<<5 and
add t=Lbase+t (2); load q from t (1); load its digest from q, compare to h,
and branch to match handling on equality (3); store r to t (1); load r
from s (1); compare r with zero and branch to the record-body label when
nonzero (2). Total 13. The link load writes r directly after its old value
has been stored to L. There is no saved-next register or pointer move.
The two bottom-test operations include the last record's failed branch.
There is no unconditional back edge. Scalar s stays live through digest
comparison and the sentinel handler, which do not overwrite it.

Match handling first compares q with zero and branches. A nonzero q means
a genuine digest match, and r still denotes the current record: terminal
recovery is unchanged. A zero q means a false sentinel match, possible only
for h=0, e=0. Resume at the ordinary store L[0]=r and then load r from s.
This false match occurs at most once globally, because L[0] is thereafter
nonzero forever. The two tests and jump to the store cost at most three
extra operations. Both sentinel and genuine-terminal extra tests fit in
the existing 2^18 terminal reserve. Address zero is initialized once to
zero, within fixed initialization, and is never overwritten.

Per bucket the head load (1), initial zero comparison/branch (2), advance
P pointer by32 (1), and compare with Pend/conditional branch (2) total6.
Initialize the traversal pointer to Pbase once in fixed setup. The same
Pend is retained from clearing and is not modified by generation. At the
last bucket, the advanced pointer equals Pend and the final branch falls
through. Empty buckets incur exactly this bound. Nonempty buckets fall
through from their final failed record test to the same epilogue. Since
all pointer arithmetic is below2^136 and stride32 divides the table size,
there is no wraparound or skipped bucket. Each record and bucket is
processed at most once, hence traversal<=13n+6B. The removed counter has
no other use. No bucket balance assumption is needed.

Fixed public code/constants/workspace use at most2^24 bytes. Fewer than
2^16 templates of at most four256-bit words fit in2^23 bytes; another
2^23 covers all buffers, scalar registers, output and selected-compression
state. Lane conversions are unrolled; record and bucket loops remain loops.
Initialize fixed storage within2^24 ordinary operations, plus2*2^16 for
all loop setup, pointer/mask/n construction, phase transitions and exits.
Charge2^18 for the one terminal phase: load both u words, recover both suffixes by the bounded divider, distinctness
checks, reconstruction, two verification wrappers, output and halting. The
verification wrappers use the same direct code and are far below this cap.
Charge their at most two complete compressions separately. There is no
precomputed collision, advice, external data or uncharged allocator.

## 5. Total resource bounds

Set F=2^24+2*2^16+2^18=17170432. Every execution satisfies
 H<=n+2,
 W<=77n+13n+12B+F=90n+12B+F,
 T=H+W/430<=(520n+12B)/430+2+F/430.
Since cB<=n<cB+K and c=994281/1000000,
 T<((520c+12)/430)B+(520/430)K+2+F/430
  = (13225653/10750000)B+(520/430)K+2+F/430
  <1.2302934B<2^128.299003.
The rational coefficient is exactly (520*(994281/1000000)+12)/430.
The extra rounding term is below2^33, and2+F/430<40000. The rational slack
(6151467/5000000-13225653/10750000)B exceeds2^33+40000.

Peak storage is96n+64B+2^24<160B+2^24<2^136 bytes, including record links,
all retained randomness (prefixes), tables, code/constants, buffers and
terminal output/division scratch. Preprocessing is(6B+2^24)/430<2^126,
already included in W. Actual nonuniform advice is zero, represented by
schema field nonuniform_advice_log2_bytes=0 (the allowed one-byte upper
bound). Astronomical abstract RAM is not a memory demand on the scoring VM.
The bound is total charged work across all processors, for failures and
successes alike; there is no expected-time-only or favorable-bucket claim.

## 6. Exact finite checks and evidence scope

The inequality ln2>693147/1000000 follows from the first seven positive
terms of2*sum_(j>=0)(1/3)^(2j+1)/(2j+1). With
z=(299003/1000000)*(693147/1000000), rational arithmetic gives
sum_(j=0..8)z^j/j!>6151467/5000000=1.2302934. Positivity of the remaining
terms implies2^0.299003>exp(z)>1.2302934, verifying the scalar cap.
All other numeric success/margin comparisons in Section3 are rational.

The evidence is the explicit target, stratified algorithm, linked detector
and recovery invariants, occupancy coupling, universal iid collision lemma
and primitive schedule. No experiment manifest or executable is declared;
the certificate manifest is empty. No actual collision pair, full-scale
run, observed probability, model confidence, or claimed empirical evidence
is supplied. No simulation is needed for these finite analytic inequalities.
The nominal reference128 and baseline_improved identifier
blake3-r2-nominal-v2 remain reference metadata, not an established attack.
This bound still exceeds that nominal exponent and is not asserted optimal.
Ready means complete for review; mechanical validity, AI qualification,
score, owner acceptance and promotion are distinct states.
