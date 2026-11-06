# Suffix-stratified birthday search with a readable null sentinel

Target blake3-r2-prefix-v1, exploratory lane, collision-frontier-v5.
Claim: time_log2=128.2715485, memory_log2_bytes=136, preprocessing_log2=126,
success_probability=0.39. These are analytical worst-case abstract RAM
bounds. No heuristic or full-scale empirical execution is asserted.

Dependencies: Directly builds on 1f8932c4-eb03-4991-b5fc-b36c2828bb3a,
retaining its exact target, probability argument, detector and primitive schedule.
The organizer baseline 1ae3c621-1c2d-4e57-a1f7-91252c92a967 was directly read
for the fixed-function lemma and accounting framework. Earlier ancestors were
not separately consulted. The literal full suffix cycle, zero-based L table, disjoint sentinel and
charged code are retained. This revision decreases the sample coefficient
using a tighter finite probability calculation, with smaller coupling loss.
No round-function distributional assumption is introduced.

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

Set B=2^128, K=2^32, c=994279963/1000000000, m=ceil(cB/K), and n=mK. Here m is a
stratum size, not a message. Compute it once by bounded fixed-size binary
long division; ceil is implementable by adding999999999 to994279963*(B/K) and then
dividing by1000000000. This is below the fixed setup reserve. We have
cB<=n<cB+K<B. Use a p-word table P and an ell-word table L, with
p=2^127=B/2 and ell=2^129=2B. These digit cardinalities multiply to2^256. Use one array A of n records.
Record i has three256-bit words (h,u,next), with stride96 bytes.
Place L first, at byte addresses0 through32ell-1. Set the null pointer
S=32ell=2^134, outside L. Reserve2^52 bytes starting at S for the sentinel,
code/constants/scratch. Initialize the word at S to digest zero and never
write it again. Put A at a=S+2^52 and P at a+96n. The sentinel occupies
its own32 bytes; code starts at S+32 and fits within the fixed reserve.
All actual record addresses exceed S. Record fields are r,r+32,r+64.
P[j] is at Pbase+(j<<5); L[j] is at j<<5, with no base addition.
All addresses are below2^136. S is a fixed public live scalar, not a record
pointer. Address zero is valid RAM holding L[0]; it is never a null pointer.
Record/table streaming pointers advance by fixed strides.

Explicitly initialize all P,L entries to S by the two-phase procedure in Section4. A receives complete first writes with no
separate zero-fill. Initialize record pointer r=a and group count g=m.
For i=0,...,n-1: use literal suffix v=(-i) mod K, draw u uniformly from256-bit words; set the current message
to LE32(u)||LE4(v), and compute its complete hash h. Use d=h&(p-1) to
load old=P[d]. Store (h,u,old) into the current record before setting
P[d]=r. Advance r by96. After each complete K-copy cycle decrement g once,
compare g with zero and branch back if nonzero. Thus the literal sequence
is 0,K-1,K-2,...,1 and repeats exactly m times. Since n=mK, every suffix
still occurs exactly m times; reversing the cyclic order permutes the strata.
Exactly m independent prefixes are sampled for each suffix. All repeats
are retained and charged. The suffix need not be stored in a record.

Traverse buckets d=0,...,p-1 in order, following P[d]'s acyclic next links.
For each record r load h,next, extract e=h>>127 and load q=L[e].
Unconditionally load the digest at address q, including the initialized
sentinel word at address S. Compare it with h. On equality, test q.
If q=S this is a false sentinel match: resume with L[e]=r and follow next.
Otherwise stop traversal on this first genuine full digest equality. Recover
both suffixes from their addresses as described below, load their u words,
and halt with failure if the reconstructed messages are equal. Otherwise
recompute both complete hashes and verify full256-bit equality and input
inequality, return the pair, and halt. If no match occurs, set L[e]=r and
follow next. When every bucket completes without a match, halt with failure.
There is no restart and at most one terminal pair and two recompressions.

Insertion links only to earlier records, so lists are acyclic, disjoint,
and contain all records exactly once. Every field is initialized before
exposure and before its first read. P,L are explicitly initialized to S. The stream
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

Let delta=2^-40 and N=floor((1-delta)n). Draw N auxiliary independent
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
 N(N-1)/(2Q)>((1-delta)c)^2/2-3/(2B)>4942963221/10000000000=0.4942963221.
The last inequality is an exact finite rational comparison. So the
auxiliary sample has an output collision with probability>1-exp(-0.4942963221).

We now bound auxiliary occupancy overflow. Each suffix count C_v is
binomial with mean mu=N/K. The different counts need not be independent.
We have mu<=(1-delta)m and mu>2^95. For t=delta, Markov's inequality and
1+x<=exp(x) give
 Pr[C_v>=m] <= exp(mu*(exp(t)-1)-tm).
For0<=t<=1/2, exp(t)<=1+t+(2/3)t^2: the tail after1+t is at most
 t^2*(1/2+t/(6*(1-t)))<= (2/3)t^2,
using1/k!<=1/6 for k>=3 and the geometric series. Since
m>=mu/(1-delta)>=mu(1+delta), the exponent is at most
 -(mu*delta^2)/3 < -2^15/3 < -2^13.
Union over K suffixes bounds overflow by
 K*exp(-2^13)<2^(32-2^13)<2^-100.
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
 Pr[success]>1-exp(-0.4942963221)-2^-100-2^-33>0.39.
Auxiliary coins are a proof device and do not form algorithmic work.

For a finite rational margin, let E12=sum_(j=0..12)(4942963221/10000000000)^j/j!.
Exact rational arithmetic gives E12*(61/100-2^-33-2^-100)>1.
Since exp(4942963221/10000000000)>E12, its reciprocal is less than61/100-2^-33-2^-100.
This verifies the strict success bound without floating point, asymptotic
limits, empirical extrapolation, or any heuristic about the fixed target.

## 4. Direct primitive schedule without runtime descriptors

One complete selected two-round compression costs1 and every other listed
256-bit RAM primitive costs1/430. This implementation has direct, unrolled
selected-compression instructions, with fixed input/state/output addresses.
It has no function call, runtime descriptor, dynamic dispatch, interpreter,
or register save convention. Its source equations are in Section1. The
compression's state/schedule temporaries are disjoint from input slots,
retained u, streaming pointers and the public constant register bank.
Constant immediates and addresses belong to the finite public program.
Each listed load/store/arithmetic/comparison/branch/random operation is
charged, and instruction fetch is implicit in a RAM primitive. Arithmetic
writes its destination directly. A move between existing scalar registers
is charged where needed. No participant program is executed as evidence.

Every primitive below has a concrete destination. As in the immediate source,
inputs use fixed addresses and live public IV constants, without a runtime
counter/length/flags/IV-address descriptor. All sixteen state resets and the
complete selected compression remain charged. The literal suffix operands and cycle-end group control are retained.
The additional saving here is removal of the L-base addition in traversal.

Initialize public scalar registers once: eight IV words, zero, S, length36,
flags11, masks32 and127, n,m,B, array/table bases and fixed buffer addresses.
Also write w[9..15]=0 once. This is within fixed initialization below.
Compression reads w without modifying it; mutable schedule copies and
message permutation are inside its complete selected-compression unit.
Thus w[9..15] remain initialized zero for every sample. Generation writes
w[0..8] afresh, without uninitialized reads or free zero allocation.

The sample wrapper consists of the following disjoint instruction groups:

* Input construction and literal suffix,24: draw u (1); lane0 AND (1);
  six shift/AND pairs for lanes1..6 (12); lane7 shift (1); store eight
  lanes and lane8=v at fixed addresses (9). Total24. Each literal body has
  its own public immediate suffix operand. It needs no suffix register,
  mask or runtime suffix update. The original u remains in a disjoint retained register.
* Reset state,16: sixteen stores to fixed state addresses, each sourcing
  the appropriate already-live IV/zero/length/flag scalar. These are the
  entire state initializer in Section1. No dynamic descriptor is created.
* Complete selected compression,1 target unit, charged separately from W.
  Internal message-schedule management and feed-forward are part of this
  full unit, not omitted or discounted. Its code does not modify u or
  the scalar bank/pointers/counters. There is no call/return wrapper.
* Pack full digest,22: load output lane0 into h (1); for each lane1..7,
  load into temporary, shift by32j, OR into h (21). Each lane is32 bits.
* Store message/digest record,3: store h at r; add r+32, store u there.
  Keep r live. The suffix is recovered from the record address at terminal
  handling, so no per-record suffix store or its field address is needed.
* Advance generation,1 per sample: add96 to r. Initial r/group-count
  setup is charged once in fixed work. No per-sample countdown is maintained.

The sample body totals24+16+22+3+1=66 ordinary operations, besides one complete
selected compression. Insert the following7 operations before advancing r:
AND d=h&mask127; shift t=d<<5; add t=Pbase+t; load old from t;
add s=r+64; store old to s; store r to t. This writes all three record fields
before exposing r. Retained digest/message scalars need no copying. Thus the
body has73 ordinary operations per sample. Execute U=K=2^32 literal copies of this
body (including the complete selected compression instructions in each copy),
then subtract1 from g, compare g with zero and conditionally branch to the group start.
There is no inner counter, branch, call, return or dispatch. Since n=mK and
K=2^32, n is divisible byU; g reaches zero exactly at the end of the
last group. The final failed branch is charged. Per group W=U*73+3,
so ordinary generation work is(73+3/U)n.
Every complete compression remains charged separately at price1, giving n
units. Unrolling changes only the program text and control placement, not
input construction, sequential state reset, pointer updates or insertion.
Each literal body uses the same scalar destinations, live retained constants,
fixed message/state slots, and pointers; the preceding body completes all
updates before the next body begins. No extra retained random words are needed.

P,L initialization has two clear loops, both unrolled U times. First
initialize P and the first p entries of L jointly: U literal copies of
(store S at P pointer; store S at L pointer; advance each pointer by32), then
compare P pointer with Pend and branch back while unequal. This costs
4p+2p/U. Next clear the remaining ell-p entries of L with U literal
copies of(store S at L pointer; advance L pointer by32), then compare L pointer
with Lend and branch back while unequal. This costs2(ell-p)+2(ell-p)/U.
Pend=Pbase+32p and Lend=32ell are constructed once in fixed work.
Both lengths are divisible by U. The initial L pointer is address zero,
the initial P pointer is Pbase, and both receive explicit initialization; the final
failed branches are counted, and every table word is initialized before use.
The total is2(p+ell)+2ell/U=(5+4/U)B ordinary operations. Both final end
pointers remain live for subsequent phases. There is no inner branch,
loop counter beyond the advancing pointers, or remainder path.
The initializer uses6U+4 templates. All setup and phase transitions are
covered by the fixed transition allowance below.

Traversal uses a guarded, bottom-tested loop and at most12 instructions per
visited record on its ordinary path. Per bucket, load r=P[d], compare r
with S and branch to the bucket epilogue if empty. This initial guard
is charged per bucket, including nonempty buckets. At the record-body label:
load h from r (1); add s=r+64 (1); shift e=h>>127 (1); shift t=e<<5 (1); load q from t (1); load its digest from q, compare to h,
and branch to match handling on equality (3); store r to t (1); load r
from s (1); compare r with S and branch to the record-body label when
unequal to S (2). Total 12. The link load writes r directly after its old value
has been stored to L. There is no saved-next register or pointer move.
The two bottom-test operations include the last record's failed branch.
There is no unconditional back edge. Scalar s stays live through digest
comparison and the sentinel handler, which do not overwrite it.

Match handling first compares q with S and branches. A q unequal to S means
a genuine digest match, and r still denotes the current record: terminal
recovery is unchanged. A q equal to S means a false sentinel match, possible only
for h=0, e=0. Resume at the ordinary store L[0]=r and then load r from s.
This false match occurs at most once globally, because L[0] thereafter contains an actual record pointer, unequal to S. The two tests and jump to the store cost at most three
extra operations. Both sentinel and genuine-terminal extra tests fit in
the existing 2^18 terminal reserve. Address S is initialized once to
zero, within fixed initialization, and is never overwritten. L[0] is a separate word.

Bucket dispatch is unrolled in groups of U consecutive buckets. Each
literal copy contains its own head load, empty guard, record-body loop,
and bucket epilogue. The head load costs1, the initial empty comparison and
branch cost2, and advancing the P pointer by32 costs1:4 per bucket. The
record-body loop and all its bottom tests remain12 per visited record.
The empty guard jumps directly to that copy's epilogue. When a nonempty
bucket's final record reaches a sentinel link, its failed bottom branch falls
through to the same epilogue. The epilogue advances the pointer and falls
through to the next literal copy, without an unconditional branch. Only
after the Uth copy is the pointer compared with Pend and conditionally
branched to the group start. Since p=2^127 is divisible by U, there is no
remainder. Every bucket, including the last, is visited exactly once; the
last failed group branch is charged. Total bucket overhead is
4p+2p/U=(2+1/U)B.

The unchanged record-body branches to a per-copy out-of-line match handler.
It compares q with S and branches to the common genuine-terminal code
when q is unequal to S. On a false sentinel match it jumps back to that copy's
ordinary L-store label; s remains live. These handlers are placed after
the normal no-collision halt, so ordinary execution does not fall into them.
The false-sentinel path still adds at most3 instructions once globally,
inside the terminal reserve. Genuine-terminal handling occurs at most once.
There is no dispatch pointer, indirect return, call overhead or per-record
new branch. Only the destinations of existing branches are duplicated.

Each bucket copy uses fewer than32 templates including head, guard,12-step
record body, local epilogue and out-of-line handler. All U copies therefore
fit32U templates. A complete selected compression uses fewer than2000
primitive templates: sixteen G calls each have only finitely many additions,
XORs, 32-bit rotations/masks and state loads/stores, plus the permutation
and feed-forward. Even allowing64 templates per G leaves976 for other
compression work. The wrapper has at most75 templates per sample, so generation
uses at most2075U+3 templates. Initializers use6U+4; fixed setup, terminal
dividers and two verification wrappers fit fewer than20000 more templates.
Thus total program size is at most2113U+20007=9075265916455<2^44 templates.
Each template occupies at most four256-bit words, so code fits2^51 bytes.
Another2^23 bytes suffices for scalar registers, fixed buffers, public
constants, output and compression state. The combined fixed reserve is
2^52 bytes, strictly larger than their sum. All code is fixed public program
text determined by the displayed templates; it contains no collision advice.

This larger finite code is charged: reserve2^54 ordinary operations for
initializing all code/constants/workspace. There are2^47 words in the whole
2^52-byte reserve, so even16 operations per word is below2^54. Program
initialization is charged, including constructing the public literal copies.
A loop over copies emits their bounded instruction templates and patches each
fixed suffix immediate and control destination. Each suffix is the negated
copy index masked to32 bits. No target-dependent search or compilation oracle
is needed. Fewer than16 ordinary operations per emitted word suffice for
stores, index arithmetic, operand construction and loop control. This fits
the reserve above even charging all words of the larger fixed region. A separate2*2^16 operations covers
all fixed setup, pointer/mask/n construction, phase transitions and exits.
Traversal is at most12n+(2+1/U)B operations, for every bucket distribution.
Charge2^18 for the one terminal phase: load both u words, recover both suffixes by the bounded divider, distinctness
checks, reconstruction, two verification wrappers, output and halting. The
verification wrappers use the same direct code and are far below this cap.
Charge their at most two complete compressions separately. There is no
precomputed collision, advice, external data or uncharged allocator.

## 5. Total resource bounds

Set U=2^32 and F=2^54+2*2^16+2^18.
Every execution satisfies
 H<=n+2,
 W<=(73+3/U)n+12n+(7+5/U)B+F
   =(85+3/U)n+(7+5/U)B+F,
 T=H+W/430<=((515+3/U)n+(7+5/U)B)/430+2+F/430.
Since cB<=n<cB+K and c=994279963/1000000000,
 T<(((515+3/U)c+7+5/U)/430)B+((515+3/U)/430)K+2+F/430
  =(2229320732018824214609/1846835937280000000000)B
    +((515+3/U)/430)K+2+F/430
  <1.207102759B<2^128.2715485.
The rounding term is below2^33, and2+F/430<2^46.
The exact rational slack
 (1207102759/1000000000-2229320732018824214609/1846835937280000000000)B
 >2^33+2^46
covers both terms. Thus all finite code initialization is included.

Peak storage is96n+32(p+ell)+2^52
=96n+80B+2^52<176B+2^52<2^136 bytes, including all record links,
retained prefixes, tables, code/constants, buffers, division and output scratch.
Preprocessing is((5+4/U)B+2^54)/430<2^126,
already included in W. Actual nonuniform advice is zero; the schema field
nonuniform_advice_log2_bytes=0 is the permitted one-byte upper bound.
These astronomical abstract RAM tables are not allocated on the scoring VM.
The cost bounds charge total work including failures; they do not assume
favorable buckets, early success, or parallel wall-clock savings.

## 6. Exact finite checks and evidence scope

The inequality ln2>693147180559/1000000000000 follows from the first fourteen positive
terms of2*sum_(j>=0)(1/3)^(2j+1)/(2j+1). Put
 z=(2715485/10000000)*(693147180559/1000000000000).
Exact rational arithmetic gives
 sum_(j=0..11)z^j/j!>1207102759/1000000000=1.207102759.
The omitted terms are positive, so2^0.2715485>exp(z)>1.207102759.
All comparisons in the success proof are retained finite rational inequalities.
No numerical floating-point rounding is needed to establish the submitted cap.

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
