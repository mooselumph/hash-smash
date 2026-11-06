# Seven-lane word-RAM circuit with stratified collision detection

Target blake3-r2-prefix-v1, exploratory lane, collision-frontier-v5.
Claim: time_log2=126.526661746, memory_log2_bytes=136, preprocessing_log2=126,
success_probability=0.39. These are analytical worst-case abstract RAM
bounds. No heuristic or full-scale empirical execution is asserted.

Dependencies: This package directly reuses published submission
f62e08a7-e7c2-43a2-81b9-4521f077a9f7: its seven-instance circuit layout,
stratified sampler, finite probability proof, sentinel detector, initialization,
and resource analysis. All are restated below. The present change omits eight unused output XORs, fourteen additions of
literal zero, four constant additions, and sixty-four unnecessary reduction
masks. The first three specializations were submitted in this session as
a69dc059-962c-459d-b721-25e9c22116b2; this revision builds on that package.
The principal additional change is a deterministic whole-circuit carry bound,
proved below, allowing four-bit guard fields to retain intermediate carries.
The inherited predecessor explicitly attributes its own sources. No independent
invention of that sampler, detector, or packing method is claimed here.

## 1. Exact complete hash

Each message has36 bytes: m=LE32(u)||LE4(v), with u a fresh ideal uniform
256-bit word and v=(-floor(i/7)) mod K for record index i, K=2^32.
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

Set B=2^128, K=2^32, c=994279962594/1000000000000, t=ceil(cB/(7K)), m=7t, and n=mK. Here m is a
stratum size, not a message. Compute it once by bounded fixed-size binary
long division; compute t by adding 7*1000000000000-1 to
994279962594*(B/K), then dividing by 7*1000000000000, and m=7t by
shifts/adds. All constants fit one word and this bounded division is charged
in setup. We have cB<=n<cB+7K<B. Use a p-word table P and an ell-word table L, with
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
separate zero-fill. Initialize record pointer r=a and group count g=t.
For i=0,...,n-1: use literal suffix v=(-floor(i/7)) mod K.
Seven consecutive records use seven independent uniform prefix words, hashed
by the packed circuit in Section 4. For each record set the current message
to LE32(u)||LE4(v), and compute its complete hash h. Use d=h&(p-1) to
load old=P[d]. Store (h,u,old) into the current record before setting
P[d]=r. Advance r by96. After each complete cycle of K seven-sample bodies decrement g once,
compare g with zero and branch back if nonzero. Thus the literal sequence
is seven copies of each value in 0,K-1,K-2,...,1; the cycle repeats t times. Since n=7tK=mK, every suffix
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
by96, then v=(0-floor(i/7))&(K-1). The subtraction is modulo2^256;
masking its low32 bits equals the required (-floor(i/7)) modK because K divides2^256. These are one-time terminal operations, not performed
per record. Operands have fewer than137 bits; a bit-at-a-time long divider
uses fewer than256 iterations of fewer than32 primitive instructions per
division, well within the2^18 terminal reserve for both record and suffix divisions and
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
 N(N-1)/(2Q)>((1-delta)c)^2/2-3/(2B)>494296322007063/1000000000000000=0.494296322007063.
The last inequality is an exact finite rational comparison. So the
auxiliary sample has an output collision with probability>1-exp(-0.494296322007063).

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
 Pr[success]>1-exp(-0.494296322007063)-2^-100-2^-33>0.39.
Auxiliary coins are a proof device and do not form algorithmic work.

For a finite rational margin, let E18=sum_(j=0..18)(494296322007063/1000000000000000)^j/j!.
Exact rational arithmetic gives E18*(61/100-2^-33-2^-100)>1.
Since exp(494296322007063/1000000000000000)>E18, its reciprocal is less than61/100-2^-33-2^-100.
This verifies the strict success bound without floating point, asymptotic
limits, empirical extrapolation, or any heuristic about the fixed target.

## 4. Seven-lane circuit over primitive RAM instructions

This algorithm evaluates seven complete hashes simultaneously with an explicit
circuit of ordinary 256-bit word operations. It does not invoke a compression
primitive during generation. Each terminal verification hash still invokes one
complete selected compression at price 1. Generation instead charges every
instruction of the following circuit at 1/430, without an additional compression
call. This distinction is essential: no seven compression calls are being
priced at one call, and no uncounted native SIMD instruction is assumed.
The only circuit instructions are the word primitives listed by v5. This uses
the stated 256-bit word width, rather than assuming each operation acts on only
one 32-bit BLAKE3 lane. If generation were implemented as seven calls to the
target primitive, those calls would cost seven; that is a different program.

For seven values x_q in [0,2^32), define

    pack(x) = sum(q=0..6) x_q * 2^(36q),
    M = sum(q=0..6) (2^32-1) * 2^(36q).

There are four zero guard bits after each lane. The highest meaningful bit is
247, so all packed values fit in one 256-bit word. Seven such values represent
seven separate instances, not seven words of a single state. There are sixteen
packed state registers and sixteen packed message-operand registers. They are a
fixed finite scalar bank, with the same register-RAM convention as the source.
Arithmetic instructions write named scalar destinations. Indexed record and table
accesses still require their explicitly counted address instructions and loads.

Each state word is now represented by seven 36-bit fields. Its low 32 bits
in each field are the target state value; the upper four bits may retain
carry history. Message fields are still clean 32-bit values. The full field
bounds proved below ensure additions never carry to the next field. Thus an
unmasked X+Y, or X+Y+Z, implements the required low-32-bit additions in all
seven instances. Costs are one and two instructions respectively. No AND
is required after an addition. XOR acts fieldwise and may preserve dirty
guard bits; the following rotation discards those guard bits exactly.

For r in {16,12,8,7}, let

    A_r = sum(q=0..6) (2^(32-r)-1) * 2^(36q),
    B_r = sum(q=0..6) ((2^r-1)<< (32-r)) * 2^(36q).

The packed rotation is the five-instruction expression

    R_r(X) = ((X>>r)&A_r) | ((X<<(32-r))&B_r).

Here both masks are required and counted. The right mask retains exactly the
low 32-r bits of each rotated lane. Contamination from the next lane starts at
bit 36-r relative to that lane, which is above the retained interval ending at
31-r. The left mask retains exactly the high r bits of each lane. Contamination
from the preceding full 36-bit field ends at relative bit 31-r, below the retained interval
starting at 32-r. These interval arguments apply to all seven lanes, including
the endpoints where absent neighboring lanes contribute zero. Dropped bits above
255 cannot affect any retained position. The field's own guard bits, after the right shift, begin at bit 32-r
and are excluded by A_r, whose retained interval ends at 31-r. After the
left shift they lie above bit 31 and are excluded by B_r. Hence R_r
independently rotates the low 32 bits of each field right by r and restores
all four guard bits to zero, even on dirty inputs. No probability premise
or small-word extrapolation is involved in these bit identities.

The packed G implements exactly the equations of Section 1:

| Update | Ordinary instructions |
| --- | ---: |
| a=a+b+x | 2 |
| d=R_16(d XOR a) | 6 |
| c=c+d | 1 |
| b=R_12(b XOR c) | 6 |
| a=a+b+y | 2 |
| d=R_8(d XOR a) | 6 |
| c=c+d | 1 |
| b=R_7(b XOR c) | 6 |

Total 30 instructions per G, sixteen G calls for two complete rounds: 480.
This saves 64 reduction masks relative to the predecessor's masked circuit.
Here is a deterministic bound for every intermediate field. The G call pattern
always uses state words 0..3 in role a, 4..7 in role b, 8..11 in role c,
and 12..15 in role d. Each state word participates in four G calls over
two rounds. Words in roles b and d are clean after each update because each
update ends with R_r. Their initial fields are also clean. Each a field starts
below 2^32 and receives eight clean b additions. The number of nonzero
message-word additions received by each a word is at most (6,4,4,4):

| a word | Round 0 operands | Round 1 operands | Nonzero count |
| --- | --- | --- | ---: |
| 0 | w0,w1,w8,w9 | w2,w6,w1,w11 | 6 |
| 1 | w2,w3,w10,w11 | w3,w10,w12,w5 | 4 |
| 2 | w4,w5,w12,w13 | w7,w0,w9,w14 | 4 |
| 3 | w6,w7,w14,w15 | w4,w13,w15,w8 | 4 |

Words w9..w15 are zero. Even treating every listed nonzero operand as
arbitrarily close to 2^32, each a field is strictly below 15*2^32.
Each c field starts below 2^32 and receives eight clean d additions, so
it is strictly below 9*2^32. All these bounds are below 2^36; additions
are monotone within each field, so they also bound every partial sum.
The first-column constant folding below only decreases the full integer
field value by a nonnegative multiple of 2^32. No inter-field carry occurs.
XOR with a clean b or d field never sets a bit at or above bit 36. Every
rotation is therefore applied within the proven 36-bit field bounds. The
highest possible occupied bit is 36*6+35=251, below 256. No top-word overflow
occurs either. This is a whole-circuit finite bound, not a probabilistic
assumption about carries or an extrapolation from small-word experiments.
Finally, dirty guard bits of the eight output XORs are removed by the existing
AND-mask32 instructions in digest extraction; all 256 digest bits are exact.
The message permutation is fixed wiring between named immutable operands, with
no runtime array permutation or operand-index calculation. Each packed message
register contains the exact seven original 32-bit operands. The eight IV words,
length 36, counter zero and flags 11 are packed constants. The first four column
G calls use those initial values directly at their first reads, then write their
ordinary destinations. Every subsequent read is dominated by the appropriate
write, exactly as for the inherited scalar initial-state specialization.
All initial-state operations remain present in the circuit table. The unmasked sixteen-G circuit costs 480 instructions before constant specialization.
For this message family w[9] through w[15] are zero. Each message word occurs
once per round among the sixteen x/y operands, also after permutation. Thus
exactly fourteen of the 32 triple-add updates have literal operand zero.
Replace a+b+0 by a+b, saving one addition at each occurrence.
The unmasked field bound above still applies.
In the first four column G calls, a and b initially are public constants.
Precompute their lane-wise sum modulo 2^32 as a packed public constant C_j.
Replace a+b+x by C_j+x. This saves four more additions; it is valid
whether or not a+b overflows within a lane, since low-32-bit equality is preserved and all subsequent rotations or
final extraction discard the guard bits. The precomputed constant is the
lane-wise sum modulo 2^32; it only reduces the field-size upper bound. These four x operands are w[0],w[2],w[4],w[6], all outside
the zero-word set, so no saving is counted twice. C_j construction and
storage fit the existing fixed initialization allowance. No dynamic state
update is omitted merely because its initial value is known.
After two rounds compute the eight packed XORs v[j] XOR v[j+8], j=0..7.
Only these are used by the first 32 root bytes. The unused output half
v[j+8] XOR IV[j] is never read and need not be evaluated. This saves eight
instructions relative to evaluating all sixteen output words. It does not
alter any returned digest bit, input flag, or finalization rule.
The specialized circuit therefore costs 480-14-4+8=470 instructions for
seven complete 256-bit hashes. All sixteen G calls and all their state
updates remain, with the exact equivalent constant simplifications above.

A generation body draws seven independent uniform words u_0,...,u_6 into seven
fixed immutable scalar registers, costing 7 random instructions. All seven use
the same literal suffix for that body. Construct the packed first eight message
operands as follows. For the q=0 source, take its low lane by AND, and its other
seven lanes by a right shift and AND each: 15 instructions. For each q=1,...,6,
extract its eight 32-bit lanes in 15 instructions, shift each left by 36q in eight
instructions, and OR each into its corresponding packed operand in eight more.
Total operand packing is 15+6*(15+8+8)=201 instructions, or 208 with randomness.
The packed suffix operand is a fixed literal sum(v<<36q), specialized into the
body, and the seven other packed message operands are constant zero. No suffix
register update, runtime multiplication, randomness expansion or extra copy is
needed. These literals are public program text whose construction is charged.

After the circuit, let O_j be its first eight packed feed-forward outputs.
For q=0 extract each lane by AND mask32 (8 instructions). For q>0 shift each
O_j right by 36q and AND mask32 (16). In either case use the j=0 extraction as
the digest destination h; for j=1,...,7 shift its extracted value left by 32j
and OR into h (14). This costs 22 instructions for q=0 and 30 for each other q,
202 in total. These are the seven complete 256-bit serialized digest words.
The packing of bytes is exactly little endian and agrees with Section 1.

Process those seven digests consecutively, retaining the seven u registers
throughout. For each digest use the inherited eleven-instruction store/insert
sequence: store h at r; add r+32 and store its u (3); AND d=h&mask127,
shift d<<5, add Pbase, load old, add r+64, store old there, store r in P[d]
(7); advance r by 96 (1). Every record field is written before P exposes it.
Thus a seven-sample body costs 208+470+202+77=957 ordinary instructions.
No complete-compression primitive was invoked in these instructions. One fixed
body for each of K=U=2^32 suffix literals is laid out in cyclic suffix order.
After all U bodies, decrement group count g once, compare to zero and branch
back: three instructions per group. Here g starts at t=m/7; each full group
produces 7K samples, so exactly n=mK samples are generated. Ordinary generation
work is (957+3/U)n/7. There is no per-sample dispatch or hidden inner loop.

The remainder of the source's detector and initialization is retained. To avoid
relying on the source externally, its full instruction accounting is restated.
P and L are explicitly initialized to the sentinel S. A receives complete first
writes and needs no zero-fill. Initialize P and the first p L entries jointly
using two stores and two pointer advances per entry, then compare/branch once
per U entries. Clear the remaining ell-p L entries using one store and one
pointer advance, again with two control instructions per U entries. Both lengths
are divisible by U. Their total cost is 2(p+ell)+2ell/U=(5+4/U)B. The sentinel
digest at S is initialized to zero once and never overwritten.

Traverse all p buckets in increasing order. A bucket guard loads its head,
compares to S and branches if empty (3); its epilogue advances the P pointer (1).
Bodies for U buckets are laid out consecutively with separate direct control
labels. After U buckets compare to Pend and branch (2). Total bucket overhead
is 4p+2p/U=(2+1/U)B, including the final failed branch. For every visited record:
load h from r; add s=r+64; shift e=h>>127; shift t=e<<5; load q=L[e]; load the
digest at q; compare it to h and branch on equality; store r in L[e]; load the
next pointer from s into r; compare r to S and branch back when unequal. These
are exactly 12 ordinary instructions. Fixed branch destinations and scalar
registers require no saved return address or descriptor. Every P bucket and every
record is visited at most once; the upper bound is independent of bucket balance.

On a digest match, compare q to S and branch to genuine-terminal recovery if
unequal. If q=S, resume the ordinary L[e] store. This false sentinel match can
occur at most once globally: it requires h=0 and e=0, and L[0] then becomes a
real record pointer and is never reset. The at most three extra instructions
fit the terminal reserve. Genuine matching terminates immediately, possibly
failing on repeated messages as already covered in the probability bound.
Recover both indices by exact binary division of r-a by 96; recover each suffix
by a further exact binary division of that index by 7, then negation and mask32.
These bounded divisions use fewer than 256 iterations of fewer than 32 word
instructions each. Four dividers, loads, wrapper work, complete output and
comparison fit in 2^18 ordinary instructions. Two complete target compression
calls for terminal checking are separately charged at price 1 each. This terminal
reserve includes the no-collision exit, sentinel handling, and halting. No restart
or external dataset is used.

Each seven-instance generation body has at most 957 primitive templates,
including all state operations and record instructions; allowing 2000 per body
is conservative. A bucket copy fits 32 templates; initializer loops use 6U+4.
Fixed setup, bounded dividers and two terminal wrappers fit fewer than 20000
additional templates. Total program size is below 2038U+20007<2^44 templates.
At four 256-bit words per template this is below 2^51 bytes. Scalar banks,
packed public masks, ordinary constants, fixed buffers, counters, scratch and
output fit 2^23 bytes. Their sum fits the 2^52-byte fixed reserve. Public packed
constants can be constructed by at most seven shifts and ORs per value; their
finite construction fits the fixed setup allowance. Code construction emits the
finite literal bodies and patches direct labels; fewer than 16 instructions per
reserved word, including loop and operand construction, fit in 2^54 operations.
An extra 2*2^16 operations covers all bounded setup and phase transitions.
No collision advice or precomputed target-dependent table is embedded.

## 5. Charged resources and finite scalar enclosure

Set U=K=2^32 and F=2^54+2*2^16+2^18. Every execution has at most two
complete target-compression calls and the following ordinary word work:

    H<=2,
    W<=(957+3/U)n/7 + 12n + (7+5/U)B + F
      =((1041+3/U)/7)n + (7+5/U)B + F.

All generation hash computation is included in those ordinary instructions.
The pricing is T=H+W/430. Since cB<=n<cB+7K, c=994279962594/1000000000000,

    T < A*B + ((1041+3/U)/7)*(7K)/430 + 2+F/430,
    A = (((1041+3/U)/7)*c+7+5/U)/430
      = 2327969858385049416035283/6463925780480000000000000.

The rounding term is less than 2^35, and 2+F/430<2^46. The exact rational
comparison

    (360147987067/1000000000000 - A)*B > 2^35+2^46

therefore proves T<0.360147987067*2^128. This is a deterministic total-work
bound including failed draws, initialization, recovery, verification and all
seven circuits. It is not parallel wall time or a conditional expectation.

Peak bytes are at most 96n+32(p+ell)+2^52=96n+80B+2^52<2^136. The change
n<cB+7K still gives n<B. All seven prefixes, vector state and registers fit
inside the fixed reserve; no second record array is required. Table initialization
and code setup cost ((5+4/U)B+2^54)/430<2^126 and are included above. There is
zero nonuniform advice; field value 0 denotes the permitted one-byte cap.
These are abstract word-RAM memory bounds, not physical allocation requirements
for the review VM.

## 6. Exact numerical checks and evidence scope

Let L=2*sum(j=0..23)(1/3)^(2j+1)/(2j+1), so the positive atanh series
proves ln(2)>L. Put z=(526661746/1000000000)*L. Exact rational arithmetic
gives

    sum(j=0..23) z^j/j! > 4*(360147987067/1000000000000).

Thus 2^0.526661746>1.440591948268, and the finite resource bound gives
T<2^126.526661746. Together with Section 3's finite success certificate,
these are finite analytic inequalities, not floating-point scoring evidence.
The seven-lane correctness follows from explicit disjoint bit intervals and
bounded carries; it is not a heuristic or an empirical extrapolation.

No participant experiment is declared or executed; the certificate manifest
is empty. The package does not provide an observed collision, full-scale run,
or measured cost. It specifies a complete finite RAM construction and its
conservative deterministic instruction count. The target and required
baseline_improved identifier remain unchanged. The proposal relies on charging
an explicitly implemented word circuit as its constituent word primitives,
as distinct from charging a call to the target-compression primitive. This
model interpretation is made explicit for cost review rather than hidden.
AI qualification, emitted score, improvement, owner review and promotion are
separate outcomes; ready means complete for review.
