# Seven-lane word-RAM circuit with stratified collision detection

Target blake3-r2-prefix-v1, exploratory lane, collision-frontier-v5.
Claim: time_log2=126.07331688, memory_log2_bytes=136, preprocessing_log2=126,
success_probability=0.39. These are analytical worst-case abstract RAM
bounds. No heuristic or full-scale empirical execution is asserted.

Dependencies: This revision directly reuses submission
8c7960c2-a5af-43fc-ab32-2eb0219f2642, qualified remotely at126.29305012
and awaiting manual owner review. It supplies the stratified seven-lane circuit,
fused output wrapper, detector and resource accounting. This revision retains the improved finite occupancy argument and moves the
random prefix within a64-byte message so four full and two half round0 G calls are public;
its earlier sources remain attributed through it. No independent invention of
the inherited circuit or actual collision is claimed.

The finite occupancy refinement was first submitted in same-session candidate
019e56b6-2826-4989-9196-5ba8c37ef8c8, now qualified at126.29304566 and
awaiting manual review. Its proof and smaller sample coefficient are retained here.
The public circuit source remains8c7960c2-a5af-43fc-ab32-2eb0219f2642.
The intermediate56-byte layout and328-instruction recount were first submitted
in same-session candidate c9df41e1-d1e4-423c-a905-54502eb5359f, also pending
publication at preparation. This revision directly refines that layout.

## 1. Exact complete hash

Each message has64 bytes. Let u be the low192 bits of a fresh ideal
uniform256-bit word. Write u as six32-bit little-endian words u0..u5.
Define the complete sixteen-word message block by

    w0,w1,w2 = the three little-endian words of v,
    w3..w7 = 0,
    w8,w9,w10,w11 = u0,u1,u2,u3,
    w12=0, w13=u4, w14=0, w15=u5,
    v = (-floor(i/7)) mod K, K=2^83.

Serialize all sixteen words in little-endian order, including all zeros.
The suffix has thirteen zero high bits in w2. The six random words occupy
positions8,9,10,11,13,15; the public suffix occupies0..2; seven words are zero.
This mapping from(u,v) to complete messages is injective. No extra runtime
packing is used during generation: the packed operand wiring below implements
this layout, and the terminal wrapper reconstructs these bytes explicitly.
The block domain of all such messages has size2^275, but this algorithm
stratifies its samples by v; it does not claim its actual messages are iid
on that whole domain. Section3 supplies a coupling proof specifically for
these stratified samples. Each v occurs exactly m times in the fixed batch,
and all n masked random u values are mutually independent. No PRNG or advice is used.

H is unkeyed BLAKE3-256 with exactly two prefix rounds in every compression.
These messages consist of one full 64-byte block in one chunk, so each
complete hash uses exactly one root compression with flags 11, true block
length 64, and counter0. There is no extra padding block or parent compression.
The message already occupies all sixteen word slots; no zero-fill beyond it is needed.
The true length field remains 64; zero-fill is not a change of message length.
Words8,9,10,11,13,15 encode u in little-endian order. Words0..2 encode v.
All other words are zero; the three suffix operands are public body literals.

Decode the block into sixteen little-endian 32-bit words w[0..15]. The eight-word IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

Initialize v[0..7]=IV, v[8..11]=IV[0..3], and
v[12..15]=(0,0,64,11). All arithmetic additions below are modulo 2^32;
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
64-byte messages, so the one-root-compression description covers every hash
it evaluates, including final verification. No uncharged parent, chunk or
second root-output compression is needed on this domain.

## 2. Concrete stratified algorithm and record invariants

Set B=2^128, K=2^83, c=994283750000/1000000000000, t=ceil(cB/(7K)), m=7t, and n=mK. Here m is a
stratum size, not a message. Compute it once by bounded fixed-size binary
long division; compute t by adding 7*1000000000000-1 to
994283750000*(B/K), then dividing by 7*1000000000000, and m=7t by
shifts/adds. All constants fit one word and this bounded division is charged
in setup. We have cB<=n<cB+7K<B. Use a p-word table P and an ell-word table L, with
p=2^127=B/2 and ell=2^129=2B. These digit cardinalities multiply to2^256. Use one array A of n records.
Record i has three256-bit words (h,z,next), where z is the full random word and u=z AND (2^192-1), with stride96 bytes.
Place L first, at byte addresses0 through32ell-1. Set the null pointer
S=32ell=2^134, outside L. Reserve2^103 bytes starting at S for the sentinel,
code/constants/scratch. Initialize the word at S to digest zero and never
write it again. Put A at a=S+2^103 and P at a+96n. The sentinel occupies
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
to the64-byte encoding of(u,v) in Section1, and compute its complete hash h. Use d=h&(p-1) to
load old=P[d]. Store (h,z,old) into the current record before setting
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
both suffixes from their addresses as described below, load their z words and mask each to 192 bits to recover u,
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
masking its low83 bits equals the required (-floor(i/7)) modK because K divides2^256. These are one-time terminal operations, not performed
per record. Operands have fewer than137 bits; a bit-at-a-time long divider
uses fewer than256 iterations of fewer than32 primitive instructions per
division, well within the2^18 terminal reserve for both record and suffix divisions and
verification wrappers. The division is exact by the record layout; no
suffix ambiguity or random seed expansion exists. All word operations are
modulo2^256 with no overflow in these address arithmetic ranges.
The two z loads, two mask192 operations, and recovered suffixes reconstruct exactly the original
64-byte messages. Verification uses the fixed root target of Section1.

## 3. Finite success proof for stratified inputs

The algorithm draws n independent uniform 256-bit words z. The message prefix
is their low192 bits; the transpose below discards high bits without separate masks. Its effective prefix values are
independent uniform192-bit values. To prove
a lower bound, organize them as independent per-suffix streams U[v,j],
0<=v<K,0<=j<m. This is exactly their joint distribution under the cyclic
generation order. Extend each stream with infinitely many independent
uniform 192-bit values solely for the following mathematical coupling; no such
extension or auxiliary sampling is performed or charged by the algorithm.

Let delta=1/450000 and N=floor((1-delta)n). Draw N auxiliary independent
uniform suffixes V_t in{0,...,K-1}, independently of every U stream. On
the t-th suffix occurrence of a particular v use the next unused U[v,j]
as prefix. The resulting N messages are independent uniform points in
D={0,1}^275: all selected stream slots are distinct independent uniform192-bit
prefix values, independent of the auxiliary suffix sequence. These are
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
 N(N-1)/(2Q)>((1-delta)c)^2/2-3/(2B)>494297890870/1000000000000=0.494297890870.
The last inequality is an exact finite rational comparison. So the
auxiliary sample has an output collision with probability>1-exp(-0.494297890870).

We now bound auxiliary occupancy overflow. Each suffix count C_v is
binomial with mean mu=N/K. The counts need not be independent. We have
mu<=(1-delta)m and mu>((1-delta)cB-1)/K. With t=delta, Markov's
inequality and 1+x<=exp(x) give

    Pr[C_v>=m] <= exp(mu*(exp(delta)-1)-delta*m).

For 0<=t<1, the positive series and j!>=2 for j>=2 imply

    exp(t)<=1+t+t^2/(2*(1-t)).

Also m>=mu/(1-delta)>=mu*(1+delta). Substituting these two bounds
makes the exponent at most

    -mu*delta^2*(1-2*delta)/(2*(1-delta)) < -86.

The final comparison uses the displayed rational lower bound on mu and the
exact constants B,K,c,delta; all denominators are positive. Exact rational
arithmetic verifies it, with a magnitude greater than86.378. Since the first
six terms of the exponential series give e>163/60 and
(163/60)^86>2^123, union over K=2^83 suffixes gives

    Pr[some C_v>=m] < K*exp(-86) < 2^-40.

Only C_v>m is an actual containment failure, so bounding >=m is conservative.
This covers all occupancy patterns; no independence of the counts is used.

For actual repeated inputs, messages with different suffixes are distinct.
Within each stratum there are m independent192-bit prefixes. The union
bound over all within-stratum pairs gives
 Pr[actual repeated input]<=K*m(m-1)/(2*2^192)
                           <n^2/(K*2^193)<2^-20,
because n<B. This is a bound for the whole actual batch, not merely the
smaller auxiliary sample. It covers the detector's early failure rule.

Whenever the auxiliary output collision occurs, occupancy containment
holds, and actual inputs are all distinct, the actual detector succeeds.
Taking probabilities on the joint coupling space and then marginalizing
out auxiliary coins therefore proves the actual algorithm's success:
 Pr[success]>1-exp(-0.494297890870)-2^-40-2^-20>0.39.
Auxiliary coins are a proof device and do not form algorithmic work.

For a finite rational margin, let E18=sum_(j=0..18)(494297890870/1000000000000)^j/j!.
Exact rational arithmetic gives E18*(61/100-2^-20-2^-40)>1.
Since exp(494297890870/1000000000000)>E18, its reciprocal is less than61/100-2^-20-2^-40.
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
message-word additions received by each a word is at most (7,4,3,4):

| a word | Round 0 operands | Round 1 operands | Nonzero count |
| --- | --- | --- | ---: |
| 0 | w0,w1,w8,w9 | w2,w6,w1,w11 | 7 |
| 1 | w2,w3,w10,w11 | w3,w10,w12,w5 | 4 |
| 2 | w4,w5,w12,w13 | w7,w0,w9,w14 | 3 |
| 3 | w6,w7,w14,w15 | w4,w13,w15,w8 | 4 |

Words w3..w7,w12,w14 are zero. Even treating every listed nonzero operand as
arbitrarily close to 2^32, each a field is strictly below 16*2^32.
Each c field starts below 2^32 and receives eight clean d additions, so
it is strictly below 9*2^32. All actual field values are below 2^36; additions
are monotone within each field, so they also bound every partial sum.
The first-column constant folding below only decreases the full integer
field value by a nonnegative multiple of 2^32. No inter-field carry occurs.
XOR with a clean b or d field never sets a bit at or above bit 36. Every
rotation is therefore applied within the proven 36-bit field bounds. The
highest possible occupied bit is 36*6+35=251, below 256. No top-word overflow
occurs either. This is a whole-circuit finite bound, not a probabilistic
assumption about carries or an extrapolation from small-word experiments.
Finally, dirty guard bits of the eight output XORs are removed by the payload-selecting
AND masks in the compaction wrapper; all 256 digest bits are exact.
The message permutation is fixed wiring between named immutable operands, with
no runtime array permutation or operand-index calculation. All IV, flag,
length64, zero-counter and suffix values are packed public constants.
The following count replaces the predecessor's439-instruction specialized
circuit; it does not accumulate overlapping deductions from its old layout.

All four round0 column G calls use message words0..7, which are suffix
literals or zeros. Their initial states are public. Compute all sixteen
exact low32-bit state outputs once per suffix body and retain them as packed
public constants at their first dynamic reads. No random prefix has yet
entered the state. The following diagonal calls are disjoint in state slots.

The first two dynamic round0 diagonal calls use operand pairs(w8,w9) and
(w10,w11). Their initial a+b sums are public and folded into packed low32-bit
constants. Each costs29 ordinary instructions instead of30. All other
instructions in the generic G table remain for these two calls.

The last two round0 diagonal calls use pairs(w12,w13)=(0,u4) and
(w14,w15)=(0,u5). Their first halves have no random input. Precompute the
exact low32-bit a,b,c,d values after the first b=R_12(b XOR c) update.
The public a+b sum for their second update is also folded into one constant.
Each remaining dynamic half is explicitly

    a = public_sum + y;             # one addition
    d = R_8(public_d XOR a);        # one XOR plus five rotation instructions
    c = public_c + d;              # one addition
    b = R_7(public_b XOR c);        # one XOR plus five rotation instructions

It costs1+6+1+6=14 primitives. No public-state load, scalar copy or runtime
permutation is assumed; constants are literal operands at their first reads,
using the same finite scalar-bank convention as the predecessor. Constant
construction and storage are charged below. Folding exact public sums modulo
2^32 only reduces dirty-field magnitudes; the field/rotation proof still applies.

Round1 has all eight dynamic G calls. Its fixed message permutation uses every
message word exactly once, and exactly seven operands are zero: w3,w4,w5,w6,w7,
w12,w14. Each removes one addition from its a+b+x or a+b+y update; no other
saving is claimed. Round1 costs8*30-7=233 ordinary instructions. Eight
final v[j] XOR v[j+8] instructions produce all256 digest bits; the unused
second output half is not computed. The complete dynamic hash circuit costs

    2*29 + 2*14 + (8*30-7) + 8 = 327

ordinary primitives per seven complete hashes. This is112 fewer than the
published source's439. Compared with the same-session56-byte layout costing
328, the six random words are spread as two complete pairs and two y-only
pairs rather than three complete pairs and one wholly public diagonal call.
This saves exactly one instruction per seven hashes, with the same number of
nonzero message operands in round1. The true block length is64; flags, target
reduction and full output remain unchanged. All public columns and half-call
states are computed exactly by the target's G equations, with no collision
advice, omitted search or guessed equality. Every dynamic state connects to
round1 through exactly the specified target wiring.

A generation body draws seven independent uniform words z_0,...,z_6 into
seven scalar registers R[0..6], costing seven random instructions. Each row
initially has eight arbitrary32-bit fields. Fields0 through5 encode the
192-bit u value; they map to message words8,9,10,11,13,15 respectively. Fields6
and7 are independent unused randomness. No initial
mask192 instruction is performed. This changes neither the distribution of
u nor the complete hash input.
All seven use the same literal suffix for that body. The input/output wrappers
use the following finite word transpose instead of individual lane extraction.

For eight row words R[0..7], each containing eight contiguous 32-bit fields,
transpose the eight-by-eight array with one stage for each j in{1,2,4}. At each stage
pair a,b=a+j where the j bit of a is zero. Let D_j be the 256-bit mask whose
32-bit field f is all ones exactly when the j bit of f is zero. For each
of the four pairs execute

    t=((R[a]>>(32*j)) XOR R[b]) AND D_j;
    R[a]=R[a] XOR (t<<(32*j));
    R[b]=R[b] XOR t.

These are six primitives: shift, XOR, AND, shift, XOR, XOR. The pair exchanges
field f+j of row a with field f of row b whenever f has zero j bit, and leaves
all other fields unchanged. It swaps bit j of the row index with bit j of the
column index. These three swaps act on disjoint row/column index bits, so commute.
After all three stages, in any order, every row/column index bit is exchanged,
so output row f contains input field f from rows 0..7 in that order. There
are twelve pairs and exactly 72 word instructions. All masks and shifts are
public constants, and the fixed row/column wiring has no dynamic indexing.
This is a proof of the bit permutation for every input, without simulation
or a claim about native vector instructions.

Before the destructive input transpose, store every full sampled word z into
its future record field. If r is the group-start record pointer, for q=0..6
compute r+(96q+32) and store R[q] there: two instructions each, fourteen
in total. These stores replace, rather than duplicate, the same fourteen
prefix-store/address instructions in the later record insertion accounting.
The record is not exposed through P until its remaining fields are written.
No live copy of the prefixes is needed after these charged stores.

The new input wrapper uses transpose stage order j=1,2,4, rather than
4,2,1. The bit-index proof above applies in either order. The missing eighth
input row is mathematically zero. At the first j=1 stage, pair(6,7) uses
fresh destinations

    new_6 = R[6] AND D_1,
    new_7 = (R[6]>>32) AND D_1.

This is exactly the ordinary exchange with old row7=0: row6 keeps its even
fields and row7 receives its odd fields in even positions. It costs three
instructions, initializes both outputs before use, and requires no physical
initialization of old row7. The other three pairs cost six instructions each,
so the first stage costs21. The complete second j=2 stage costs24.
No write is omitted in either of these first two stages.

After these two stages, rows have exchanged their low two row/column index
bits. Let row r and field f be decomposed into high bit2 and low two bits.
The field in that row now comes from original input row
(r AND 4)+(f AND 3), and original input field (f AND 4)+(r AND 3).
Consequently every row B with r>=4 has fields3 and7 zero: their original
input row is7, which was zero. Thus for pairs A=row a, B=row a+4, a=0..3,

    A = lo_A + (hi_A<<128),  0<=lo_A,hi_A<2^128,
    B = lo_B + (hi_B<<128),  0<=lo_B,hi_B<2^96.

The last ordinary j=4 transpose stage would make

    out_a = lo_A + (lo_B<<128),
    out_b = hi_A + (hi_B<<128).

The first spreading stage j=4 then moves the high four field positions
16 bits upward, giving exactly

    spaced_a = lo_A + (lo_B<<144),
    spaced_b = hi_A + (hi_B<<144).

Construct these directly with primitive operations:

    spaced_a = (A AND (2^128-1)) OR (B<<144),
    spaced_b = (A>>128) OR ((B>>128)<<144).

The first line costs three instructions. The B high-half term vanishes under
the256-bit left shift, and its low half has only96 live bits, so no retained
bit overflows. The second costs four instructions; the B>>128 value has only
96 bits, so its shifted payload ends at bit239. In both lines, the low and
high terms are disjoint. All expressions use the old A,B as needed and write
fresh scalar destinations; fixed names replace them without extra copies.
These identities hold for every allowed random input and suffix.

Only output rows0..5 are message operands. For a=0,1 construct both results,
costing seven instructions per pair. For a=2,3 construct only spaced_a,
costing three each: spaced_b would be discarded rows6,7 and has no consumer.
Thus the fused final-transpose/first-spreading stage costs2*7+2*3=20.
There is no read of those discarded outputs in later wiring or masks.

The six retained rows now have payload field q at position32q+16*bit_2(q),
with q=0..6 and no q7 payload. Finish spreading with j=2 then j=1. At each
stage the fixed masks select the32-bit payload intervals whose bit_j(q)
is zero or one. Execute

    R=(R AND stay) OR ((R AND move)<<(4*j)).

This costs four primitives per row per stage,48 in total. The interval
positions at every stage are determined by

    pos(q)=32q+4*sum(k in completed spreading stages) k*bit_k(q).

Starting with stage4 complete, moving stages2 and1 in decreasing order
preserves disjoint intervals. The final position is36q, four guard bits
are zero, and the highest payload bit is247. All masks are public constants.
The new input transform costs21+24+20+48=113 ordinary primitives. Add seven
independent random-word draws for a120-instruction input wrapper, saving19
relative to the predecessor's139. The fourteen early prefix stores remain
part of the77-instruction record accounting and are not omitted or counted
twice. The six output operand rows contain exactly the low192 prefix bits
of each of the seven originally stored random words.
Wire the six spaced prefix rows0..5 to message operands w8,w9,w10,w11,w13,w15
respectively. This is a fixed renaming of immutable scalar operands, not a
runtime array access or copy. The three packed suffix operands w0,w1,w2
are fixed literals across all seven fields. The remaining operands w3..w7,
w12 and w14 are zero. The120-instruction input wrapper therefore supplies
the exact new complete-message block without extra generation operations.
Public literal/mask construction is charged to fixed initialization.

After the circuit's eight output XORs, compact each packed output row back
from offsets36q to32q, but fuse the final compaction stage with the first
transpose stage. First execute only the reverse-spacing stages j=1 and j=2.
For each stage use masks selecting exactly the current32-bit payload intervals:

    R=(R AND stay) OR ((R AND move)>>(4*j)).

Each stage costs four instructions per row, so these two stages on eight rows
cost64 instructions. The first masks discard every dirty guard bit; the next
stage also retains only payload. For q=0..6 the resulting field position is
36q-4*bit_0(q)-8*bit_1(q)=32q+16*bit_2(q). Therefore every row has exactly
this form, with all other bits zero:

    X = lo + (hi << 144),  0<=lo<2^128, 0<=hi<2^96.

The four low fields form lo; the three high fields form hi. The missing
q=7 field is zero. This is a support statement for all inputs, including
dirty circuit outputs before the first masks, not an empirical assertion.
The omitted j=4 compaction would map X to lo+(hi<<128).

In the usual first (j=4) transpose stage, pair rows a,b=a+4, for a=0..3.
After full compaction that exchange would produce

    new_a=lo_a + (lo_b<<128),
    new_b=hi_a + (hi_b<<128).

Construct those same two words directly from the partly compacted A,B:

    new_a = (A AND (2^128-1)) OR (B<<128),
    new_b = (A>>144) OR ((B>>16) AND ((2^96-1)<<128)).

The first line uses three primitives (AND, shift, OR). The shift is a256-bit
word shift: its overflow is discarded, so B's hi term vanishes and only
lo_b remains in the high half. The second line uses four primitives (two
shifts, AND, OR). A>>144 is exactly hi_a. The mask in the second term
selects exactly hi_b shifted from bit144 to128, discarding every bit of
lo_b. Each OR combines disjoint intervals. The seven instructions compute
the displayed standard-stage outputs exactly. Compute both into fresh named
scalar destinations before any overwrite; subsequent fixed wiring uses
these names. The constant-size scalar bank and temporaries fit the existing
reserve. There is no dynamic index, memory access, scalar copy, or extra
assignment needed for this fixed register wiring.

All four row pairs are disjoint, so the fused stage costs4*7=28 instructions.
It replaces eight j=4 compaction steps (8*4=32) and four j=4 transpose
exchanges (4*6=24), formerly56 instructions. It saves28 instructions,
without omitting any retained output bit. Complete the ordinary transpose
with j=2 and j=1, omitting only the final R[7]=R[7] XOR t in pair(6,7),
as in the predecessor. These remaining eight pairs cost48-1=47 instructions.
The omitted write has no consumer; all required temporaries and R[6] writes
remain. These two ordinary stages operate on exactly the words the original
first transpose stage produced, so the original bit-permutation proof applies.
The output wrapper costs64+28+47=139 instructions, instead of167. Its
rows q=0..6 are exactly the seven full digest words, in the little-endian
encoding of Section1. Row7 is discarded. Neither the hash definition nor
its success distribution changes.

Process those seven digests consecutively, using the prefixes already stored
in their final records. For each digest use the inherited record sequence
with its prefix store moved earlier: store h at r (1); AND d=h&mask127,
shift d<<5, add Pbase, load old, add r+64, store old there, store r in P[d]
(7); advance r by 96 (1). Every record field is written before P exposes it.
The per-record insertion now costs nine instructions; seven such insertions
and the fourteen early prefix-store instructions total 7*9+14=77. Thus a
seven-sample body costs 120+327+139+77=663 ordinary instructions.
No complete-compression primitive was invoked in these instructions. One fixed
body for each of K=U=2^83 suffix literals is laid out in cyclic suffix order.
After all U bodies, decrement group count g once, compare to zero and branch
back: three instructions per group. Here g starts at t=m/7; each full group
produces 7K samples, so exactly n=mK samples are generated. Ordinary generation
work is (663+3/U)n/7. There is no per-sample dispatch or hidden inner loop.

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
Load both stored z words and apply mask192 before comparing message prefixes. High64 bits are ignored in both message inequality and complete hash reconstruction. These two mask instructions fit the terminal reserve.
Recover both indices by exact binary division of r-a by 96; recover each suffix
by a further exact binary division of that index by 7, then negation and mask83.
These bounded divisions use fewer than 256 iterations of fewer than 32 word
instructions each. Four dividers, loads, wrapper work, complete output and
comparison fit in 2^18 ordinary instructions. Two complete target compression
calls for terminal checking are separately charged at price 1 each. This terminal
reserve includes the no-collision exit, sentinel handling, and halting. No restart
or external dataset is used.

Each seven-instance generation body has at most 663 primitive templates,
including all state operations and record instructions; allowing 2000 per body
is conservative. A bucket copy fits 32 templates; initializer loops use 6U+4.
Fixed setup, bounded dividers and two terminal wrappers fit fewer than 20000
additional templates. Total program size is below 2038U+20007<2^94 templates.
At four 256-bit words per template this is below 2^101 bytes. Scalar banks,
packed public masks, ordinary constants, fixed buffers, counters, scratch and
output fit 2^23 bytes. Their sum fits the 2^103-byte fixed reserve. Public packed
constants can be constructed by at most seven shifts and ORs per value; the four public G calls and two public half-calls together cost fewer than2580 additional operations per body; their
finite construction fits the fixed setup allowance. Code construction emits the
finite literal bodies and patches direct labels; fewer than 16 instructions per
reserved word, including loop and operand construction, fit in 2^105 operations.
An extra 2*2^16 operations covers all bounded setup and phase transitions.
No collision advice or precomputed target-dependent table is embedded.

## 5. Charged resources and finite scalar enclosure

Set U=K=2^83 and F=2^105+2*2^16+2^18. Every execution has at most two
complete target-compression calls and the following ordinary word work:

    H<=2,
    W<=(663+3/U)n/7 + 12n + (7+5/U)B + F
      =((747+3/U)/7)n + (7+5/U)B + F.

All generation hash computation is included in those ordinary instructions.
The pricing is T=H+W/430. Since cB<=n<cB+7K, c=994283750000/1000000000000,

    T < A*B + ((747+3/U)/7)*(7K)/430 + 2+F/430,
    A = (((747+3/U)/7)*c+7+5/U)/430.

The rounding term is less than 2^86, and 2+F/430<2^97. The exact rational
comparison

    (263033211/1000000000 - A)*B > 2^86+2^97

therefore proves T<0.263033211*2^128. This is a deterministic total-work
bound including failed draws, initialization, recovery, verification and all
seven circuits. It is not parallel wall time or a conditional expectation.

Peak bytes are at most 96n+32(p+ell)+2^103=96n+80B+2^103<2^136. The reduced sample count
n<cB+7K still gives n<B. All seven prefixes, vector state and registers fit
inside the fixed reserve; no second record array is required. Table initialization
and code setup cost ((5+4/U)B+2^105)/430<2^126 and are included above. There is
zero nonuniform advice; field value 0 denotes the permitted one-byte cap.
These are abstract word-RAM memory bounds, not physical allocation requirements
for the review VM.

## 6. Exact numerical checks and evidence scope

Let L=2*sum(j=0..23)(1/3)^(2j+1)/(2j+1), so the positive atanh series
proves ln(2)>L. Put z=(07331688/100000000)*L. Exact rational arithmetic
gives

    sum(j=0..23) z^j/j! > 4*(263033211/1000000000).

Thus 2^0.07331688>1.052132844, and the finite resource bound gives
T<2^126.07331688. Together with Section 3's finite success certificate,
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


