# Independent counter trials for an ordinary two-round BLAKE3 collision

This package targets blake3-r2-prefix-v1 in the exploratory lane under
collision-frontier-v5. It proposes time_log2=101, memory_log2_bytes=44,
preprocessing_log2=97, nonuniform_advice_log2_bytes=7 and success_probability=0.39.
The time bound and memory bound are analytical. No full 32-bit collision or
full-scale run is claimed. Success depends on H-rate; accounting for completed
historical advice construction depends on the explicitly disclosed H-history.
Neither is an unconditional theorem. There are no other distribution premises.

## 1. Sources, contribution and comparison

The constructor, pinned advice, length cancellation, last-chunk reduction and
model-rate evidence come from Jbenisek and the contributors of production
submission 40087647-1a84-4a2b-bb18-5b8edf0edefa, promoted source
55dfae1cfb429015a293db48c7c9f88f566641e2 in Layr-Labs/hash-smash:
https://github.com/Layr-Labs/hash-smash/tree/55dfae1cfb429015a293db48c7c9f88f566641e2/lanes/exploratory/candidates/blake3-r2
Production PR1009 was merged at bb9c6710c9f6f4033a5a8e6b2cb23800925b4b94;
the source proof, claim and experiment are byte-identical at that merged commit.
https://github.com/Layr-Labs/hash-smash/pull/1009
The promoted source is licensed under Apache 2.0 by the production Terms Section 5;
the license is included below. Retained original mathematical passages are
explicitly marked appendices. No independent origin, new half-collision or
priority over that work is asserted. Its source-reported historical measurements
remain untrusted reports, not measurements performed in this session.

The change is to discard the production algorithm's context enumeration,
filter tables, joint solver, packed lanes, credit meter and probabilistic work
budgets. This algorithm instead samples every trial independently, constructs
both last chunks directly and compares their complete 256-bit chaining values.
Its hard per-trial budget is charged on every failure. Independence follows
from fresh disjoint coins, so no context-clustering premise is required. Only
a deliberately weaker valid-collision rate and an extremely loose historical
construction-resource bound are retained as declared heuristics.

The directly used dev submission 892507d9-2ac3-4e6b-a7cc-602919d430c6 is a
comparator in this proof: its official generic bound is128.45, while the new
conditional bound is101. Its generic attack is not a subroutine here. The
external production source is a material dependency, separately and fully
identified above; the configured dev attribution endpoint returns submission
not found for production IDs, so the cross-deployment relation cannot be
represented as a normal dev graph edge. It is not omitted as an origin claim.
The structured declaration covers the available dev comparator, not a claim
that this independent-trial design derives from the generic detector.

## 2. Exact target and full-message reduction

H is unkeyed BLAKE3-256 with the first two rounds in every compression, standard
IV, message permutation, chunk tree, true block lengths, counters, flags,
feed-forward and first 32 root-output bytes. The IV is

    6a09e667 bb67ae85 3c6ef372 a54ff53a
    510e527f 9b05688c 1f83d9ab 5be0cd19.

A two-round compression initializes v[0..7]=cv, v[8..11]=IV[0..3],
v[12..15]=(counter low32,counter high32,block length,flags). Each G call uses
32-bit modular arithmetic and narrow rotations:

    a1=A+B+x; d1=ROR(D XOR a1,16); c1=C+d1; b1=ROR(B XOR c1,12)
    a2=a1+b1+y; d2=ROR(d1 XOR a2,8); c2=c1+d2; b2=ROR(b1 XOR c2,7).

Its outputs are(a2,b2,c2,d2). Round0 calls are
G(0,4,8,12,w0,w1), G(1,5,9,13,w2,w3), G(2,6,10,14,w4,w5),
G(3,7,11,15,w6,w7), G(0,5,10,15,w8,w9), G(1,6,11,12,w10,w11),
G(2,7,8,13,w12,w13), G(3,4,9,14,w14,w15). For round 1 replace w by
w[P[i]], P=(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8), and repeat those
state indices. Output words are v[i] XOR v[i+8] followed by v[i+8] XOR cv[i].
The first eight are the chaining value or, with ROOT, the digest words.

Given t in[1,2^32), let F be1024t zero bytes, and A,B be the constructor's
55/63-byte last chunks. Both full messages have t+1 chunks. Their shared
prefix F produces the same stack of subtree chaining values. Their last
chunks start with cv=IV and are compressed once with counter t, flags 3
(CHUNK_START|CHUNK_END), and their respective true lengths. They are not root
compressions. If these complete eight-word chaining values agree, all following
parent descriptors agree because their other children come from F. Every
parent uses cv=IV, length 64, counter 0, PARENT, and the final descriptor uses
ROOT in the standard way. Hence the complete 256-bit root digests agree.
At least one parent exists because t>=1. This does not hash an already
finalized root CV or change root counters. Lengths differ, so inputs are distinct.
Both lengths are below 2^42 bytes and their bit lengths below 2^45<2^64.

The diagnostic returns a separate root instance, counter 0/flags 11, whose
masked digest property is independently checked. Its masked success is not
asserted for the full counter messages: subsequent parents mix all words.

## 3. Pinned advice and concrete constructor

Use precisely the six old promoted constants in AppendixA, not the different
constants in the production repository's later amendment. Arithmetic below
and in the appended constructor is modulo2^32. Define

    K=IV[2]+IV[6], W4'=((K+W4) XOR8)-K, delta5=W4-W4'=-8,
    K2.a1=K+W4, K2.d1=ROR(55 XOR K2.a1,16),
    K2.c1=IV[2]+K2.d1, K2.b1=ROR(IV[6] XOR K2.c1,12).

AppendixA verifies the fixed call outputs and the unchanged four CV words.
For the promoted constants Y3=8127c181, Y3'=7edf3e7e,
Y11=7af77f38, Y11'=850000c3. Set

    class_mask=03cf8303, class_value=030c0303,
    cube_mask=0e09818b, cube_value=02008000.

For a 19-bit index k, put its bits in the zero positions of class_mask,
least significant first, OR class_value to obtain e, and set y=e-Y3.
This gives2^19 distinct members. For a uniform 32-bit r, set
c=(r AND NOT cube_mask) OR cube_value; this gives a uniform member of a
2^21-element cube. The masks have13 and 11 set bits respectively.

The class identity follows from(e XOR x)-e=x-2(e AND x): with
x=ROL(830303cf,16)=03cf8303 and Y3'-Y3=fdb77cfd,
(x-(Y3'-Y3))/2=030c0303. Thus e XOR(e+Y3'-Y3)=x for every member, and
E3's first-half d difference is830303cf. Likewise
ROL(18b0e098,12)=0e09818b and Y11'-Y11=0a08818b give
(0e09818b-0a08818b)/2=02008000. Thus c in the cube prescribes E1's
first-half b difference18b0e098. These are exact integer identities, not
assumptions of independence among internal words.

The seven outer words, y and c are fed into the 93 assignment lines of
AppendixB, in their printed order. The appendix gives all message words,
t and the last chunks, and a table of the G assignments each line solves.
Every right-hand side reads only a free coordinate, constant or earlier
assignment; no inversion search, SAT call or unbounded subroutine occurs
in a trial. Names S,X,Y are states after round 0 columns, all round 0 and
round 1 columns; K,D,C,E identify the calls printed in the source excerpt.
The G equations above and the appendix's complete table determine them.
References in the source excerpt to its original Sections1/2 mean the target
and G equations here; its LemmaQ is the class identity just proved; its
LemmaTR is the complete-message tree argument in Section 2 here. Thus no
external page must be fetched to assess the constructor.

## 4. Independent-trial attack and probability space

Initialize the advice, constants, finite code and workspace. Set N=2^93.
For each trial i=0,...,N-1:

1. Draw fresh independent uniform 256-bit RAM words U,V. The seven outer
   words are bits 0..223 of U in seven32-bit lanes. The index k is the
   low19 bits of U>>224. Obtain y as in Section 3. Set c from the low32
   bits of V using the cube mask. The13 unused bits of U and 235 unused
   bits of V are discarded, but both full random draws are charged.
2. Execute AppendixB CO, CT and CS to construct t,A,B. If t=0, count the
   failed trial and continue. It cannot be treated as a non-root last chunk.
3. Compute both selected two-round compressions on the last chunks at
   counter t, flags 3, lengths55/63. Compare all eight CV words, packed as
   one256-bit key. If they differ, continue. No filter, solver, early mask
   success or partial agreement is accepted.
4. On equality, construct both full messages F||A,F||B, re-evaluate both
   complete selected hashes with their standard trees/root flags, check all
   output bits and input inequality, return them and halt. Verification
   failure would halt with failure; it cannot occur under the exact target
   and constructor equations. If all N trials fail, halt with failure.

Every trial has fresh disjoint coins. The264 used bits are mutually independent
and uniform, hence the seven outer words, class member and cube member have
exactly the specified product law. Applying the fixed constructor and fixed
selected hash to disjoint fresh coins makes the success indicators independent
and identically distributed. Repeated coordinate tuples, if any, require no
resampling and do not invalidate independence of iid random variables. No
random-oracle or internal-round independence premise is being smuggled in.

H-rate asserts that a trial under this precise law has probability at least
p=2^-94 of t!=0 and full CV equality. It includes invalid-counter mass and
all outcomes, with no assumed success among excluded t=0 trials. Under H-rate,

    Pr[failure] <= (1-2^-94)^(2^93) <= exp(-1/2).

Since exp(1/2)>1+1/2+1/8+1/48=79/48, success is greater than 31/79,
which is greater than 39/100 because3100>3081. Thus the declared0.39 follows
with strict finite slack. H-history is an accounting premise, separate from
this probability calculation. Probability is over ideal algorithmic coins;
it is not confidence in the premise or the AI review.

## 5. Explicit operation and storage bounds

The model charges one selected compression1 and every other256-bit primitive
1/430. Per trial there are at most two selected compressions, including failed
trials. The simple RAM implementation uses fixed slots/registers for every
constructor name and unrolls the 93 assignments. At most128 such rows, including
construction of fixed call values if redundantly repeated, each expand into
at most64 primitive operations: at most four data loads, one result store,
fixed-slot addresses as code operands, additions/subtractions with masks,
XORs and narrow rotations as two shifts, OR and mask. No displayed row has
an expression remotely as large as64 instructions; this envelope even allows
extra operand loads, copies and spills. This part costs at most8192 primitives.

Decode the seven random lanes, masked cube and class index, scatter its19 bits
using a 32-iteration loop with fewer than 32 primitives each, pack and zero-fill
the two blocks, initialize both compression descriptors/states, pack both full
CVs and compare them, control the trial loop, and retain a terminal pair. A
further2^14 primitives exceeds these bounded loops and fixed-size conversions;
for example all 32 message lanes can each use fewer than 64 operations including
loads/stores/shifts, and both wrappers and all controls fit below another8192.
There is no dynamic dictionary, Python interpreter or library cost assumption
in this RAM program. The Python diagnostic implements the same formulas for
evidence; its elapsed time is not an attack cost. Allowing more than twice
8192+16384 gives the uniform per-trial ceiling W_trial<=2^16 ordinary
primitives, plus H_trial<=2 target compressions. Failed/invalid trials are
charged at this full ceiling as well.

Historical advice construction is not free. Under H-history its entire
completed cost is at most2^96 target-compression units and peak storage at
most2^43 bytes. Loading the advice, fixed constants, code and workspace costs
at most2^24 further ordinary primitives, which is already far below one unit
of the remaining2^96 allowance; conservatively all preprocessing is bounded
by 2^97 units. The source reports much smaller caps (AppendixD), but this
package does not equate wall-clock logs with operation counts or pretend to
have replayed an omitted historical generator. H-history is explicit.

On a terminal full-CV match, t<2^32. Each full hash has t+1 chunks, at most
16 block compressions per full prefix chunk and fewer than t+1 parent nodes.
Even allowing redundant root work, both full-hash verifications use fewer
than 2^38 selected compressions. Allocate two arrays for the complete messages,
explicitly fill their zero prefix words and tails, then hash with an explicit
stack of at most33 CVs and compare/output both messages. Each message is below
2^42 bytes, so both arrays occupy below 2^43 bytes. Fixed code, buffers, stack,
registers and output descriptors fit below 2^24 bytes. Allow2^16 ordinary wrapper
operations per compression plus a generous2^45 ordinary primitives for filling,
reading and writing message words. This costs less than 2^50 target-equivalent
units including all recompressions, construction and output. It is charged
once even on terminal verification failure. There is no external storage or
uncharged materialized prefix. All addresses fit below 2^45 in one RAM word.

Let N=2^93. For every possible execution, conditional only on the explicit
historical-resource premise,

    T <= (2+2^16/430)N + 2^97 + 2^50
      < 155N + 16N + N
      = 172N
      < 256N = 2^101.

The bound is on total computation, summed across processors; no parallel
latency saving is credited. No mean solver ledger or random work budget
enters it. The per-trial cap is deterministic; only success uses H-rate.
Memory peak is below 2^44 bytes in every phase: history uses at most2^43,
search code/workspace below 2^24, and output arrays plus fixed storage below
2^43+2^24<2^44. The73-byte source advice record is below 2^7 bytes; unused
filter outcomes retained in that record need no runtime search or tables.
Memory is a reviewed reported metric with no scalar or tie-break contribution.

## 6. Heuristic evidence and limitations

### H-rate: valid full-collision rate

This is a score-critical premise for exactly the promoted old constants,
seven independent uniform outer words, a uniform member of the full 2^19
class and an independent uniform member of the full 2^21 cube. It states
Pr[t!=0 and all 256 CV bits equal]>=2^-94. It is not proved and not directly
measured at 32 bits. The claimed algorithmic success is conditional on it.

AppendixC supplies the donor's model and six outcome counts. In that artificial
product-word model the listed full residual event has probability
1032*2^-101, about 2^-90.989. Our threshold is16/129 of that rate, roughly
12.4%, for any valid full collision; the production model/measurements do not
prove transfer to the constructor or to the t!=0 sub-event. No false equality
of those probability spaces is claimed. Source-reported 8-bit end-to-end data
contains 40,882 full toy collisions against 40,800.63 predicted over
3,235,715,578,385 trials, lower reported 97.7% ratio bound 0.99213. Source-reported
32-bit partial events agree with the model at accessible depths around2^-32,
with much larger samples and conditioning described in the source. These
reports are relevant but untrusted, not independently reproduced here; the
toy constants/width and partial predicates differ from the full target event.
The source explicitly reports no full 32-bit joint-event observation.

Our organizer-executed diagnostic independently checks256/256 root-instance
masked agreements on digest words0,2,5,7. It also reports, as untrusted participant
observations,256/256 counter half-agreements and prescribed beta differences,
256 nonzero counters, and zero full equalities. The source-inspected program
uses the same independent-coordinate law at test scale, but its deterministic
SHAKE seed expansion is reproducibility evidence, not ideal randomness. These
finite checks support constructor relevance, not the 2^-94 full-rate premise.
No confidence number is substituted for algorithmic success. If H-rate fails,
the deterministic time cap remains but0.39 success need not hold.

### H-history: generous historical construction resources

The fixed advice is materially inherited. This score-critical accounting
premise states that all completed work used to obtain this exact record,
including failed searches, model selection, recounts and advice/code creation,
used at most2^96 target-equivalent computation and at most2^43 bytes of
simultaneous storage. It does not assert that a new capped search always
returns the same record. AppendixD reproduces the source's records and
reported capped SEL construction, with 116 solver runs, per-run caps5*2^53
ordinary operations, per-model recount caps2^51 and selection2^50. Their
reported envelope is

    S_old=116*5*2^53 +116*(2^51+2^10)+2^50
         =5486510246044225536 <2^63 ordinary operations.

The source's own cap is below 2^54 target units. Even charging each of those
ordinary operations as a whole target unit leaves more than 33 bits of room
below our2^96 historical bound. Reported peak storage is below 2^29 bytes,
far below the disclosed2^43 premise. These are intentionally very loose bounds,
not fresh measurements. The raw logs record wall time and lack a primitive
operation counter; the omitted SAT generator and historical counter are not
replayed by this package. The premise is therefore disclosed instead of
presenting retrospective caps as mechanically proved historical costs.
If it fails severely enough, the total-time or memory claim may fail. This
uncertainty is separate from H-rate and from the exact constructor identities.

## 7. Local validation and interpretation

The complete independent sampler diagnostic runs only in the organizer's
bounded, non-root, networkless, read-only pinned Python executor. The host
recomputes the selected root hashes and masked predicate. Numeric internal
observations remain untrusted. No code from the participant ran on the host.
No full-scale attack was attempted. The exact subset behavior, selected
constructor and conditional rare-event rate are separate claims.

The required baseline_improved identifier blake3-r2-nominal-v2 is reference
metadata, not an established attack or security theorem. This conditional101
bound is below the nominal display128 and the 128.45 generic comparator under
the stated premises, not a certified break of full-round BLAKE3. The source's
much faster optimized construction is acknowledged;101 is not a global novelty
or best-known claim. Ready means complete for review, not qualified, human
accepted or promoted. The complete package is ready for remote review after fresh mechanical and
isolated checks; readiness is not a qualifying verdict.

# Appendix A: licensed source ingredients

The following mathematical text is retained from the promoted source's
Section3. It uses the exact old constants reproduced in this package.

## 3. Three ingredients

**3.1 The length is cancelled inside K2.** K2 is the only call of round 0 that reads the block length n, the initial value of v[14], and it overwrites that word; it is also the only call of round 0 that reads w4 and w5. Its inputs are (IV[2], IV[6], IV[2], n). Put K = IV[2] + IV[6] = 5bf2cd1d. For lengths 55 and 63, whose XOR is 8, define for any w4, w5
    w4' = ((K + w4) XOR 8) - K        w5' = w5 + w4 - w4'.
**Lemma L.** K2 with block length 55 and words (w4, w5) leaves the same four state words as K2 with block length 63 and words (w4', w5').
Proof. Let a1 = K + w4. In the second execution the first assignment gives K + w4' = a1 XOR 8, so the second gives ROR(63 XOR a1 XOR 8, 16) = ROR(55 XOR a1, 16) because 63 XOR 8 = 55: the same d1. The third and fourth depend only on d1 and constants. The fifth gives (a1 XOR 8) + b1 + w5' = a1 + b1 + w5 because w5' - w5 = w4 - w4' = a1 - (a1 XOR 8). The last three depend only on values already shown equal. QED.
Hence two messages of 55 and 63 bytes that share every word except w4, w5, related as above, have the same state S after the column step and the same state X after round 0, since no other call of round 0 reads v[14], w4 or w5 before K2 has made the states equal.
*Which words must be zero.* For both messages to be honest byte strings of their lengths with the same words w6..w15, the bytes 55 to 63 of the block must be zero in both. In the 55-byte message they are zero fill. In the 63-byte message bytes 55 to 62 are its last eight bytes, which are chosen to be zero, and byte 63 is zero fill. Byte 55 is the top byte of w13, bytes 56 to 59 are w14 and bytes 60 to 63 are w15. So the family needs
    w14 = 0,   w15 = 0,   top byte of w13 = 0,
and nothing else: bytes 0 to 54 are free in both messages.
**3.2 A pinned call C3.** Fix the six constants
    X3 = 29d4fa98   X7 = bee3af28   X11 = 44036000   X15 = 40c58500
    W4 = 97475638   W13 = 0007c006
The top byte of W13 is zero. K + W4 = f33a2355 and W4' = ((K + W4) XOR 8) - K = 97475640, so W4 - W4' = fffffff8, that is -8 modulo 2^32. Evaluate C3 = G(3,7,11,15, w4, W13) on the inputs (X3, X7, X11, X15) with w4 = W4 and with w4 = W4':
    w4 = W4    a1=7ffffff8 d1=7af83f3a c1=befb9f3a b1=01200183
               a2=8127c181 d2=bbfbdffe c2=7af77f38 b2=76f7aefd
    w4 = W4'   a1=80000000 d1=8500c0c5 c1=c90420c5 b1=fed77e78
               a2=7edf3e7e d2=bbfbdffe c2=850000c3 b2=76f7aefd
**Fact P.** The two executions give the same d output bbfbdffe and the same b output 76f7aefd. They differ in the a output (8127c181, 7edf3e7e) and in the c output (7af77f38, 850000c3). This is a finite computation on the displayed constants.
**3.3 Half of the digest does not see the difference.**
**Lemma H.** Take two executions of the 2-round compression that have the same state X after round 0 and the same message words except w4 and w5. Suppose (X[3], X[7], X[11], X[15]) = (X3, X7, X11, X15), w13 = W13, and w4 is W4 in the first execution and W4' in the second. Then the two digests agree on digest words 0, 2, 5 and 7.
Proof. C0, C1, C2 read neither w4 nor w5 and act on identical states, so they leave identical values in both executions. C3 reads state words 3, 7, 11, 15 and the words w4, w13; by Fact P it leaves the same v[7] and v[15] in both executions and may differ only in v[3] and v[11]. So Y agrees except possibly in Y[3] and Y[11]. E0 reads Y[0], Y[5], Y[10], Y[15] and w1, w11. E2 reads Y[2], Y[7], Y[8], Y[13] and w9, w14. None of these is Y[3], Y[11], w4 or w5, so E0 and E2 produce identical outputs Z[0], Z[5], Z[10], Z[15] and Z[2], Z[7], Z[8], Z[13]. Finally o[0] = Z[0] XOR Z[8], o[2] = Z[2] XOR Z[10], o[5] = Z[5] XOR Z[13] and o[7] = Z[7] XOR Z[15] use only those eight words. QED.
The remaining digest words o[1] = Z[1] XOR Z[9], o[3] = Z[3] XOR Z[11], o[4] = Z[4] XOR Z[12] and o[6] = Z[6] XOR Z[14] are computed from the outputs of E1 and E3 only. The **residual** of a pair is the 128-bit string R = (o[1] XOR o'[1], o[3] XOR o'[3], o[4] XOR o'[4], o[6] XOR o'[6]). The pair is a collision exactly when R = 0.


# Appendix B: licensed complete counter constructor

This retains source Section8 through its exact constructor theorem. The
source reference mapping is specified in our Section3. Source model/optimized
search claims outside these excerpts are not adopted by this attack.

## 8. The counter construction

*Words and constants.* The construction has nine free words: the seven *outer words* C0.d1, D2.a1, D2.b1, S11, S4, X9 and w6; a member y of the class of 6.1 (Lemma Q), which becomes the value of Y4; and the *inner word* c1, which becomes the third value of E1 on message A. The constants are those of Section 4: X3, X7, X11 and X15, w4 = W4, w13 = W13, w14 = w15 = 0, the four constant first values K2.a1, K2.d1, K2.c1 and K2.b1 of K2 given in step O, and Y3, Y11 of Fact P. The compression reads three more values besides the message and the IV. K3 reads the flags, here 3 (the line for K3.d1); K1 reads v[13], here 0 (the line for K1.a1); and K0 reads the counter v[12], which is not fixed in advance: the line for t solves K0's second assignment for it. The names are those of Section 4.
*The cube Q*.* Q* is the set of the 2^21 words c with (c AND 0e09818b) = 02008000. Member number j of Q*, for 0 <= j < 2^21, is the word whose bits at the 21 positions where 0e09818b has a zero are the bits of j, in increasing order of position.
*Members.* In Sections 8 to 12 a *member* is a member of the class of Lemma Q, not of the sub-class of 6.1. Member number k of the class, for 0 <= k < 2^19, is the Y4 whose e1 = Y3 + Y4 has the bits of k at the 19 positions where 03cf8303 has a zero, in increasing order of position, and Y4 = e1 - Y3. The search of this package uses every member; it has no sub-class and no rule A.
**Step CO (the outer step; 77 lines, from the seven outer words and y).**
    X2 = D2.a1 + D2.b1 + W13;   X8 = ROL(X7,7) XOR D2.b1
    C0.c1 = X8 + C0.d1;   K3.a1 = IV[3] + IV[7] + w6
    K3.d1 = ROR(K3.a1 XOR 3,16);   K3.c1 = IV[3] + K3.d1
    S15 = S11 - K3.c1;   S3 = ROL(S15,8) XOR K3.d1
    K3.b1 = ROR(IV[7] XOR K3.c1,12);   D3.a1 = S3 + S4
    S7 = ROR(K3.b1 XOR S11,7);   D3.b1 = X3 - D3.a1
    D2.c1 = ROL(D2.b1,12) XOR S7;   D3.c1 = ROL(D3.b1,12) XOR S4
    X4 = ROR(D3.b1 XOR X9,7);   X13 = X8 - D2.c1
    X14 = X9 - D3.c1;   C0.b1 = ROR(X4 XOR C0.c1,12)
    D2.d1 = ROL(X13,8) XOR X2;   D3.d1 = ROL(X14,8) XOR X3
    Y8 = ROL(Y4,7) XOR C0.b1;   S13 = ROL(D2.d1,16) XOR D2.a1
    S9 = D3.c1 - D3.d1;   Y12 = Y8 - C0.c1
    K1.c1 = S9 - S13;   Y0 = ROL(Y12,8) XOR C0.d1
    K1.d1 = K1.c1 - IV[1];   C0.a1 = Y0 - C0.b1 - w6
    K1.a1 = ROL(K1.d1,16);   w2 = K1.a1 - IV[1] - IV[5]
    X0 = C0.a1 - X4 - w2;   S14 = ROL(D3.d1,16) XOR D3.a1
    K1.b1 = ROR(IV[5] XOR K1.c1,12);   S10 = K2.c1 + S14
    D0.d1 = ROL(X15,8) XOR X0;   S5 = ROR(K1.b1 XOR S9,7)
    D0.c1 = S10 + D0.d1;   D0.b1 = ROR(S5 XOR D0.c1,12)
    X10 = D0.c1 + X15;   X5 = ROR(D0.b1 XOR X10,7)
    S1 = ROL(S13,8) XOR K1.d1;   w3 = S1 - K1.a1 - K1.b1
    X12 = ROL(C0.d1,16) XOR C0.a1;   D1.c1 = X11 - X12
    D1.d1 = D1.c1 - S11;   S8 = D2.c1 - D2.d1
    K0.b1 = ROL(S4,7) XOR S8;   S2 = ROL(S14,8) XOR K2.d1
    S6 = ROR(K2.b1 XOR S10,7);   X1 = ROL(X12,8) XOR D1.d1
    K0.c1 = ROL(K0.b1,12) XOR IV[4];   D1.b1 = ROR(S6 XOR D1.c1,12)
    C1.a1 = X1 + X5 + w3;   S12 = S8 - K0.c1
    w7 = S3 - K3.a1 - K3.b1;   X6 = ROR(D1.b1 XOR X11,7)
    C1.d1 = ROR(X13 XOR C1.a1,16);   D1.a1 = ROL(D1.d1,16) XOR S12
    C1.c1 = X9 + C1.d1;   C2.a1 = X2 + X6 + w7
    w10 = D1.a1 - S1 - S6;   C1.b1 = ROR(X5 XOR C1.c1,12)
    C2.d1 = ROR(X14 XOR C2.a1,16);   w12 = D2.a1 - S2 - S7
    Y1 = C1.a1 + C1.b1 + w10;   C2.c1 = X10 + C2.d1
    Y13 = ROR(C1.d1 XOR Y1,8);   C2.b1 = ROR(X6 XOR C2.c1,12)
    K0.d1 = K0.c1 - IV[0];   Y9 = C1.c1 + Y13
    S0 = ROL(S12,8) XOR K0.d1;   D0.a1 = ROL(D0.d1,16) XOR S15
    w8 = D0.a1 - S0 - S5;   w5 = S2 - K2.a1 - K2.b1
    w9 = X0 - D0.a1 - D0.b1;   w11 = X1 - D1.a1 - D1.b1
    Y5 = ROR(C1.b1 XOR Y9,7)
**Step CT (the trial; 16 lines, from c1 and the names of step CO).**
    E1.d1 = c1 - Y11;   E1.a1 = ROL(E1.d1,16) XOR Y12
    Y6 = E1.a1 - Y1 - w12;   Y10 = ROL(Y6,7) XOR C2.b1
    Y14 = Y10 - C2.c1;   E1.b1 = ROR(Y6 XOR c1,12)
    Y2 = ROL(Y14,8) XOR C2.d1;   E3.h1 = ROR(Y14 XOR (Y3 + Y4),16)
    w0 = Y2 - C2.a1 - C2.b1;   E3.g1 = Y9 + E3.h1
    K0.a1 = IV[0] + IV[4] + w0;   E3.f1 = ROR(Y4 XOR E3.g1,12)
    t = ROL(K0.d1,16) XOR K0.a1;   w1 = S0 - K0.a1 - K0.b1
    E1.a2 = E1.a1 + E1.b1 + w5;   E3.e2 = Y3 + Y4 + E3.f1 + w8
**Step CS (the messages).** If t = 0 the trial is invalid and is dropped: a message with no full chunk before its last chunk has that chunk as its root, compressed with counter 0 and flags 11 and not with the flags 3 that the line for K3.d1 used. Otherwise the words w0 to w12 of the lines, with w4 = W4 and w13 = W13, and w14 = w15 = 0 form the block of A; A is the first 55 bytes of its little-endian encoding, and B the first 63 bytes of that of the same words with w4' = W4' and w5' = w5 + fffffff8 in place of w4 and w5, as in steps S2 and S3 of Section 4. F is the string of 1024 t zero bytes, and the two messages are F || A, of 1024 t + 55 bytes, and F || B, of 1024 t + 63 bytes.
*The order and the calls.* Table CT gives each call's eight assignments by the name that the line for that assignment assigns; the cells K2.a1, K2.d1, K2.c1 and K2.b1 are the four constant values. E1's first five assignments are the lines for Y6, E1.a1, E1.d1, E1.b1 and E1.a2, in the order of the assignments; E3's first two assignments are the line for E3.h1, and its third to fifth the lines for E3.g1, E3.f1 and E3.e2.

| Call | 1st | 2nd | 3rd | 4th | 5th | 6th | 7th | 8th |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| K0 | K0.a1 | t | K0.d1 | K0.c1 | w1 | S0 | S12 | K0.b1 |
| K1 | w2 | K1.a1 | K1.d1 | K1.b1 | w3 | S1 | K1.c1 | S5 |
| K2 | K2.a1 | K2.d1 | K2.c1 | K2.b1 | w5 | S2 | S10 | S6 |
| K3 | K3.a1 | K3.d1 | K3.c1 | K3.b1 | w7 | S3 | S15 | S7 |
| D0 | w8 | D0.a1 | D0.c1 | D0.b1 | w9 | D0.d1 | X10 | X5 |
| D1 | w10 | D1.a1 | D1.d1 | D1.b1 | w11 | X1 | D1.c1 | X6 |
| D2 | w12 | S13 | S8 | D2.c1 | X2 | D2.d1 | X13 | X8 |
| D3 | D3.a1 | S14 | S9 | D3.c1 | D3.b1 | D3.d1 | X14 | X4 |
| C0 | X0 | X12 | C0.c1 | C0.b1 | C0.a1 | Y0 | Y12 | Y8 |
| C1 | C1.a1 | C1.d1 | C1.c1 | C1.b1 | Y1 | Y13 | Y9 | Y5 |
| C2 | C2.a1 | C2.d1 | C2.c1 | C2.b1 | w0 | Y2 | Y14 | Y10 |

The order was found by a solver search of the participant's helper agents for an order in which Y4 and E1.d1 are both free words.
**Lemma CT (the counter order).** (a) *Triangular.* In the printed order, step CO and then step CT, every line assigns a name that no earlier line assigns and that is neither one of the nine free words nor a constant, and it reads only constants, the nine words and names of earlier lines; a line of step CO reads neither c1 nor a name of step CT. Every line is one assignment of one call solved for the name on its left; the exceptions are the line for E3.h1, which is the first two assignments of E3 with the first substituted into the second (e1 = Y3 + Y4 + w15, w15 = 0), and the line for E3.e2, which uses the same e1. By Table CT the 93 lines and the four constant values of K2 are, each exactly once, the eight assignments of each of the eleven calls K0..K3, D0..D3, C0..C2, with the inputs and the message words of Section 1 for block length 55, counter v[12] = t, v[13] = 0 and flags v[15] = 3, with w4 = W4, w13 = W13, w14 = w15 = 0, and with the constants X3, X7, X11, X15 as the a output of D3, the b output of D2, the c output of D1 and the d output of D0; and the first five assignments of E1 and of E3 for message A, E1 with c input Y11 and E3 with a input Y3.
(b) *The calls.* For every choice of the nine words, the names of the lines are the executions of these calls. In particular round 0 on the block of A, with block length 55, counter t, v[13] = 0 and flags 3, leaves the state X of the names, with the four constants as X[3], X[7], X[11] and X[15]; C0 has outputs (Y0, y, Y8, Y12); and in the compression of A, E1.c1 = c1, since E1's third assignment is E1.c1 = Y11 + E1.d1.
(c) *The levels.* A line of step CO is a function of the seven outer words and y. Of the message words only w0 and w1 are lines of step CT, and so is the counter t; every other message word is a line of step CO or a constant. So the trials of one outer step differ in w0, w1 and t and in nothing else of their two messages.
Proof. (a) is read off the displays, each formula compared with Section 2 and with its call's inputs, outputs and message words (Section 1, with v[12] = t, v[13] = 0 and v[15] = 3); Table CT has one name in each of its 88 cells, all different, the four constant values of K2 among them, and with the five names of E1 and the four lines of E3 they are the 93 lines and the four constants. (b) As in Lemma T2 (b): an assignment solved for one of its terms is an equivalent equation modulo 2^32 (Fact 1), so a line's assignment holds once it has run, and by (a) no later line changes its names. By (a) and Table CT all eight assignments of each call hold, a constant output in its place (the lines for D3.b1 and D3.d1; X8; D1.c1 and X6; D0.d1 and X10) and y as the b output of C0 (the line for Y8); by Fact 1 the names are the execution of the call. (c) By induction over the printed order, with (a): a line of step CO reads only constants, the seven outer words, y and lines of step CO; w2, w3, w5 and w7 to w12 are lines of step CO, w6 is an outer word, w4, w13, w14 and w15 are constants, and w0, w1 and t are lines of step CT. QED.
**Theorem C (the last-chunk half-collision).** For every choice of the seven outer words, of a member y of the class and of a word c1, steps CO and CT give a counter t. If t is not zero, step CS outputs two distinct messages F || A and F || B of 1024 t + 55 and 1024 t + 63 bytes, with 1 <= t < 2^32, such that
(i) their last chunks are A and B, compressed with counter t, v[13] = 0 and flags 3 (Lemma TR (a));
(ii) the chaining values CV_t(A) and CV_t(B) agree on words 0, 2, 5 and 7;
(iii) in both last-chunk compressions Y4 = y, and the XOR difference between A and B of E3's first-half d value is eta = 830303cf; (iv) in the compression of A, E1.c1 = c1; and if c1 is in Q*, the XOR difference between A and B of E1's first-half b value is beta* = 18b0e098.
Proof. t is the XOR of two 32-bit words, so t < 2^32 and t >> 32 = 0, the value v[13] = 0 that the line for K1.a1 used. The sixteen words have w14 = w15 = 0 and w13 = W13, whose top byte is zero, so A and B are honest strings of 55 and 63 bytes whose zero-filled blocks are the sixteen words and the same words with w4 and w5 replaced, as in Section 5. By Lemma TR (a) the last chunks are compressed with counter t, v[13] = 0, flags 3 and block lengths 55 and 63. By Lemma CT (b) round 0 on the block of A leaves the state X of the names, with the four constants as X[3], X[7], X[11] and X[15]. The counter, v[13] and the flags are the same in both compressions, and K2 is the only call of round 0 that reads the block length, w4 or w5; Lemma L, whose proof concerns K2 alone, therefore gives the same state X for B. Lemma H gives (ii): its proof uses only round 1 and o[i] = Z[i] XOR Z[i + 8] for i = 0, 2, 5 and 7, and the chaining value is (o[0], .., o[7]). (iii) As in the proof of Lemma T: C0 reads the same words of X and w2, w6 in both compressions and has b output y by Lemma CT (b); w15 = 0, Y14 is the same in both, the a input of E3 is Y3 for A and Y3' for B by Fact P, and y is in the class, so the difference is eta by the definition of the class (6.1). (iv) E1.c1 = c1 is Lemma CT (b). E1 has inputs (Y1, Y6, Y11, Y12) and message words (w12, w5) for A, and (Y1, Y6, Y11', Y12) and (w12, w5 + delta) for B. Its first and second values are the same for both, so its third values are c1 and c1 + DY11, with DY11 = Y11' - Y11 = 0a08818b, and its fourth values are ROR(Y6 XOR c1, 12) and ROR(Y6 XOR (c1 + DY11), 12). Their XOR is ROR(c1 XOR (c1 + DY11), 12), which is beta* exactly when c1 XOR (c1 + DY11) = ROL(beta*, 12) = 0e09818b. For words c and x, (c XOR x) - c = x - 2 (c AND x) modulo 2^32, which is the identity of the proof of Lemma Q; with x = 0e09818b this holds exactly when 2 (c1 AND 0e09818b) = 0e09818b - DY11 = 04010000. As 0e09818b has no bit 31 the doubling is exact, and it holds exactly when (c1 AND 0e09818b) = 02008000, that is when c1 is in Q*. The messages are distinct because their lengths differ. QED.

# Appendix C: source-reported model rate and supporting measurements

The following source Section10.1 is retained as reported mathematical/model
evidence, not an organizer-verified count. The counting program it references
is not part of this package and was not run in this session.

**10.1 The model rate.** The seven-word model M of Section 13 treats the residual of a trial as a function of seven words, E1.d1, E1.b1 and E1.a2 of message A and Y4, Y9, w8 and E3.h1. In this package Y4 is uniform in the class of eta, not in the sub-class, and the other six are independent uniform words, so M has 2^192 * 2^19 = 2^211 inputs. Under M the rate of the class is 85074516985129 / 524288 = 162,266,763.66 (Section 13): a trial has R = 0 with probability that number times 2^-128. The part of a value beta of E1's first-half b difference in it is written r(beta); the part of beta* is 71,698,432, and the part of the six outcomes of S that this search lists (below) is 67,633,152. A trial of Section 8 has c1 in Q* and so the difference beta* (Theorem C (iv)); under M the event that c1 = Y11 + E1.d1 lies in Q* has probability 2^-11 and is the event that the difference is beta* (Lemma S1). The rate at which a trial that M conditions on c1 in Q* has R = 0 with an outcome of S is therefore
    p = 2^11 * 67,633,152 * 2^-128 = 138,512,695,296 * 2^-128 = 1,032 * 2^-101,
about 2^-90.989. It is 853.61 = 2^9.738 times the model rate of a trial of the class.
*The outcomes of beta*.* In the count of Section 13 an outcome of beta is a pair (tau, eps) of the differences of E1's a and c outputs. For an outcome j of beta*, L_j is the number of triples (E1.c1, E1.b1, E1.a2) of words for which E1 on A and on B (6.2) gives the differences beta*, tau_j and eps_j; and N3_j is the number N3 of step 3 of the count for that outcome: the number of quadruples (Y4, E3.h1, Y9, w8), Y4 in the class, for which E3 on A and on B gives the differences eta and tau_j XOR ROR(tau_j, 1) of its first-half d and b values and tau_j and eps_j of its c and a outputs. Every input of the 2^211 of the model falls into one outcome, so r(beta*) = sum over j of L_j N3_j / 2^83. Beta* has fourteen outcomes on the class, all with eps = 6e21be55; this search lists the six of S, j = 1 to 5 and 7:

| j | tau | L_j | N3_j | L_j * N3_j / 2^83 |
| ---: | --- | ---: | ---: | ---: |
| 1 | 175020a0 | 562,949,953,421,312 | 108,086,391,056,891,904 | 6,291,456 |
| 2 | 185020a0 | 2,251,799,813,685,248 | 72,057,594,037,927,936 | 16,777,216 |
| 3 | 275020a0 | 562,949,953,421,312 | 18,014,398,509,481,984 | 1,048,576 |
| 4 | 285020a0 | 2,251,799,813,685,248 | 108,086,391,056,891,904 | 25,165,824 |
| 5 | 385020a0 | 1,125,899,906,842,624 | 144,115,188,075,855,872 | 16,777,216 |
| 6 | 675020a0 | 140,737,488,355,328 | 4,503,599,627,370,496 | 65,536 |
| 7 | 685020a0 | 562,949,953,421,312 | 27,021,597,764,222,976 | 1,572,864 |
| 8 | 175060a0 | 281,474,976,710,656 | 6,755,399,441,055,744 | 196,608 |
| 9 | 185060a0 | 1,125,899,906,842,624 | 9,007,199,254,740,992 | 1,048,576 |
| 10 | 275060a0 | 281,474,976,710,656 | 1,125,899,906,842,624 | 32,768 |
| 11 | 285060a0 | 1,125,899,906,842,624 | 13,510,798,882,111,488 | 1,572,864 |
| 12 | 385060a0 | 562,949,953,421,312 | 18,014,398,509,481,984 | 1,048,576 |
| 13 | 675060a0 | 70,368,744,177,664 | 281,474,976,710,656 | 2,048 |
| 14 | 685060a0 | 281,474,976,710,656 | 3,377,699,720,527,872 | 98,304 |
| sum, S: j = 1 to 5 and 7 (listed) | | | | 67,633,152 |
| sum, j = 1 to 7 (the seven of the program) | | | | 67,698,688 |
| sum, all fourteen | | | | 71,698,432 |

The rows j = 1 to 7 have the L_j of the sub-class of entry 26ebba63 and four times its N3_j, so on this scale they carry exactly its 67,698,688 = 1,033 * 2^16. S leaves out row 6, 675020a0, with 65,536 = 2^16, and carries 67,633,152 = 1,032 * 2^16, so p = 1,032 * 2^-101 exactly; the rows j = 8 to 14, with bit 14 of tau set, add 3,999,744, 5.6 per cent of the part of beta*, and are not listed either. The integers L_j and N3_j are those of the participant's counting program, printed in Section 17 with the six rows of its output that this search lists; it prints L_j N3_j / 2^81, four times the last column, and the six listed rows sum to 270,532,608 = 4 * 67,633,152 there, and the scale 2^83 is that of a trial with Y4 uniform in the 2^19 members of the class. Of the 52 values of tau that pass the screens of the count, 30 have N3_j > 0 and 14 have L_j N3_j > 0. The count uses no rule on h1.
*Why S.* S = 5f is part of the stated advice record of Section 12, and what the analysis uses of it is verified here: its count, 67,633,152 = 1,032 * 2^16 (the table above, Section 17), its certificate with SHARE and E_COUNT (Section 8) and its charge (Section 11). It is not claimed to be least under Section 11; step 3 of SEL (Section 12) chose it under the ledger of entry 415e792c.
*Why beta*.* Beta* = 18b0e098 is a value of the stated advice record, and what the analysis uses of it is verified here: its cube of c1, k = 11 fixed bits, mask 0e09818b and value 02008000 (Theorem C (iii) and (iv)), and its fourteen outcomes on the class with their counts (the table above). It is the beta of the solution with which the solver found the six constants.

The8-bit end-to-end protocol in the promoted source reports SHA256
c5895dd64b07710f9fb386b0f9d4f6b5cb38b14b502a4cc80e51c60584432a4e for its
preregistration text. Its source report says one run with no interim look,
40,882 complete toy collisions versus40,800.63 predicted and no failed tree
checks. Programs/raw samples are not in this package; no inference of target
full-event probability is presented as verified evidence. The local declared
experiment supplies our new independently host-checked root-mask observations.

# Appendix D: source-reported completed advice records

This retained source Section14 supports H-history. It records its own
limitations; no wall-clock-to-RAM conversion is assumed. The generous2^96
unit/2^43-byte premise in our Section6, not the donor's tighter assertions,
is used in our total bound.

## 14. The records of SEL

This section gives the participant's records behind the premise H-SEL-return of Section 12; the harness does not check them. The solver log, trail5_lx.log (116 lines, SHA-256 ae0fc528b515c0fbd7b17693b79f73855fd3c15df331f5e3b2514068f7224771), has one line per run in the order the runs ended. A run called the generator trailmin5.py, with r2_sat.py and r2_trail.py (SHA-256 beginning 2e20272c8bfdc850, d38ab14e1478bfaa and 9335c9f697e5f18e), for the logged variant pin-lxN (N the XOR of the two lengths, 8 for 55 and 63), bound and seed; it builds the instance of SEL step 1 and runs `kissat -q --sat --seed=S --time=T` on it, on one processor core. The driver scripts set T to 5,400, 7,200 or 9,000 seconds, and two of them add one clause per pair (D3, D11) of the variant then in the log; the log records neither T, these clauses nor start times, and the sign of delta of some variants only with a model. No operation counter was kept: t is the logged wall time of the solver call.
The counter is the C program pair_calc_sub, built with gcc -O2 -fopenmp from pair_calc_sub.c, pair_calc_batch.c, r2_e3count.c, n3x.inc and n3r.inc (SHA-256 beginning c2c5fa4a5aa0b5e6, 6b96bb1fdd72e331, 9335052ba5764843, 4390344d557488cf and a5fa399525d9cb52); these rebuild, byte for byte, the binary that made the recount (4512e46fb05f9db9). It was called once per returned instance (D3, D11, delta, Y3, Y11, eta, beta) on the whole class of its eta, with one thread; it adds L * N3 over the outcomes of beta in integers and divides by 2^(96 - k), the class having 2^(32 - k) members: for eta = 830303cf, k = 13 and this is the sum of Section 17 divided by 2^83. All 65 calls exited 0 with no outcome uncounted, and a second enumeration of the outcomes gave the same numerators. The sources, 41,570 bytes for the generator and 75,010 for the counter, would not fit in the organizer's 512 KiB review budget and are not printed.
Columns: run, the line of the log; lx, bnd (bound) and seed as logged; t in seconds; result SAT, UNSAT, cap (UNKNOWN at a driver's time cap) or out (UNKNOWN, stopped from outside below every cap); for SAT, the beta returned and its exact part. Run 20 returns the record; its log line follows the table.

```text
run lx bnd seed t result beta part
1 1 110 201 0 UNSAT
2 3 108 205 0 UNSAT
3 3 106 206 1 UNSAT
4 1 106 203 2 UNSAT
5 3 110 204 3 UNSAT
6 1 108 202 5 UNSAT
7 4 118 501 364 SAT 403864b4 174021/16
8 8 118 504 651 SAT c5960780 128
9 4 114 601 360 SAT 90948931 3477/8
10 8 116 604 463 SAT 5c182484 555/4
11 16 114 507 1487 SAT a35f8170 112863/4
12 8 113 704 585 SAT 82392898 22224
13 8 110 505 1926 SAT 81199182 19351/8
14 8 110 804 880 SAT 011cc4b6 34867/2
15 4 110 502 2746 SAT afbc3054 8448
16 8 107 904 584 out
17 4 111 701 2599 SAT 907df8c2 2162688
18 4 108 521 1787 SAT 81584e44 1328640
19 4 105 522 2774 SAT 409c6132 591360
20 8 104 506 4770 SAT 18b0e098 71698432 <- the record
21 8 105 524 2865 SAT 11198c98 786432
22 8 108 717 1112 SAT a4980680 2359296
23 8 102 602 2745 out
24 8 104 601 2747 SAT b0188284 9304576
25 8 104 712 2628 SAT 009b4089 49152
26 8 108 1717 2380 SAT 65560c80 9984
27 8 104 711 3931 SAT 18f05282 1897952
28 8 108 2717 985 SAT 92d50080 933888
29 8 106 605 4972 SAT 83924388 3858432
30 8 102 714 5043 SAT 45be4188 460800
31 8 108 3717 589 SAT 01192093 57344
32 8 106 715 5114 SAT 5897c098 4628480
33 6 112 801 205 SAT d234801a 4048
34 8 102 713 5400 cap
35 8 100 716 5400 cap
36 6 106 802 1089 SAT e91e11a6 1863680
37 6 106 804 1294 SAT 10910c51 7485511/256
38 10 110 806 1456 SAT 823a119a 72687/64
39 8 100 603 7101 SAT 82df8088 13107200
40 8 104 1711 2938 SAT 05160c85 860487
41 6 112 803 2214 SAT c0d09dea 52224
42 6 111 1801 2237 SAT 84930914 42931/1024
43 10 109 1806 1012 SAT 10dd0552 44032
44 6 106 1804 1216 out
45 6 112 1803 691 SAT 207601d6 81920
46 8 103 705 3245 out
47 8 104 1712 5400 cap
48 8 100 1716 2667 out
49 6 105 1802 2092 SAT f8902310 79800
50 4 100 608 9000 cap
51 4 104 607 9000 cap
52 8 98 604 9000 cap
53 8 106 1715 3907 SAT 6c982280 818400
54 6 111 2801 1576 SAT 405720a1 3072
55 8 102 701 6834 out
56 8 102 1714 4261 out
57 8 108 4717 4331 SAT f8b7c181 61440
58 6 110 2803 1637 SAT 69160422 67632
59 116 108 905 213 out
60 8 106 2715 725 SAT 811f9490 786432
61 8 102 2714 529 out
62 6 106 2804 2486 SAT 48152212 2573556
63 120 104 903 609 out
64 10 110 805 5099 SAT 89139496 80256
65 6 110 3801 1208 SAT aa193012 14892
66 116 108 904 919 SAT a03ba070 9510
67 120 104 901 1224 SAT 849510b8 884736
68 120 104 1901 29 out
69 8 102 1713 5400 cap
70 6 110 4801 1240 SAT 217a5025 67200
71 8 104 2711 5400 cap
72 112 108 906 2914 SAT f990e10a 2355712
73 10 108 2806 5015 out
74 116 106 1904 2331 out
75 120 104 2901 2091 SAT 825ba088 73728
76 10 109 1805 2896 SAT 835580d6 1024
77 120 103 3901 190 out
78 120 103 4901 33 out
79 10 108 2805 122 out
80 8 102 2713 2437 out
81 8 104 2712 5400 cap
82 8 100 2716 5400 cap
83 6 105 2802 5400 cap
84 6 109 5801 2140 SAT c07d40a0 121344
85 6 108 3803 4135 SAT 029c4263 54512
86 6 105 3802 236 out
87 8 97 703 7142 out
88 116 106 2904 1282 SAT 233f88d0 2266691/16
89 8 108 5717 4740 SAT 80790998 786432
90 8 106 3715 4575 out
91 112 108 907 4992 out
92 116 108 1905 4983 SAT b9748048 344560
93 10 108 3805 1653 out
94 10 108 3806 2358 out
95 120 100 902 5400 cap
96 6 105 3804 4956 out
97 8 102 3713 1792 out
98 120 104 1903 4941 SAT 8cf806b0 98304
99 6 108 6801 1539 SAT c1160c60 102568
100 120 100 1902 280 out
101 8 102 3714 5400 cap
102 8 106 4715 1106 out
103 112 105 1906 3117 SAT c0d063f0 236096
104 116 106 3904 1503 out
105 8 102 4713 775 out
106 112 105 2906 331 out
107 8 106 5715 900 out
108 8 108 6717 2216 SAT 26782888 842005/256
109 8 104 3711 4126 out
110 6 108 7801 1626 SAT 243a08a1 86592
111 6 107 4803 3165 SAT 111603ea 49152
112 10 108 4806 2031 SAT 4ed204a6 65424
113 8 104 3712 3586 SAT 1893c498 645120
114 6 105 4802 3351 SAT 40bc2162 439296
115 8 102 4714 2908 SAT 271a1080 7249920
116 8 104 4712 1181 SAT 8ad48098 6912
```

```text
RES model=pin-lx8 bound=104 fixed=no seed=506 t=4770s status=SATISFIABLE cost=100 x1w=13 PIN=29d4fa98,bee3af28,44036000,40c58500,97475638,0007c006 D3=fdb77cfd D11=0a08818b delta=fffffff8 Y3=8127c181 Y11=7af77f38 eta=830303cf beta=18b0e098 tau=185020a0 eps=6e21be55 parts=A1:11,A4:13,A5:21,A3:14,A6:23,A7:18 sol=27e956dc,027077ff,800817b3,e614819a,615469a6,9ff1dcb4,6fc881ad
```


# Appendix E: original contributor credits

These are retained historical credits from the donor's Section16. They do
not assert that every donor optimization is used here, or that the credited
people/model instances reviewed this independent-trial variant. Only the
constructor, advice, model/evidence and historical records are reused.

## 16. Credit

One line per contributor. Apart from the helper agents of the participant, nobody named here has reviewed this package, and a credit is not an endorsement.

- **hecmas**, entry e9b6649e (65.3643): the member loop over contexts, the two direct tables of the filter and the restatement of
  the premises for contexts (9.8, 10.3, described in the participant's words).
- **Th0rgal**, entry 77818485: setting the credit of the solver at an exact model mean of its work, here of the executed ledger
  (9.1, 10.3); earlier, the member values built once per outer step (entry df8bd46d) and three coding steps of 6.5 (entry
  8c81a219).
- **GPT Sol 6.1 (OpenAI)**, an AI model run by the participant: the cluster gate with Lemmas KP and A9, its layout and charges
  (answer CI 1), its opened-cluster budget (answer CJ 1) and tight layout (CJ 2 to 5), the least factors of H4' on our sample and
  the reserves over contexts (CK), the stacked ledger and its once reserves (CK2), the metered credit with its meter, preflight
  reserve, the ratio of Lemma ME and the premise H5_exec (CK3), the cached Y9 of a batch with its frames, fill budget and the
  premise H_G_cluster, and the stacked row (CM), the omega-first batch and its audit, the E count in a register with the frame of
  a passing lane and the global ledger of 1,024 (answers CA and CD), the root certificate with Lemma RC and the guard (G15) with
  Lemma G15 (CF 6 and 7), the guard (G7) with Lemma G7 (AX 1), the pre-check and the budgets (AW), the joint solver with its
  certificates, guards and caps (AE to AT), Lemmas F and S9 (AC), Lemmas IP, S1 to S5 and S8, the sub-class and rule A of the root
  instance, and, in its local answers, the fold F1 and the shortcut P1 (D9), the row and specification of entry 89b451ff that this
  row keeps (D11 and D12), the source bank, immediate list addresses, the context bound and the cap transfer with Lemma CP (D13),
  the masked partner walk with Lemma XF and its class specialization (D14), the straddle gate with Lemmas CL and OR and its
  six-operation key (D14 and D16), and the row of entry 070a02b2 with its audit of the masked opening (D18).
- **GPT-6 Astra (OpenAI)**, an AI model run by the participant: the exact flat mean and the bound in model M on the mean of the
  solver's ledger of the earlier layout (Batch 11), cited in 9.1 and 10.3 and not reproduced here; one row per family, Lemma FX (Batch 17).
- **Jbenisek**, the participant who files this package: the half-collision, the class search and the counter construction of the
  participant's entries from 17bba2ae on (Section 15), among them the guard (G7) in this solver (0bc5f130).
- **The participant who filed entry dd91b2f6**: dropping the sub-class and rule A in the solver design, and the fourteen outcomes
  of beta* on the class; nothing of that entry is used.
- **winglock**: searching only a sub-class of members chosen by an exact count (entry 18a7fc52), which the sub-class of the root
  instance follows.
- **5kyguy**: keeping masks in registers across the loop over the members (entry 404d14df).
- **0xshikhar**, entry 73d5265f: keeping the frame words and the counts of the walk in registers (9.8, 9.9).
- **tekkac**: the lane layout of 6.5, seven 36-bit lanes with a masked rotation (public ticket 2bf40fb).
- **Grok (xAI)**, run by the participant: the four cuts of the masked opening, the two chunks priced together, the bookkeeping,
  the descriptor selection and the chunk addressing (job 58), as GPT Sol audited them (answer D18); the schedule and budget cuts
  of this row, (G15) at its itemized 74, the cuts of the global ledger, the tabled rotations of the shortcut, the context schedule
  and the preflight on the call side of the pre-check (jobs 58 and 59), as GPT Luna 5.6 composed them (answer D25); the deletion
  of the scalar rebuild, the cursor and the context schedule (job 53), as GPT Sol certified them (answer D13); earlier, the
  hostile review of entry c66f230d.
- **GPT Luna 5.6**, an AI model run by the participant: the ternary gate with the representative's test kept, its composition with
  the schedule and budget cuts and the joint credit with the call budget (answer D25), the row of entry 244f068c, composed with
  the lane replicas, the descriptor re-encoding and the kept index, with its exact ledger (answer D41), and the broadcast table BT
  of the preceding row with its price (answer D52), which this row replaces by stored broadcast words.
- **The daydream panel of the participant**, helper agents in the voices of a compiler and an accountant: the lane replicas of
  T2', T1 and the gate table, the descriptor re-encoding (the carries in the descriptor address, PX', JE = JU >> 7, no separate
  test of n_0) and the representative's index kept for PXF', with their prices and walk checks, which this row carries over to the lane
  copies of T1, R2, L2 and PXR.
- **GPT-6 Luna**, on the owner's server: a search for better pinned constants, which found none.
- **A model reached through the service Venice**: a statement on prior art, unverified and used in no proof or figure.
- **Helper agents of the participant**, instances of the AI model that wrote this text: the reimplementation of the member loop
  and its measurements, the omega-first batch with its op-counting simulation, the cache and the meter of the declared program,
  our audit of the layout of this row (the work register, the shortcut, the pre-check without a table, the table addresses, the
  gate key, the written-out code and the meter without slack), the combination sweep from which the masked partner walk came, the
  memory layout of this row (the two levels of T2, Lemma T26, the computed gate, the stored broadcasts and the streamed output), the
  build of this row with its op count of the declared program, the integer recounts, the price with its integer test, the count of
  Section 17, the measurements of Section 13, and this text.


# Appendix F: Apache License2.0

The promoted source is incorporated under Apache2.0 under the production
Terms Section5. Source modifications are described in Section1 and in the
declared experiment's header. The original contributor credits are retained.


                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
