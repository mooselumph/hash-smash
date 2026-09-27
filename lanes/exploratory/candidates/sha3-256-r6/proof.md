# SHA3-256 prefix rounds 0 through 5: unconditional generic collision package

The scalar below is `time_log2` under `collision-frontier-v5` with selected-target
reference operation cost C = 1626. Memory remains a separately reported resource
bound.

Selected lane: exploratory. Target: `sha3-256-r6-prefix-v1`.
This finite classical algorithm has total charged time below 2^128.5,
peak memory below 2^137 bytes, and success probability above 1/2.
The proposed scalar is 128.5. It is a generic analytic construction
with infeasible resource use, not a claimed cryptanalytic advance.
The required `baseline_improved` identifier `sha3-256-r6-nominal-v2`
identifies the organizer's nominal reference only. That nominal 128 is not
an established attack, qualified baseline, or security bound; this package
does not claim to improve it.

## 1. Exact complete hash and legal messages

Let n = 5 * 2^126 and N = 2^256. The input family D is all 64-byte strings,
so |D| = 2^512. Every message has legal bit length 512 < 2^64.
Represent a message by two 256-bit words u,v and serialize it as
LE32(u) || LE32(v), where LE32 writes exactly 32 little-endian bytes,
including zero bytes. This is a bijection from pairs of words onto D.
N and |D| are mathematical cardinalities used only in the proof; the
algorithm never stores either of those out-of-word-range integers.

The selected complete hash has a 1600-bit state, rate 1088 bits (136 bytes),
capacity 512, the all-zero initial state, and full 256-bit output.
Each such message's entire padded input is exactly one 136-byte block:

    LE32(u) || LE32(v) || 06 || (00 repeated 70 times) || 80

This is the SHA3 domain suffix 01 and pad10*1, using delimited suffix 0x06.
There is exactly one absorption permutation, no extra squeezing permutation,
and no Davies-Meyer feed-forward.

The complete subroutine H(u,v) is as follows. Store the state as 25 lanes,
each in the low 64 bits of a separate RAM word; upper bits are zero.
The lane index is x+5y for 0 <= x,y < 5, in little-endian lane order.
Set all 25 lanes A to zero, then for j = 0,1,2,3 set

    A[j]   = (u >> (64*j)) AND (2^64-1)
    A[j+4] = (v >> (64*j)) AND (2^64-1).

Set A[8] = 0x06 and A[16] = 0x8000000000000000.
These are precisely the padded rate block XORed into the all-zero state.
Lanes 17 through 24 remain the zero capacity portion.

Apply exactly the first six Keccak-f[1600] rounds, indices 0 through 5.
For each round use the following stages; within a stage assignments are
simultaneous, and each stage reads the preceding one. Subscripts x,y are
modulo 5. All lane arithmetic is on 64 bits, with NOT64 and rot64 restricted
to those bits, not the entire 256-bit RAM word.

    C[x] = A[x,0] XOR A[x,1] XOR A[x,2] XOR A[x,3] XOR A[x,4]
    D[x] = C[x-1] XOR rot64(C[x+1],1)
    T[x,y] = A[x,y] XOR D[x]
    B[y,2*x+3*y] = rot64(T[x,y],rho[x,y])
    Anew[x,y] = B[x,y] XOR ((NOT64 B[x+1,y]) AND B[x+2,y])
    A = Anew
    A[0,0] = A[0,0] XOR RC[round]

The rho offsets, listed in x+5y order, are

    0, 1,62,28,27, 36,44, 6,55,20, 3,10,43,25,39,
    41,45,15,21, 8, 18, 2,61,56,14.

Use these six RC constants in this order:

    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001.

Return

    d = A[0] OR (A[1] << 64) OR (A[2] << 128) OR (A[3] << 192).

LE32(d) is exactly the first 32 squeeze bytes, hence the full target digest.
This is the fixed prefix-round complete hash, not Keccak-p's last-round
convention, raw permutation hashing, a free initial state, different padding,
or truncated output. Numeric ordering of d in the search changes no equality
test: equality means all 256 output bits agree.
The six-round transformation costs one selected-target sponge permutation
under collision-frontier-v5; surrounding construction and serialization
operations are charged separately at 1/C units per primitive word operation.

## 2. Algorithm, data structures and stopping rule

Use two arrays A and B of n records each, unrelated to H's small local lane
array. Each record is exactly three RAM words (digest,u,v), or 96 bytes.
Use one counting array Z of 2^128 RAM words. No previous collision or
input-specific advice is supplied.

Initialize fixed code/constants/workspace and zero all 6n table words and
all 2^128 counter words. For i = 0,...,n-1 draw fresh independent uniform
256-bit words u_i,v_i, compute d_i=H(u_i,v_i), and store (d_i,u_i,v_i) in
A[i]. Charge all 2n random draws and all hashes, including unsuccessful
samples. A deterministic seed expansion is not an implementation of these
ideal random-word calls.

Sort all records by the full 256-bit digest word using a two-pass
least-significant-digit radix sort with 128-bit digits and a stable
counting sort per pass. Pass 1 uses the low digit
digit1(d) = d AND (2^128 - 1) and copies A into B. Pass 2 uses the high
digit digit2(d) = d >> 128 (a logical shift on the 256-bit word, so the
result is below 2^128) and copies B back into A. Each pass with source S
and destination D performs exactly these four stages:

    Stage Z (zero):   for k = 0,...,2^128-1: Z[k] = 0.
    Stage C (count):  for i = 0,...,n-1 in increasing order:
                          k = digit(S[i].digest); Z[k] = Z[k] + 1.
    Stage P (prefix): t = 0; for k = 0,...,2^128-1 in increasing order:
                          tmp = Z[k]; Z[k] = t; t = t + tmp.
    Stage M (move):   for i = 0,...,n-1 in increasing order:
                          k = digit(S[i].digest);
                          D[Z[k]] = all three words of S[i];
                          Z[k] = Z[k] + 1.

After stage P, Z[k] equals the number of records whose digit is below k.
Stage M therefore places each record at the next free position of its digit
class, and because it processes records in increasing order, equal-digit
records keep their relative order: the pass is stable. After pass 1 the
records are ordered by the low 128 digest bits; after the stable pass 2
they are ordered by the high 128 bits, with ties retaining low-half order
from pass 1. The final array is therefore sorted by the full 256-bit
digest, and each equal-digest class is contiguous. Every loop trip count
above is a function of n alone; no count depends on the data values, so the
charged operation totals of this section are worst-case over the coins.

Scan adjacent records of the final array. When two digest words agree,
compare both message words. If the messages are identical, continue.
If they differ, recompute H for both from fresh all-zero states, check full
digest equality, and output the two 64-byte messages.
On verification failure output failure; this branch is unreachable under
exact RAM semantics. If the scan ends without a witness, output failure.
There is one complete batch and no restart or amplification.

Sorting preserves every record and makes each equal-digest class contiguous.
If a class contains distinct messages, some adjacent messages differ:
otherwise transitivity of equality would make the whole class one message.
Thus the algorithm succeeds exactly when its sample contains distinct
messages with equal target digests. Every output satisfies the exact
ordinary-collision relation by distinctness and complete-hash recomputation.

## 3. Unconditional success for this fixed function

The only randomness is the 2n independent uniform RAM words. H remains the
fixed function in section 1. For each of its N possible digest values y let

    p_y = |{m in D : H(m)=y}| / 2^512.

Some p_y may be zero, and no balance assumption is made. Independent uniform
messages produce independent outputs with this common distribution p,
because each output is a deterministic function of its respective input.
This fact asserts no independence among rounds or internal differences.

Here is the full finite-distribution bound. For q<=N let e_q(p) denote the
sum of products of probabilities over all q-element subsets of coordinates.
The probability of all q sampled outputs being distinct is q! e_q(p).
Hold all coordinates except a,b fixed, and keep a+b fixed. Then

    e_q(p) = a*b*e_(q-2)(rest) + (a+b)*e_(q-1)(rest) + e_q(rest),

where e_0=1 and impossible-size coefficients are zero.
All coefficients are nonnegative, so replacing a,b by their mean cannot
decrease e_q: their product increases at fixed sum.
To obtain a global maximum rigorously, e_q attains one on the compact
probability simplex. Among maximizers choose one minimizing sum p_i^2.
If two of its coordinates differ, averaging them does not decrease e_q
and strictly decreases the sum of squares, a contradiction.
Therefore the uniform vector maximizes e_q, including over distributions
with zero coordinates. No limiting repeated-averaging step is assumed.

Let E be the event that some two sampled digests agree. Apply this inequality
with q=n and then 1-x<=exp(-x) to each factor:

    Pr(not E) <= n! * binomial(N,n) / N^n
              = product_(j=0)^(n-1) (1-j/N)
              <= exp(-n*(n-1)/(2*N)).

Here n*(n-1)/(2*N) = (25*2^252 - 5*2^126)/2^257 = 25/32 - 5*2^-131.
The truncated exponential series with x = 25/32 gives

    exp(x) > 1 + x + x^2/2 + x^3/6 + x^4/24 + x^5/120
           = 1 + 0.78125 + 0.30517578 + 0.07947286 + 0.01552204 + 0.00242532
           > 2.1838,

with every displayed decimal a shorthand for the exact rational value, so

    exp(-25/32) < 1/2.1838 < 0.45792.

Also exp(5*2^-131) < 1 + 5*2^-130 because exp(t) < 1 + 2t for 0 < t < 1/2.
Combining,

    Pr(not E) < 0.45792 * (1 + 5*2^-130) < 0.45793,
    Pr(E) > 0.54207.

Repeated inputs do not count as ordinary collisions. Let R be the event
that any two sampled messages are equal. Each particular pair agrees with
probability 2^-512; therefore the union bound gives

    Pr(R) <= binomial(n,2)/2^512 < n^2/2^513 = 25*2^252/2^513 < 2^-255.

On E without R an equal-digest pair necessarily has distinct messages.
The scan therefore finds a valid witness. No independence between E and R
is required for

    Pr(success) >= Pr(E)-Pr(R) > 0.54207 - 2^-255 > 0.542 > 1/2.

The JSON reports the weaker lower bound 0.5, above the required 0.39.
This argument works for every fixed map D to N digests, including unbalanced
ones. It uses neither a random-oracle premise nor balanced-output,
pseudorandomness, experimental extrapolation or differential independence.
This is algorithmic success, not confidence in the proof or an AI reviewer.

## 4. 256-bit RAM implementation and complete charged time

All actual scalar values fit in a word: n, digit values below 2^128, counter
values at most n, indices, endpoints, 3*i, 6*n, and byte addresses below
2^137. The proof cardinalities N and |D| and the large total-time bounds
are not machine registers. Address record i as base+(i<<1)+i and then use
offsets 0,1,2. For byte addressing additionally shift the word address left
by five. Counter k is addressed as baseZ+k. Only the listed shifts/additions
are used; no multiplication is assumed. Each record is three individual
loads/stores, never a free bulk copy. There are no unbounded counters,
recursion stacks or multiword addresses.

Under collision-frontier-v5 the charged primitive word operations are the
256-bit loads/stores, additions/subtractions, bitwise operations,
shifts/rotations, comparisons, conditional branches and independent uniform
random-word draws listed in the model, each costing 1/C = 1/1626 units.
Code and constants are charged to memory and their one-time loading to time;
the model's primitive list defines the per-instruction charged work, and the
envelopes below overcount the explicitly enumerated operations of every loop
body.

The following finite envelopes deliberately overcount implementation
constants.

Generation, per record: two random-word draws; 25 zero stores; eight lane
extractions at one shift and one AND each; eight lane stores; two padding
constant stores; permutation call bookkeeping; four output-lane loads, three
shifts and three ORs; record-address formation and three record stores;
loop increment, compare and branch. The explicit count is at most 76
primitive operations; the envelope is 96 per record.

Radix pass, per record: stage C uses one digest load, one digit extraction
(one AND, or one shift), one counter-address addition, one counter load,
one increment, one counter store, and three loop operations, at most 9.
Stage M uses one digest load, one digit extraction, one counter-address
addition, one counter load, one destination record-address formation
(dest<<1, one addition, one base addition), one counter increment, one
counter store, three record loads, three record stores, and three loop
operations, at most 18. Together at most 27 primitive operations per record
per pass; the envelope is 32 per record per pass, hence 64n for two passes.

Counter array, both passes: stage Z uses one store, one increment and two
loop-control operations per index, at most 4*2^128 per pass. Stage P uses
one load, one store, one addition, one increment and two loop-control
operations per index, at most 6*2^128 per pass. Together at most 20*2^128
for both passes.

Scan, per inspected adjacent pair including the repeated-message check:
two digest loads, one compare, one branch, three loop operations, and on a
digest match four message-word loads, two compares and one branch. Charging
the digest-match work to every pair gives at most 15; the envelope is 16
per record, hence 16n.

The final witness recomputation, verification and output emission uses two
selected permutations and fewer than 2^14 further operations.

For H, 25 zero stores, eight lane extractions, two padding stores, one
selected permutation, four output-lane loads, three shifts/ORs and call
bookkeeping are already included in the generation envelope above. The two
random draws and three record stores also fit within it. Explicit copying
of all 25 lanes at the permutation interface, if charged in addition to
that primitive, fits this envelope. Every constant shift 64*j can be
precomputed; no variable integer multiplication is needed.

The uniform program has the fixed loop bodies specified above. Its
elementary straight-line/control code needs fewer than 2^14 instructions.
Even if the selected primitive's code storage is included, six rounds of
25 lanes require fewer than this number: fixed lane coordinates eliminate
modulo/index computations, and each round uses fewer than 1024 elementary
instructions for the displayed XOR, rotation, chi, loads and stores.
All six rounds plus the generation, radix-pass, scan and loop bodies remain
below 2^14 instructions. Five-word encoding uses 81920 words.
Constants, counters, temporary records, output and working lanes together
use fewer than 4096 further words, totaling less than 2^17 words.
Reserve the larger 2^24-byte fixed area for all of them.
Loading this code/constants and clearing the fixed area costs at most
2^30 charged operations. These are uniform data, not searched advice.

| Phase | Worst-case charged word operations |
| --- | ---: |
| Load fixed code/constants and initialize fixed workspace | 2^30 |
| Zero both n-record arrays and the counter array at initialization | 6n + 4*2^128 |
| Draw, construct, hash and store every message | 96n |
| Two radix passes, stages C and M | 64n |
| Counter zero and prefix stages, both passes | 20*2^128 |
| Scan all adjacent pairs, including repeated-message checks | 16n |
| Witness verification and output | 2^14 |

The table charges all samples, failed comparisons, both radix passes and
verification regardless of success. There is no hidden restart cost.
These are worst-case bounds for one run, hence also bound expected time.
Total ordinary word operations, summing every phase above:

    W <= 96n + 64n + 16n + 6n + (4*2^128 + 20*2^128) + 2^30 + 2^14
      = 182n + 24*2^128 + 2^30 + 2^14
      = 227.5*2^128 + 24*2^128 + 2^30 + 2^14
      < 251.5*2^128 + 2^31,

using 2^30 + 2^14 < 2^31.

The number of selected six-round permutations is

    H = n + 2,

one per sampled message plus the two final verification recomputations.
Under collision-frontier-v5 the total charged time is T = H + W/C with
C = 1626:

    W/1626 < (251.5*2^128)/1626 + 2^31/1626
           < 0.154675*2^128 + 2^21,

because 251.5/1626 < 0.154675 (equivalently 251.5 < 0.154675*1626 = 251.502)
and 2^31/1626 < 2^31/2^10 = 2^21. Therefore

    T < 5*2^126 + 2 + 0.154675*2^128 + 2^21
      = 1.25*2^128 + 0.154675*2^128 + 2^21 + 2
      = 1.404675*2^128 + 2^21 + 2
      < 1.40468*2^128,

because 2^21 + 2 < 2^22 < 0.000005*2^128. Finally 1.40468^2 = 1.97313 < 2,
so 1.40468 < 2^(1/2) and

    T < 2^(1/2) * 2^128 = 2^128.5.

The organizer unit is named `target-compressions`: one selected six-round
sponge permutation costs one unit and each other listed primitive word
operation costs 1/1626 units. T is not merely the number of hashes.
Preprocessing is the fixed initialization, array zeroing and counter
initialization, already included in T:

    P <= 2^30 + 6n + (4*2^128 + 20*2^128) = 2^30 + 31.5*2^128 < 2^133,

because 31.5*2^128 < 32*2^128 = 2^133 and 2^30 < 0.5*2^128.

No earlier search chooses messages, favorable coins, collisions, parameters
or advice. No failed trials or preparation steps are left outside T.

## 5. Memory, data and interpretation of the claim

Each array occupies 3n words = 96n bytes, including every retained 64-byte
message and 32-byte full digest. Both arrays total 6n words = 192n bytes.
The counting array occupies 2^128 words = 2^133 bytes.
Retained random words are the stored message words, not another allocation.
Uniform code/constants, copying temporaries, state, counters, output and
other fixed data all fit in the 2^24-byte area justified above.
There are no additional table copies, external storage, recursive stacks,
compressed messages or retained randomness outside those areas.

    M <= 192n + 2^133 + 2^24
      = 240*2^128 + 32*2^128 + 2^24
      = 272*2^128 + 2^24
      < 2^137 bytes,

because 272*2^128 + 2^24 < 272*2^128 + 240*2^128 = 512*2^128 = 2^137.
This is within 256-bit byte or word addressing. It is not constant memory
or a statement of physical practicality.

The JSON fields have these explicit units and meanings:

* `time_log2: 128.5` means T < 2^128.5 total charged operations.
* `memory_log2_bytes: 137` means M < 2^137 peak bytes, including code.
* `preprocessing_log2: 133` means P < 2^133 charged setup operations,
  already included in T, not an extra omitted phase.
* `success_probability: 0.5` is a proved one-batch lower bound.
* `nonuniform_advice_log2_bytes: 0` bounds advice by 2^0 bytes.
  Actual nonuniform advice is zero bytes. The schema cannot encode log2(0),
  so the nonnegative value 0 is a conservative upper bound, not a hidden
  precomputed collision. Uniform program/constants are charged above.

Resource logarithms describe conservative upper bounds; success describes
a lower bound. The proposed scalar is 128.5. No scalar improvement or Pareto
dominance over an established attack is claimed.

## 6. Evidence, heuristic disclosures and limitations

All needed evidence is the self-contained analytic argument in sections
1 through 5. The heuristic list is empty: every material probability and
resource premise is discharged for the fixed target and stipulated RAM.
Fresh independent uniform random words are an explicit model primitive,
not an empirical assumption about a device or deterministic PRNG.
No smaller-round experiment or sibling package is needed for this proof.
There are no toy-to-full-size extrapolations or unexplained cryptanalytic
premises, and no external link must be fetched to assess the argument.

The certificate manifest is valid and empty. No computed collision or
certificate is claimed. No experiment is declared, and no candidate
program has been executed. Finite sampling would not establish the costs
or success of this infeasible run and is not used as evidence.
This is an analytic upper bound in the abstract model, not a measured
practical attack.

`ready` means complete and available for review. Qualification and score
emission require organizer review of this exact package.
Exploratory qualification is `plausible_not_refuted`; rigorous qualification
is `ai_rigor_qualified`. Neither is mathematical proof or human acceptance.
This candidate does not assert a review outcome, trusted score or successful
Yukon baseline import.
