# A 32-step SHA-256 ordinary collision from the 2026/1120 36-step local collision

This package describes a classical cryptanalytic collision attack on SHA-256 reduced
to its first 32 compression rounds (target profile `sha256-r32-prefix-v1`, cost model
`collision-frontier-v5`). The claimed charged time is
at most `2^53.0` target-compression units for a fixed, pre-declared work budget whose
worst-case charged work is `2^52.40` (Section 7.5) and whose success probability is at
least `0.503` (Section 7.7), with about `2^26` bytes of online memory. Every compression that the attack evaluates in full is charged one unit;
partial step evaluations are charged by their primitive operations at `1/2224`. A
fully conservative variant that charges every uncontrolled-part candidate as a whole
compression costs `2^57.9` under the same fixed budget (Section 7.6) and is reported as
a fallback.

The construction is structural, not generic: it reuses without change the 36-step
SHA-256 local collision and differential characteristic of Li, Zhang, Li, Liu, Qian
and Zhu, "Pushing Collision Attacks on SHA-2 to 39 Steps" (IACR ePrint 2026/1120,
Tables 9 and 10), together with the memory-efficient two-block conversion of that
work (CRYPTO 2026 framework of Li et al., and Li, Liu, Wang, ePrint 2024/349). The
central facts, proved and measured below, are (i) the whole characteristic lives in
step indices `0..30`, so a 32-step compression enforces exactly its conditions and no
others, and (ii) the state of both messages up to step 15 and the set of usable tail
words `(W14, W15)` do not depend on the chaining value, which allows the uncontrolled
part to be scanned with a few word operations per candidate. The algorithm is stated
with a fixed budget (a fixed number of first-block trials, a cap on scanned blocks, a
cap on continued survivors); the charged work is the worst case over that budget and
the success probability is bounded below for that same budget.

The required reference identifier `sha256-r32-nominal-v2` names the organizer display
reference only. The claimed scalar `53.0` is below the nominal exponent `128`; this
package therefore does claim a cryptanalytic advantage over the generic birthday
bound for this target, and states the construction, the cost accounting and the
evidence that support it.

## 1. Exact target

The target is `sha256-r32-prefix-v1` (FIPS 180-4 SHA-256 restricted to rounds
`0..31`), exactly as defined by `verifier/hash_functions.py:digest` with
`algorithm="sha256"`, `rounds=32`:

- Standard fixed initial value, used once at the start of the complete message:
  `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`.
- FIPS 180-4 padding: append `0x80`, then zero bytes to length `56 (mod 64)`, then
  the 64-bit big-endian original bit length. Padding is applied to the complete
  message and produces one or more additional full blocks.
- Every 64-byte block is processed by the reduced compression `C32`: parse into
  big-endian 32-bit words `W[0..15]`; expand for `t = 16..31`
  `W[t] = W[t-16] + s0(W[t-15]) + W[t-7] + s1(W[t-2]) (mod 2^32)`,
  `s0(x)=ROTR7(x)^ROTR18(x)^SHR3(x)`, `s1(x)=ROTR17(x)^ROTR19(x)^SHR10(x)`; run rounds
  `t = 0..31` of the standard step function with the standard constants `K_t` at
  their original indices; then feed-forward, adding each of the eight working words
  to the incoming chaining word modulo `2^32`.
- The digest is all eight 32-bit chaining words, big-endian, no truncation.

A pair `(m, m')` qualifies when `m` and `m'` are distinct finite byte strings (bit
length `< 2^64`) whose complete `sha256-r32` digests are byte-for-byte equal. There is
no chosen IV, free-start state, compression-only relation, near-collision,
truncation, or round renumbering. Rounds `0..31` are executed on every padded block,
including the padding block; those compressions are counted in Section 7.

Throughout, `A_i` and `E_i` denote the two state words produced at step `i` in the
alternate description used by ePrint 2026/1120 Section 2:
`E_i = A_{i-4} + E_{i-4} + Sig1(E_{i-1}) + IF(E_{i-1},E_{i-2},E_{i-3}) + K_i + W_i` and
`A_i = E_i - A_{i-4} + Sig0(A_{i-1}) + MAJ(A_{i-1},A_{i-2},A_{i-3})`, with the incoming
chaining value written `(A_{-1},A_{-2},A_{-3},A_{-4},E_{-1},E_{-2},E_{-3},E_{-4})`, i.e.
`A_{-1}=a, A_{-2}=b, A_{-3}=c, A_{-4}=d, E_{-1}=e, E_{-2}=f, E_{-3}=g, E_{-4}=h` in FIPS
register names. `Sig0(x)=ROTR2^ROTR13^ROTR22`, `Sig1(x)=ROTR6^ROTR11^ROTR25`,
`IF(x,y,z)=(x&y)^(~x&z)`, `MAJ(x,y,z)=(x&y)^(x&z)^(y&z)`. This is algebraically
identical to the FIPS recurrence (`E_i` is the new `e` register and `A_i` the new
`a` register); it only renames the eight registers to two indexed families so that the
characteristic tables are legible. Primed symbols (`A'_i`, `W'_i`, ...) refer to the
second message of a pair.

## 2. Result and relation to prior work

No ordinary-collision attack at exactly 32 steps has been published; the only prior
result touching 32 steps is the 2011 semi-free-start collision of Mendel, Nad and
Schlaffer. Published ordinary collisions are practical at 31 steps (Li, Liu, Wang,
ASIACRYPT 2024), practical at 35 and 36 steps and theoretical (`2^79.1`, `2^104.3`)
at 37 and 38 steps (ePrint 2026/1120). Costs are not monotone in the step count
because each result uses a purpose-built local collision.

This package keeps the 2026/1120 36-step local collision in place. Its message
difference pattern is (ePrint 2026/1120 Section 4.1)

```
nonzero message-word differences only in W5, W6, W7, W8, W9, W13, W14, W21, W23.
```

Section 5 shows that this local collision is valid without modification at 32 steps
and that 32-step evaluation enforces exactly the characteristic's conditions. Section 7
derives the cost from the condition counts of Tables 9 and 10 (reproduced here,
Section 4.3), one measured first-block density, one measured conditional-probability
profile of the uncontrolled part, and an explicit operation ledger.

## 3. Notation for the characteristic tables

From ePrint 2026/1120 Section 2.1, a signed difference over the 32 bit positions of a
word uses the alphabet `=` (both bits equal, unconstrained), `0` (both bits `0`),
`1` (both bits `1`), `n` and `u` (the bits differ). The convention realised by the
published pair of Table 2 (checked in Section 4.4 on every active row) is: `n` marks
`x[i]=1, x'[i]=0` and `u` marks `x[i]=0, x'[i]=1`. Bit `0` is the least significant
bit; the tables print bit `31` (most significant) on the left. `n` and `u` are the bits
that differ; `0` and `1` are value conditions without a difference; `=` is free.

The printed tables also contain a `+` glyph in the `∇E` column. Section 4.3 shows
that in the uncontrolled rows it sits exactly at the bit positions of the two-bit
relations listed in Table 10 (`E15[24]=E16[24]`, `E15[15]=E16[15]` for row 16); it
marks a position that carries a listed two-bit condition and is not an additional
condition. In the dense rows (`i <= 15`) the `+` positions are handled by the SAT
solver together with all other dense-part conditions and never enter the cost.

"Controlled" conditions are those enforced deterministically during message
construction, on the dense steps `0..15`. "Uncontrolled" conditions are those on
state and message words at steps `i >= 16`; their number is `c_unc` and they are
satisfied probabilistically.

## 4. The differential characteristic

### 4.1 Table 9 of ePrint 2026/1120, rows -4..31 (verbatim)

Each row lists `∇A_i`, `∇E_i`, `∇W_i` (32 glyphs each, bit 31 left). Rows `32..35` of
the published table are all `=` and are omitted because they do not exist at 32
steps; rows `24..31` are all `=` (no difference and no condition).

```
  i  ∇A_i                              ∇E_i                              ∇W_i
 -4  ================================  ================================                                  
 -3  ================================  ================================                                  
 -2  ================================  ================================                                  
 -1  ================================  ================================                                  
  0  ================================  ================================  ================================
  1  ================================  ================================  ================================
  2  ================================  ================================  ================================
  3  ================================  ==1=============================  ================================
  4  ================================  ==0==1==0=00++======+======1====  ================================
  5  nuu=============================  ==n==0==0011++1===0=+====1=0==11  ==n=============================
  6  =====u===n=====u=====n==n==n====  11u0=n11n1uuuu101000n1==100n0100  =====n===u==========n===========
  7  ================================  10110111nu0100u=11u10101=n001=uu  ==n=============================
  8  ================================  =10==11=01000101==0001==10=1==00  =======u=======u===n====u=1=u=n=
  9  ==================n=u===========  1nu110001001==00==0n0n==01110110  ============u=======nn==========
 10  ====n=u===n===========u====u==n=  0u0011n1un110+1u00u11u11n010101n  ================================
 11  =nu=============================  =11nu11011un0+000011u0001u=u0uu0  ================================
 12  ====n=========n=n=======u==u====  1011u=01001nuu+0u11010101001=101  ================================
 13  =======nn=======u===============  =1=0=10==00111+11==1u=1=n0=0=01=  =====n===n==========n===========
 14  ================================  =u==00===u=011u11==n1=n=1==+====  ==u=============================
 15  ==u=============================  =0=====+00===11=+==01=0=0==+====  ================================
 16  ================================  =0=====+01===n1=+==1==1===0u====  ================================
 17  ================================  ==10===nn====1==u===000===11==1=  ================================
 18  ================================  ==1====00====1==0==========1====  ================================
 19  ================================  ==u====10=======1===10==========  ================================
 20  ================================  ==0=============================  ================================
 21  ================================  ==1=============================  =====0=uu=====1=n=0=============
 22  ================================  ================================  ================================
 23  ================================  ================================  ==n=============================
 24  ================================  ================================  ================================
 25  ================================  ================================  ================================
 26  ================================  ================================  ================================
 27  ================================  ================================  ================================
 28  ================================  ================================  ================================
 29  ================================  ================================  ================================
 30  ================================  ================================  ================================
 31  ================================  ================================  ================================
```

### 4.2 Table 10 of ePrint 2026/1120 (two-bit conditions), verbatim

`X[a]=Y[b]` is an equality condition on two bits, `X[a]!=Y[b]` an inequality; the
right column is the probability with which a random value satisfies the row.

```
A16 : A14[29]=A16[29]                                                   2^-1
A17 : A16[29]=A17[29]                                                   2^-1
E16 : E16[0]!=E16[13], E15[15]=E16[15], E15[24]=E16[24]                 2^-3
E17 : E17[6]!=E17[19], E17[2]=E17[20]                                   2^-2
E19 : E19[2]=E19[16]                                                    2^-1
W5  : W5[1]!=W5[12], W5[8]!=W5[25], W5[18]!=W5[14]                      2^-3
W6  : W6[0]!=W6[28], W6[9]=W6[30], W6[1]!=W6[18]                        2^-3
W7  : W7[1]!=W7[12], W7[8]=W7[25], W7[14]!=W7[18]                       2^-3
W8  : W8[14]=W8[31], W8[18]=W8[22], W8[20]=W8[31], W8[9]=W8[13],
      W8[8]=W8[23], W8[11]=W8[22]                                       2^-6
W21 : W21[31]=W21[1], W21[30]=W21[0], W21[16]=W21[25], W21[14]=W21[21]  2^-4
W23 : W23[4]=W23[6], W23[22]!=W23[31], W23[20]=W23[27]                  2^-3
```

### 4.3 Condition counts per row (reproduced from Tables 9 and 10)

For each row, the columns give `diff/value/plus` glyph counts of `∇A_i`, `∇E_i`,
`∇W_i` (number of `n`/`u`, number of `0`/`1`, number of `+`) and the number of Table
10 two-bit conditions attached to the row.

```
  i   A(d/v/+)  E(d/v/+)  W(d/v/+)  two-bit
  0   0/0/0     0/0/0     0/0/0       0
  1   0/0/0     0/0/0     0/0/0       0
  2   0/0/0     0/0/0     0/0/0       0
  3   0/0/0     0/1/0     0/0/0       0
  4   0/0/0     0/6/3     0/0/0       0
  5   3/0/0     1/11/3    1/0/0       3
  6   6/0/0     9/20/0    3/0/0       3
  7   0/0/0     7/22/0    1/0/0       3
  8   0/0/0     0/21/0    6/1/0       6
  9   2/0/0     4/22/0    3/0/0       0
 10   6/0/0     9/22/1    0/0/0       0
 11   2/0/0     9/20/1    0/0/0       0
 12   5/0/0     5/24/1    0/0/0       0
 13   3/0/0     2/17/1    3/0/0       0
 14   0/0/0     5/9/1     1/0/0       0
 15   1/0/0     0/9/3     0/0/0       0
 16   0/0/0     2/7/2     0/0/0       4
 17   0/0/0     3/9/0     0/0/0       3
 18   0/0/0     0/6/0     0/0/0       0
 19   0/0/0     1/5/0     0/0/0       1
 20   0/0/0     0/1/0     0/0/0       0
 21   0/0/0     0/1/0     3/3/0       4
 22   0/0/0     0/0/0     0/0/0       0
 23   0/0/0     0/0/0     1/0/0       3
```

Sums that the cost uses:

- Uncontrolled conditions `c_unc` (all conditions on `(A_i, E_i, W_i)` for
  `i >= 16`): direct `n/u/0/1` glyphs in rows `16..23` = `42` (state rows `16..21`:
  `9+12+6+6+1+1 = 35`; `∇W21`: `6`; `∇W23`: `1`) plus the Table 10 two-bit
  conditions at `i >= 16` = `15` (`A16:1, A17:1, E16:3, E17:2, E19:1, W21:4, W23:3`).
  Total `c_unc = 57`, exactly the figure of ePrint 2026/1120 Section 4.2. Counting the
  two `+` glyphs of row 16 as further conditions would double count the `E15/E16`
  relations already in the 15.
- First-block conditions `c_cv`: `E3` has one value condition (`E3[29]=1`); `∇W5`
  has one difference bit and three two-bit conditions; `∇W6` three and three; `∇W7`
  one and three: `1+4+6+4 = 15`, the paper's count. Section 7.2 measures the joint
  probability of these 15 conditions at 32 steps as `2^-14.03`; the missing bit is
  explained there.
- Rows 14 and 15 carry `29` glyph conditions (including four `+`); the published
  attack reports `2^20` usable values of `(W14, W15)` after all conditions that can be
  imposed on them (Section 7.3).

### 4.4 The verified conforming pair at 32 steps

The published colliding blocks of ePrint 2026/1120 Table 2 are `M0`, `M1`, `M1'`.
With `CV1 = C36(IV, M0)` (the chaining value the pair was built for)

```
CV1 = a7214391 72d495bd 1d78c430 edfda8bc 725cf553 506e84f8 44d8d7ad 92c65d9d
M1  = 09abc425 0e8b8121 85808046 fadb1bca 394268e3 b9dfbd34 ae156845 74169a81
      1ea03337 a3210f16 79b82017 91059d10 97294bab 65ceec9c 89c67ae2 ac5eb7f9
M1' = 09abc425 0e8b8121 85808046 fadb1bca 394268e3 99dfbd34 aa556045 54169a81
      1fa123bd a3290316 79b82017 91059d10 97294bab 618ee49c a9c67ae2 ac5eb7f9
```

the trusted reference gives `C32(CV1, M1) == C32(CV1, M1')` on all 256 bits (and the
same for every step count `24..36`; Section 5). The signed differences of the states
and expanded words of this pair at 32 steps, computed from `CV1` with the exact
step function (file `eng/results/005-conditions-r32/pair32.json` of the lab, columns
as in Table 9, followed by the expanded words `W_i`, `W'_i` in hex), are:

```
  i  ∇A_i                              ∇E_i                              ∇W_i                              W_i      W'_i
  0  ================================  ================================  ================================   09abc425 09abc425
  1  ================================  ================================  ================================   0e8b8121 0e8b8121
  2  ================================  ================================  ================================   85808046 85808046
  3  ================================  ================================  ================================   fadb1bca fadb1bca
  4  ================================  ================================  ================================   394268e3 394268e3
  5  nuu=============================  ==n=============================  ==n=============================   b9dfbd34 99dfbd34
  6  =====u===n=====u=====n==n==n====  ==u==n==n=uuuu======n======n====  =====n===u==========n===========   ae156845 aa556045
  7  ================================  ========nu====u===u======n====uu  ==n=============================   74169a81 54169a81
  8  ================================  ================================  =======u=======u===n====u===u=n=   1ea03337 1fa123bd
  9  ==================n=u===========  =nu================n=n==========  ============u=======nn==========   a3210f16 a3290316
 10  ====n=u===n===========u====u==n=  =u====n=un=====u==u==u==n======n  ================================   79b82017 79b82017
 11  =nu=============================  ===nu=====un========u====u=u=uu=  ================================   91059d10 91059d10
 12  ====n=========n=n=======u==u====  ====u======nuu==u===============  ================================   97294bab 97294bab
 13  =======nn=======u===============  ====================u===n=======  =====n===n==========n===========   65ceec9c 618ee49c
 14  ================================  =u=======u====u====n==n=========  ==u=============================   89c67ae2 a9c67ae2
 15  ==u=============================  ================================  ================================   ac5eb7f9 ac5eb7f9
 16  ================================  =============n=============u====  ================================   42605c04 42605c04
 17  ================================  =======nn=======u===============  ================================   d31745a9 d31745a9
 18  ================================  ================================  ================================   8874bab9 8874bab9
 19  ================================  ==u=============================  ================================   37bb854a 37bb854a
 20  ================================  ================================  ================================   fa40a444 fa40a444
 21  ================================  ================================  =======uu=======n===============   ba37d83e bbb7583e
 22  ================================  ================================  ================================   4bd335df 4bd335df
 23  ================================  ================================  ==n=============================   2ed17fd8 0ed17fd8
 24  ================================  ================================  ================================   68e5fc72 68e5fc72
 25  ================================  ================================  ================================   e5741ae8 e5741ae8
 26  ================================  ================================  ================================   4767824b 4767824b
 27  ================================  ================================  ================================   3078128e 3078128e
 28  ================================  ================================  ================================   12338fe1 12338fe1
 29  ================================  ================================  ================================   0750c48a 0750c48a
 30  ================================  ================================  ================================   b9cd22fd b9cd22fd
 31  ================================  ================================  ================================   a7e4277e a7e4277e
```

Checks performed on this pair (script `final/char_analysis.py`): every `n`/`u` glyph
of Table 9 rows `0..31` for `A`, `E` and `W` coincides with the pair's signed
difference; every `0`/`1` glyph of the `∇W` rows holds; `E3[29]=1` holds; all 33
two-bit conditions of Table 10 hold. The characteristic and the pair therefore
describe the same object, and `n`/`u` are read with the convention of Section 3.

A second, independent published instance is the 36-step semi-free-start pair of
ePrint 2026/1120 Table 11 (chaining value `414e392b c207f5e7 56e6b04d 3b8b9fc2
54288441 10492883 8c7b95bb da1be99e`, message words with differences in
`W5,W6,W7,W8,W9,W13,W14`). With the trusted reference it also collides at every step
count `24..36`, including 32.

### 4.5 The message-expansion cancellations

Under the characteristic the expanded words `W16, W17, W18, W19, W20, W22, W24..W31`
carry no difference. For `W17, W18, W19, W26, W27, W31` all expansion inputs are
difference-free, so this is automatic. The remaining seven are two-operand
cancellations of the modular differences of two active inputs (the other two inputs
are difference-free); because `s0` and `s1` are GF(2)-linear, the XOR difference of
`s0(W_j)` or `s1(W_j)` is fixed by `∇W_j`. From the pair of Section 4.4:

```
word  operand a   XOR diff  (HW)   operand b    XOR diff  (HW)   P[cancel], uniform   P[cancel | signs of a fixed]
W16  W9          00080c00 (HW 3)   sigma1(W14)  00081400 (HW 3)        4/64 = 2^-4      2^-3
W20  sigma0(W5)  04400800 (HW 3)   W13          04400800 (HW 3)        8/64 = 2^-3      2^-3
W22  W6          04400800 (HW 3)   sigma0(W7)   04400800 (HW 3)        8/64 = 2^-3      2^-3
W24  W8          0101108a (HW 6)   sigma0(W9)   0301119a (HW 9)    64/32768 = 2^-9      2^-9
W25  W9          00080c00 (HW 3)   sigma1(W23)  00081400 (HW 3)        4/64 = 2^-4      2^-3
W29  W13         04400800 (HW 3)   sigma0(W14)  04400800 (HW 3)        8/64 = 2^-3      2^-3
W30  W14         20000000 (HW 1)   W23          20000000 (HW 1)         2/4 = 2^-1      2^-1
```

`P[cancel], uniform` is the exact probability, over uniform random operand values
with the given XOR input differences, that the two modular differences cancel (the
sum has XOR output difference `0`); it is obtained by enumerating all sign patterns
of the difference bits. The last column fixes the signs of operand `a` to those of the
characteristic, which is the situation inside the attack (the dense part fixes them),
and reproduces the corresponding Table 10 counts (`W5: 3` for `W20`, `W7: 3` for
`W22`, `W23: 3` for `W25`) and the measured `2^-3` selectivity of the `W16`
cancellation on `W14` (Section 7.3). The `W24` cancellation depends on `W8` and `W9`,
which belong to the fixed dense part; its six Table 10 conditions are solved by the
SAT solver and never enter the online cost. The six other cancellations are declared
as organizer-run `addition-xor-sampled-v1` experiments with exactly these input
differences (Section 9).

## 5. Validity of the characteristic at 32 steps

**(a) Structural.** The characteristic's entire nonzero activity is confined to step
indices `<= 30`: the state difference `(∇A_i, ∇E_i)` is zero for `i >= 20` and the
last state condition is at `E21`; the last message word with a difference is `W23`;
the expansion cancellations (Section 4.5) are at indices `16, 20, 22, 24, 25, 28, 29,
30`. A 32-step compression computes `W0..W31` and runs steps `0..31`; therefore every
condition of Tables 9 and 10 is present and enforced at 32 steps, and the only extra
expanded word, `W31 = W15 + s0(W16) + W24 + s1(W29)`, has four difference-free inputs
and is difference-free automatically. Conversely, at 36 steps the expanded words
`W32..W35` are also difference-free automatically (their inputs `W16..W33` are all
difference-free), so the 36-step and 32-step condition sets coincide: the 32-step
attack enforces exactly the published conditions, no more and no fewer. The difference
in `E19` is cancelled at step 23 by `∇W23` (the last active word), the difference in
`E17` at step 21 by `∇W21`; from step 24 on both messages run on identical states
and identical words `W24..W31`, so the feed-forward outputs are equal.

**(b) Measured.** With the trusted reference (`verifier/hash_functions.py:_compress`),
from `CV1 = C36(IV, M0)` the Table 2 second-block pair collides at every step count
`24..36`, including 32 (all 256 bits); the Table 11 semi-free-start pair collides at
`24..36` as well. Taking instead `CV1' = C32(IV, M0)`, the naive 32-step first block
of the same `M0`, the pair collides at no step count: an ordinary 32-step collision
needs a first block whose 32-step chaining value satisfies the first-block conditions,
which is the charged block-1 search of Section 6.

## 6. The attack algorithm

The attack is the memory-efficient two-block conversion of ePrint 2026/1120 Section
4.2 instantiated at 32 steps, with one additional observation (Step 3) that the
published algorithm does not need but that this cost model rewards. The colliding
messages are `m = B0 || M1` and `m' = B0 || M1'`, 128 bytes each; the target's padding
rule appends a common third block. Write `CV1 = C32(IV, B0) = (A_{-1},...,E_{-4})`.

**Step 1 (preprocessing, once).** Find one valid assignment of the dense part: the
expanded words `W8..W13` and the state words `A_0..A_13`, `E_4..E_13` of both messages,
consistent with the step function and with all Table 9/10 conditions at steps
`0..15` (including the `W8` conditions of Table 10). This is a SAT problem; the
published 36-step instance took about `2^39.8` compression-equivalents and the 32-step
instance is the same problem. (The dense part of the verified pair of Section 4.4 is
one such assignment and could be reused; the cost below charges a fresh solve.)

**Step 1' (preprocessing, once): the tail table `V`.** The state words at steps 14
and 15 of both messages depend only on the dense part and on `(W14, W15)`:
`E14 = A10 + E10 + Sig1(E13) + IF(E13,E12,E11) + K14 + W14`, `A14 = E14 - A10 +
Sig0(A13) + MAJ(A13,A12,A11)`, likewise `E15, A15`, and the primed words with
`W'14 = W14 + (W'14 - W14)` fixed by `∇W14` and `W'15 = W15`. The table `V` is the set
of all `(W14, W15)` in `{0,1}^32 x {0,1}^32` satisfying the following explicit
conditions, none of which involves the chaining value:

- (V1) `(W14, W'14)`, `(E14, E'14)`, `(A14, A'14)` satisfy every glyph of Table 9 row 14
  (`n`/`u` difference bits, `0`/`1` value bits, equality elsewhere);
- (V2) `∇W16 = 0`: `W9 + s1(W14) = W'9 + s1(W'14) (mod 2^32)` (with `W9, W'9` from the
  dense part); and `∇W29 = 0`: `W13 + s0(W14) = W'13 + s0(W'14)`;
- (V3) the modular differences `E'15 - E15` and `A'15 - A15` computed from step 15 with
  `W15 = 0` equal those of the characteristic (`0` and the value realised by the
  verified pair); these do not depend on `W15` because `W15` enters `E15` and `E'15`
  identically;
- (V4) `(E15, E'15)`, `(A15, A'15)` satisfy every glyph of Table 9 row 15;
- (V5) the modular differences `E'16 - E16` and `A'16 - A16` computed from step 16 with
  `W16 = 0` equal those of the characteristic; these do not depend on `W16` (which is
  common to both messages by (V2)) nor on the chaining value.

`V` is enumerated exactly once: all `2^32` values of `W14` are tested against (V1)-(V3)
(one step evaluation each; `32` values survive for the verified pair's dense part,
Section 7.3), then all `2^32` values of `W15` for each surviving `W14` against (V4)-(V5)
(two step evaluations each). Each entry stores `s1(W14)`, `s1(W15)`,
`base16 = A12 + E12 + Sig1(E15) + IF(E15,E14,E13) + K16`, `base'16`, and
`off16 = -A12 + Sig0(A15) + MAJ(A15,A14,A13)`, `off'16` (six 32-bit fields, one 256-bit
word per entry). Its size is `|V| = K`; the measurement of Section 7.3 gives
`K = 2^21.0` (two runs: `2^20.98`, `2^21.12`); the budget below uses `K <= K_max =
2^21.2` for the work bound and only the product `K * p_c` (Section 7.4) for the success
bound. Enumeration cost: at most `2^32 * 2 * 54 + 32 * 2^32 * 4 * 54` operations, i.e.
below `2^35` compression units, part of the charged preprocessing.

**Fixed budget.** The following quantities are fixed before the run and never adapted:

```
q     = 2^-14.1        lower bound on the first-block acceptance probability (Section 7.2)
y     = 2^-37.2        lower bound on the per-accepted-block collision yield K * p_c (Section 7.4)
M     = ceil(0.70 / y) = 2^36.685   cap on the number of accepted first blocks that are scanned
N_b   = ceil(M * (1 + 2^-10) / q) = 2^50.787   number of first-block trials (all charged)
S_max = 2 * M * K_max * 2^-12.4 = 2^46.5       cap on step-16 survivors that are continued
```

**Step 2 (block-1 trials, exactly `N_b` of them).** For `t = 1, ..., N_b`: draw a fresh
uniform 64-byte block `B0_t` (two `UniformWord` draws) and compute `CV1 = C32(IV, B0_t)`
(one full compression, charged one unit). Check on the fly, from `CV1` and the fixed
`A_0..A_3`, `E_4..E_7`, whether the 15 first-block conditions hold, in the order `E3`
(reject with probability `1/2`), then `W7`, `W6`, `W5`:

```
E3 = A3 + A_{-1} - Sig0(A2) - MAJ(A2,A1,A0)          condition E3[29] = 1
E2 = A2 + A_{-2} - Sig0(A1) - MAJ(A1,A0,A_{-1})
E1 = A1 + A_{-3} - Sig0(A0) - MAJ(A0,A_{-1},A_{-2})
W7 = E7 - A3 - E3 - Sig1(E6) - IF(E6,E5,E4) - K7      W'7 = E'7 - A3 - E3 - Sig1(E'6) - IF(E'6,E'5,E4) - K7
W6 = E6 - A2 - E2 - Sig1(E5) - IF(E5,E4,E3) - K6      W'6 = E'6 - A2 - E2 - Sig1(E'5) - IF(E'5,E4,E3) - K6
W5 = E5 - A1 - E1 - Sig1(E4) - IF(E4,E3,E2) - K5      W'5 = E'5 - A1 - E1 - Sig1(E4) - IF(E4,E3,E2) - K5
```

The conditions are: the signed difference of `(W7, W'7)`, `(W6, W'6)`, `(W5, W'5)`
equals the `∇W7`, `∇W6`, `∇W5` row of Table 9, and the nine two-bit conditions of
Table 10 on `W5, W6, W7` hold. A block that passes is "accepted". For each accepted
block, as long as fewer than `M` blocks have been accepted so far, the remaining early
words follow by inversion (`W0..W4` common to both messages):

```
E0 = A0 + A_{-4} - Sig0(A_{-1}) - MAJ(A_{-1},A_{-2},A_{-3})
W4 = E4 - A0 - E0 - Sig1(E3) - IF(E3,E2,E1) - K4
W3 = E3 - A_{-1} - E_{-1} - Sig1(E2) - IF(E2,E1,E0) - K3
W2 = E2 - A_{-2} - E_{-2} - Sig1(E1) - IF(E1,E0,E_{-1}) - K2
W1 = E1 - A_{-3} - E_{-3} - Sig1(E0) - IF(E0,E_{-1},E_{-2}) - K1
W0 = E0 - A_{-4} - E_{-4} - Sig1(E_{-1}) - IF(E_{-1},E_{-2},E_{-3}) - K0
```

so `W0..W13` of the second block are fixed for this `B0`; the constants
`c16 = W0 + s0(W1) + W9`, `c17 = W1 + s0(W2) + W10`, `c18 = W2 + s0(W3) + W11`,
`c19 = W3 + s0(W4) + W12` and their primed versions are computed, and Step 3 is run
for this block. Accepted blocks beyond the `M`-th are ignored. All `N_b` trials are
charged whether or not they are accepted, and whether or not a collision has already
been found (the run may stop early at a collision; the work bound charges the full
budget).

**Step 3 (tail scan of one accepted block).** For each entry `j` of `V` (all `K`
entries, in table order): `W16 = c16 + s1(W14_j)` (common to both messages, because
`∇W16 = 0`); `E16 = base16_j + W16`, `E'16 = base'16_j + W16`, `A16 = E16 + off16_j`,
`A'16 = E'16 + off'16_j`. Test the row-16 conditions: the XOR of `(E16, E'16)` equals the
`∇E16` difference mask with the signs of Table 9; the seven `0/1` value bits of `∇E16`;
`A16 = A'16`; and the Table 10 relations `E16[0]!=E16[13]`, `E15[15]=E16[15]`,
`E15[24]=E16[24]`, `A14[29]=A16[29]` (the last three are value conditions on `E16`,
`A16` because `E15`, `A14` are fixed per entry). A candidate that passes is a "survivor".
As long as fewer than `S_max` survivors have been continued in the whole run, a survivor
is continued: `W17 = c17 + s1(W15_j)` and step 17 (`15` conditions), then steps 18 (`6`),
19 (`7`), 20 (`1`), 21 (`1`), with the expanded words `W18..W23` computed from the fixed
words and the candidate; the `W21` conditions (`6` glyphs and `4` two-bit) and `W23`
conditions (`1` glyph and `3` two-bit) are tested when those words are formed. A
candidate that passes all `57` uncontrolled conditions yields the second blocks
`M1 = (W0..W15)` and `M1' = (W'0..W'15)`; by Section 5 the pair then collides at 32
steps and the run outputs `(B0 || M1, B0 || M1')`. Survivors beyond the `S_max`-th are
discarded. If the budget is exhausted without a collision, the run outputs failure.

**Collision check and message formatting.** For a surviving `(B0, M1, M1')` recompute
both complete `sha256-r32` digests with the reference and confirm equality and
`m != m'`. The two 128-byte messages receive a common padding block `P` (`0x80`,
zeros, the 64-bit length `1024`); since the chaining values after block 2 are equal
and `C32(., P)` is a common function, the digests are equal. The padding-block
compression and the final digests are `O(1)` compressions and are counted in Section 7.

## 7. Cost accounting (target compressions)

All costs are in `sha256-r32` compression units: one full `C32` costs `1`; every
other 256-bit RAM primitive (load/store, add/sub, and/or/xor/not, shift/rotate,
compare, branch, random word) costs `1/C`, `C = 2224`. The organizer convention behind
`C` (script `scripts/reference_operation_costs.py`, reproduced here by instrumenting
the reference for round counts `14..32`) prices one state-update step at `54`
operations and one expanded message word at `30` (rotations as shift, shift, or, mask).
No compression evaluated in full is ever charged below one unit, and no unit-priced
compression is additionally charged per operation. The work bound is the worst case
over the fixed budget of Section 6: every one of the `N_b` first-block trials, the full
table scan for each of at most `M` accepted blocks, and the full continuation for each
of at most `S_max` survivors are charged regardless of the random outcomes; no term is
an expectation.

### 7.1 Parameters

| symbol | meaning | value used | status |
|---|---|---|---|
| `c_unc` | printed uncontrolled conditions, steps `>= 16` | `57` | reproduced by counting Tables 9/10 (Section 4.3) |
| `q` | first-block acceptance probability, lower bound | `2^-14.1` (measured `2^-14.03`; published `2^-15`) | measured at 32 steps from the IV (Section 7.2) |
| `K` | table size `|V|` | `2^21.0` measured; `K_max = 2^21.2` for work | measured by enumeration (Section 7.3) |
| `p_c` | per-candidate probability of passing all uncontrolled conditions, over `V` | `2^-57.65` measured | per-step profile over `V` (Section 7.4) |
| `y` | per-accepted-block collision yield `K * p_c`, lower bound | `2^-37.2` (measured `2^-36.67`) | Section 7.4 |
| SAT | one-time dense-part solve plus tail-table enumeration | `2^40` | published `2^39.8`; table `< 2^35` |
| `M`, `N_b`, `S_max` | fixed budget | `2^36.685`, `2^50.787`, `2^46.5` | derived from `q`, `y` (Section 6) |

### 7.2 First-block density (measured)

Program `final/cvrate.c` draws random 64-byte blocks `B0`, computes `CV1 = C32(IV, B0)`
with a compression function checked against the trusted reference (self-tests: it
reproduces `C36(IV, M0) = CV1` of Table 2 and the 32-step second-block collision), and
tests the 15 conditions of Section 6 Step 2 with the dense part of the verified pair.
Over `2^28` blocks (seed 7), `16024` passed: `c_cv = 14.03` (relative standard error
`0.8%`, i.e. `+-0.02` bits). The cumulative pass rates per condition group were
`E3[29]: 2^-1.00`; `+W7 signed difference: 2^-1.04`; `+W7 two-bit: 2^-4.04`;
`+W6 signed: 2^-7.04`; `+W6 two-bit: 2^-10.04`; `+W5 signed: 2^-11.04`; `+W5
two-bit: 2^-14.03`. The difference from the published `2^-15` is that the `E3[29]=1`
condition and the signed-difference condition on `W7` are the same event (the
modular difference of `W7` is fixed by the dense part, and its sign pattern is
determined by bit 29 of `E3`), so the 15 conditions carry 14 bits; the other 13
conditions each cost one bit, as counted. The cost uses `c_cv = 14.1`; with the
published `15` every figure below rises by at most `0.55` bits (Section 7.5).

### 7.3 The table `V` (measured)

ePrint 2026/1120 Section 4.2 states that `(W14, W15)` has `2^20` possible values after
all conditions that can be imposed on rows 14 and 15. Program `final/dcheck.c`
enumerates the table `V` of Section 6 (conditions (V1)-(V5)) with the dense part fixed
to the verified pair:

- `W14`, exhaustive over `2^32`: `2^17.00` values satisfy (V1); `2^14.81` of them also
  give `∇W16 = 0` and `2^11.82` (3616 values) also `∇W29 = 0` (V2); `32` values
  (`2^5.00`) also satisfy (V3). The pair's own `W14` is among the 32.
- `W15`, `2^24` (run 1) and `2^20` (run 2) uniformly random values per admissible `W14`:
  `2^-10.0` satisfy (V4) (`9` value bits on `E15`, one signed bit on `A15`); `2^-15.0`
  (`2^-14.93` to `2^-15.10` per `W14`) also satisfy (V5). For 16 of the 32 admissible
  `W14` no `W15` satisfies (V5) (`0` of `2^24`); those `W14` contribute nothing to `V`.
- `|V| = 2^32 * sum_i p_i = 2^20.98` (run 1) and `2^21.12` (run 2), where `p_i` is the
  measured `W15` acceptance for the `i`-th admissible `W14`. The exact enumeration in
  Step 1' (all `2^32` values of `W15` for each of the 32 `W14`) determines `K` exactly;
  the budget uses `K_max = 2^21.2` for the work bound.

The published `2^20` is one bit below `|V|`; Section 7.4 measures the corresponding
extra bit as an unprinted condition at step 17 that holds for about half of `V`. Both
descriptions give the same per-block yield `K * p_c` (Section 7.4).

### 7.4 Uncontrolled-part conditional probabilities (measured)

Program `final/localrate.c` (mode: dense rows `< 16` fixed to the verified pair) samples,
for each step `i = 16..21`, the uncontrolled input rows `16..i-1` uniformly among values
conforming to their Table 9 glyphs and Table 10 relations, and `W_i` uniformly with the
row's `∇W_i` pattern, and measures the probability that `(A_i, E_i)` satisfy row `i`
and its Table 10 relations (`2^22` samples per step, seed 5):

```
step   counted conditions   measured -log2 P
 16          13                13.049
 17          15                14.881
 18           6                 6.002
 19           7                 7.004
 20           1                 0.999
 21           1                 1.001
 sum         43                42.937
```

The `14` remaining uncontrolled conditions are on `W21` (`10`) and `W23` (`4`), i.e.
`c_unc = 57`. The counted and measured profiles agree to `0.06` bits in total; step
17 measures `0.12` bits better than counted.

The same profile measured over `V` (program `final/dcheck.c`, mode 17: 128 pairs
`(W14, W15)` drawn from `V`, eight per admissible `W14`, `2^15` samples per pair for
step 17 and `2^18` per step for a 16-pair run): step 16 `2^-12.9` (`13` counted; all
pairs between `2^-12.5` and `2^-13.6`); step 17 `2^-15.75` averaged over the 128 pairs
(`15` counted; individual pairs show `0` to `6` successes in `2^15` samples, i.e. the
rate varies across `V` and its `V`-average is `0.75` bits below the printed count);
steps 18 and 19 `2^-6.0` and `2^-7.0` (`6`, `7` counted); steps 20, 21 `2^-1.0` each
(`1`, `1` counted, measured on the verified pair's `(W14, W15)`). With the `14` counted
conditions on `W21`, `W23`, the per-candidate probability over `V` is

```
p_c = 2^-(12.9 + 15.75 + 6.0 + 7.0 + 1.0 + 1.0 + 14) = 2^-57.65,
```

and the per-accepted-block yield is `K * p_c = 2^(20.98 - 57.65) = 2^-36.67`. The
budget uses the lower bound `y = 2^-37.2`, half a bit below the measurement. The
statistical error of the step-17 average (`76` events) is about `0.17` bits; the
step-16 average (`2^18` samples on 16 pairs, thousands of events) is below `0.05` bits.

### 7.5 Fixed-budget ledger (worst case)

Every term is a fixed count multiplied by a fixed per-item charge; no expectation
enters. Charges per item (Section 6):

- **First-block trial.** One full `C32` (`1` unit) plus the on-the-fly check: `E3`
  (add, sub, `Sig0` 14 ops, `MAJ` 5 ops, bit test: 24 ops), then `W7` (about 30 ops
  including `Sig1`, `IF`, five add/sub) with its signed-difference and three two-bit
  tests (about 12 ops), and likewise `W6`, `W5` when reached: at most `24 + 3 * 42 =
  150` operations if every stage is reached, charged as the worst case: `1 + 150/2224 =
  1.0674` units. (The average is below 48 operations; the worst case is charged.)
- **Accepted block preparation.** Inversion of `W0..W7` for both messages and the
  constants `c16..c19` (fewer than 300 operations): charged `300/2224` units, at most
  `M` times.
- **Tail candidate.** One load, one add for `W16`, four adds for `E16, E'16, A16,
  A'16`, xor and compare for the difference pattern, and and compare for the value
  mask, shift, xor, and, compare for `E16[0]!=E16[13]`, compare for `A16 = A'16`, and
  at most six conditional branches: `21` operations; charged `32` operations
  (`32/2224 = 2^-6.12` units), exactly `K <= K_max` times per scanned block.
- **Survivor continuation.** Steps 17..23 for both messages with the expanded words
  `W17..W23` and all tests: at most `2 * (7 * 54 + 7 * 30) + 100 < 1300` operations;
  charged `4096` operations, at most `S_max` times.
- **Preprocessing.** SAT solve of the dense part `2^39.8` plus the table enumeration
  `< 2^35`: charged `2^40`.
- **Padding block, final digests, collision check.** Fewer than `8` compressions.

```
W = N_b * 1.0674          = 2^50.787 * 1.0674                 = 2^50.88   (block-1 trials)
  + M * 300/2224          = 2^36.685 * 2^-2.89                = 2^33.80   (accepted-block preparation)
  + M * K_max * 32/2224   = 2^36.685 * 2^21.2 * 2^-6.12       = 2^51.77   (tail scan)
  + S_max * 4096/2224     = 2^46.5 * 2^0.88                   = 2^47.38   (survivor continuation)
  + 2^40 + 8                                                             (preprocessing, finish)
  = 2^52.43.
```

(Script `final/cost32_fixed.py` evaluates this with the block-1 check charged at 60
operations, giving `2^52.40`; the table above charges the 150-operation worst case,
`2^52.43`.) The claimed bound `time_log2 = 53.0` exceeds `2^52.43` by `0.57` bits. The
margin is on top of the worst-case charges already in the ledger (block-1 check at its
maximum, tail candidates at `1.5x` the operation count, survivors at `3x`, table size
at `K_max`).

Sensitivity of the budget (recomputing `M`, `N_b` and the work): `y = 2^-37.5` gives
`2^52.70`; `y = 2^-38.0` gives `2^53.20` (above the claim); `q = 2^-15` (the published
density) gives `2^52.77`; `K_max = 2^21.5` gives `2^52.6`. Each bit less of `y` adds
one bit to `M`, `N_b` and the tail term; each bit less of `q` adds one bit to the
block-1 term only.

Two structural remarks. First, no evaluation of `C32` on a block is charged below one
unit: block-1 trials are full compressions charged `1` each; tail candidates evaluate
one incremental step from precomputed chaining-value-independent state and are charged
by their operations, as the cost model prescribes for ordinary word operations.
Second, the table `V` is shared across all scanned blocks because it does not depend on
`CV1` (Section 6, Step 1'); this is a property of the characteristic (no difference and
no condition on `W0..W4`, dense part fixed), not a parallelism or word-packing argument,
and the total work is summed over all trials.

### 7.6 Conservative fallback

Charging every one of the `M * K_max = 2^57.9` tail candidates of the same fixed budget
as a full compression gives `W = 2^57.9 + 2^50.9 + 2^40 = 2^57.9`. With expected rather
than budgeted counts and the published parameters (`c_unc = 57`, `d = 20`, `c_cv =
15`) the published skeleton gives `2^52 + 2^57 + 2^39.8 = 2^57.04`; the script
`final/cost32.py` reproduces the published 36-step (`2^57.04`) and 38-step (`2^104.32`)
figures with the same formula. Neither fallback is claimed; they are stated so that the
claim can be assessed under a stricter reading of the pricing of partial evaluations.

### 7.7 Success probability of the fixed budget, memory, data, preprocessing, advice

**Success probability.** The success event is that the run of Section 6 (fixed `N_b`,
`M`, `S_max`) outputs a pair of distinct messages with equal 32-step digests. The random
coins are the `N_b` fresh uniform first blocks; the table `V` is fixed. Let `A` be the
number of accepted blocks among the `N_b` trials, `S` the number of survivors among the
candidates of the first `min(A, M)` accepted blocks, and `F` the event that none of
those candidates passes all uncontrolled conditions. The run fails only if `A < M`, or
`S > S_max` (a survivor may then be discarded), or `F`; hence

```
Pr[fail] <= Pr[A < M] + Pr[S > S_max] + Pr[F].
```

- `A` is binomial with `N_b` trials: the trials are independent (fresh uniform blocks)
  and each is accepted with the same probability `q_true`; by the heuristic
  `cv-coverage`, `q_true >= q = 2^-14.1`, so `E[A] = N_b q_true >= N_b q = M (1 + 2^-10)
  = mu`. The Chernoff lower tail `Pr[A <= (1 - d) mu] <= exp(-d^2 mu / 2)` with
  `(1 - d) mu = M`, `d = 2^-10 / (1 + 2^-10)`, gives `Pr[A < M] <= exp(-2^-20 * 2^36.687
  / 2.004) = exp(-5.3 * 10^4)`, below `2^-70000`. (Monotonicity in `q_true` holds
  because `A` is stochastically larger for larger acceptance probability.)
- Under the heuristic `uncontrolled-independence`, each scanned candidate passes the
  step-16 test independently with probability at most `2^-12.4` (Section 7.4: `2^-12.9`
  on average over `V`, `2^-12.5` for the most permissive entry measured), so `S` is
  dominated by a binomial with mean `mu_S <= M K_max 2^-12.4 = S_max / 2`, and
  `Pr[S >= 2 mu_S] <= exp(-mu_S / 3) = exp(-2^45.5 / 3)`, negligible.
- Under the same heuristic, each of the `M K` scanned candidates passes all
  uncontrolled conditions independently with probability `p_c`, with `K p_c >= y =
  2^-37.2` by the heuristic `tail-table`; hence `Pr[F] = (1 - p_c)^(M K) <= exp(-M K
  p_c) <= exp(-M y) = exp(-0.70) = 0.4966`.

Therefore `Pr[success] >= 1 - 0.4966 - 2^-70000 - exp(-2^43.9) > 0.503`, and the
declared `success_probability = 0.5` holds for the fixed budget whose worst-case work
is bounded in Section 7.5. This is an algorithmic-coin probability for the fixed target
under the declared heuristics; it does not encode confidence in any heuristic.

**Memory.** Online: the table `V` (`K <= 2^21.2` entries of 32 bytes, at most `2^26.2`
bytes), the dense part and constants (`< 2^12` bytes). The one-time SAT preprocessing
used about `2^30.5` bytes in the published run; `memory_log2_bytes = 31` covers that
peak. Memory is reported, not scored.

**Data.** Every block-1 trial hashes one 64-byte block (`2^50.79 * 64 = 2^56.8`
bytes); every tail candidate corresponds to one distinct second block (`2^57.9 * 64 =
2^63.9` bytes of candidate message material, most of it never formed in full).
`data_log2 = 64` is a conservative upper bound. No external, chosen-prefix or
challenge data is used.

**Preprocessing.** `preprocessing_log2 = 40` covers the SAT solve and the table
enumeration; both are included in `W` and are independent of the online coins.

**Non-uniform advice.** `nonuniform_advice_log2_bytes = 0`. The characteristic is a
fixed published `O(1)` description; its dense-part solution is recomputed in the
charged preprocessing (the published solution could be reused, which would only
reduce the cost).

### 7.8 Reconciliation with an alternative partition of the conditions

A parallel measurement in the lab (engineer's `eng/results/005-conditions-r32/counts.md`)
partitions the same conditions differently and arrives at "about `2^70`". It accepts a
first block on the signed differences of `W5, W6, W7` only (`2^-5.04`, without the nine
Table 10 two-bit conditions on `W5..W7`), takes as tail freedom the `(W14, W15)` values
that satisfy only the signed differences at steps 14, 15, `∇W16 = 0` and the modular
step-15 differences (`d' = 2^30.1`), and then measures a per-candidate probability of
`2^-74.4` (joint `2^-8.0`, `2^-21.0`, `2^-33.4` through steps 16, 17, 18 over `2^35`
trials; local per-step estimates beyond). In that partition the nine `W5..W7`
conditions (`W20`, `W22`, `W21` cancellations), the `W29` cancellation, and the
chaining-value-independent step-16/17 conditions of Section 7.3 are all paid per tail
candidate instead of being enforced once per first block or once offline. The grand
total over random `(CV1, W14, W15)` agrees: `5.04 + (64 - 30.1) + 74.4 = 113.3` bits
there versus `14.03 + (64 - 21.0) + 57.65 = 114.7` bits here (`+-1` bit from the
`W29`/`W30` and `W23` attributions), which is the expected agreement of two partitions
of one probability mass. The cost difference is only where the conditions are enforced:
paying them per tail candidate multiplies the candidate count by about `2^17`, which
is why that accounting reaches `2^70`; enforcing them in the first-block filter (free,
the compression is computed anyway) and in the offline table (Section 7.3) yields the
`2^57.9` budgeted candidate count of Section 7.5. The joint measurements of that partition are
consistent with the counts used here: `8.0 = 2` (pattern bits) `+ 6` (step-16 implicit
conditions, `|V|` versus the visible `2^27`), `21.0 - 8.0 = 13.0` (row-16 value and
two-bit conditions plus the `E17` pattern, counted `14`), `33.4 - 21.0 = 12.4` (row-17
value and two-bit conditions, counted `12`).

## 8. Heuristics, evidence and limitations

Five premises are declared in `claim.json`. The fixed-budget success bound of
Section 7.7 is a theorem given `cv-coverage`, `uncontrolled-independence` and
`tail-table`; no further premise is used there.

- `cost-transfer-32` (score-critical). The condition set of the published 36-step
  characteristic, evaluated at rounds `0..31`, is the complete set of conditions for a
  32-step collision of the second block: no condition is added by truncation and none
  is lost. Evidence: the structural argument of Section 5(a) (support at index `<= 30`,
  `W31` difference-free, identical automatic behaviour of `W32..W35` at 36 steps) and
  the trusted-verifier measurements of Section 5(b) on two independent published
  instances. Limitation: the published condition set is taken as complete for the
  published attack; the lab reproduced its counts (Section 4.3) and its conditional
  profile (Section 7.4) but did not re-derive the characteristic from scratch.

- `uncontrolled-independence` (score-critical). Distinct scanned candidates `(B0, j)`
  pass the step-16 test, and pass all 57 uncontrolled conditions, as independent events
  with the probabilities measured in Section 7.4 (`<= 2^-12.9` and `p_c = 2^-57.65` on
  average over `V`). Evidence: the per-step conditional profile of Section 7.4 (`42.94`
  measured versus `43` counted for the state conditions on the verified pair's
  `(W14, W15)`; `12.9 / 15.75 / 6.0 / 7.0` versus `13 / 15 / 6 / 7` averaged over `V`),
  the exact and sampled local cancellation experiments of Section 9, and the published
  36-step colliding pair obtained with the same accounting. Limitation: joint dependence
  across steps `16..21` and between the state and `W21/W23` conditions is not measured
  (the joint event is `2^-57.65`); the profile is measured for one dense solution.

- `cv-coverage` (score-critical). A uniformly random first block `B0` is accepted by
  the 15-condition filter of Section 6, Step 2 with probability `q_true >= q = 2^-14.1`.
  Evidence: the measurement of Section 7.2 (program `final/cvrate.c`, `2^28` uniform
  blocks compressed with 32 rounds from the standard IV, `16024` accepted, `2^-14.03`,
  standard error `0.02` bits, with the per-condition-group breakdown listed there), and
  the published measurement at 36 steps (`2^-15` over `2^40` blocks). Scope: the
  fixed dense solution of the verified pair; the standard IV; 32 rounds. Limitation:
  the measurement is lab-run, not organizer-run; another dense solution would have its
  own density with the same counted conditions; the one-bit difference from the
  published figure is explained by the `E3`/`W7` redundancy but that measurement was
  not reproduced at 36 steps.

- `tail-table` (score-critical). The table `V` defined by the explicit conditions
  (V1)-(V5) of Section 6 has `K = |V| <= K_max = 2^21.2` entries, and the per-block yield
  satisfies `K * p_c >= y = 2^-37.2`. Evidence: the enumeration of Section 7.3
  (program `final/dcheck.c`: exhaustive `W14` giving 32 admissible values; `W15`
  acceptance `2^-15.0` per admissible `W14` over `2^24` and `2^20` samples; `|V| =
  2^20.98` and `2^21.12`), the profile over `V` of Section 7.4 (`K p_c = 2^-36.67`
  measured, half a bit above `y`), and the published `2^20` with `57` conditions
  (`2^-37`). Scope: the fixed dense solution of the verified pair. Limitation: `|V|`
  is measured by sampling `W15` (the exact count is produced by the enumeration in
  Step 1'); the profile is measured on 128 sampled pairs; each bit less of `y` adds one
  bit to the total (Section 7.5 sensitivity).

- `partial-step-pricing` (supporting). An incremental evaluation of one step of the
  compression from precomputed state, performed with ordinary 256-bit word operations,
  is charged at `1/2224` per operation, while every full compression is charged one
  unit. Evidence: the cost model text (`collision-frontier-v5`: one selected
  compression costs one unit; every other primitive word operation costs `1/C`) and
  the organizer's derivation of `C` from the operation count of one compression.
  Limitation: if partial evaluations were instead priced as whole compressions, the
  bound becomes `2^57.9` for the same fixed budget (Section 7.6); the rest of the
  analysis is unchanged.

Not heuristic: the target definition, the padding block, the two-block collision
correctness given a conforming pair (Section 5), the condition counts (Section 4.3),
the characteristic/pair consistency (Section 4.4), and the exact cancellation
probabilities (Section 4.5).

## 9. Experiments

The manifest declares seven organizer-run experiments. `add-3bit-aligned-cancel-exact`
is an exhaustive 8-bit count (`da = db = 0x15`, `dc = 0`, exactly `8192/65536 = 2^-3`),
the finite-width analogue of the `W20`, `W22`, `W29` cancellations (identical
three-bit patterns on both operands). `expansion-cancel-W16`, `-W20`, `-W22`, `-W25`,
`-W29`, `-W30` are 32-bit `addition-xor-sampled-v1` experiments with exactly the XOR
input differences of Section 4.5 and output difference `0`; their exact uniform-input
probabilities are `2^-4, 2^-3, 2^-3, 2^-4, 2^-3, 2^-1` (expected successes `16, 32,
32, 16, 32, 128` of 256). These establish the local transition probabilities of six of
the seven cancellations that the characteristic relies on, with 256 organizer-seeded
samples each (Hoeffding half-width `0.10` at `alpha = 0.01`); they do not establish the
joint probability of the trail, which remains the declared heuristic. The samples are
organizer-generated from the organizer's seed protocol; the package makes no claim that
the public-seed samples are representative beyond the reported finite counts, and the
Hoeffding intervals are those reported by the organizer runner under its own stated
assumption. No experiment was selected or modified after seeing results: the six
cancellations are all the two-operand cancellations of the characteristic except `W24`
(expected `0.5` successes in 256 samples), and their expected counts were computed
before declaration (Section 4.5). No
`python-message-pairs-v1` experiment is declared: an output-XOR-mask event on complete
messages from the standard IV would require the second-block collision itself (the
common padding block re-randomises any residual difference, and `W14` is active so the
second block cannot be the final padded block), which is the full `2^52.4` attack. A
fresh conforming pair was also not found by a one-hour nldtool search from the
characteristic, as expected at this cost.

## 10. What is proved, measured and heuristic

- Proved (from the definitions): the target semantics; that a conforming second-block
  pair from a valid `CV1` gives equal digests after the common padding block; that the
  condition set at 32 steps equals the published set (Section 5(a)); the exact
  cancellation probabilities of Section 4.5.
- Measured with the trusted reference: the 32-step second-block collision of the Table
  2 pair from `CV1 = C36(IV, M0)` and of the Table 11 pair (Section 5(b)); the
  consistency of Table 9/10 with the pair (Section 4.4).
- Measured with lab code checked against the reference: `q = 2^-14.03` at 32 steps
  from the IV (Section 7.2); the conditional profile `42.94` versus `43` (Section 7.4)
  and the profile over `V` giving `p_c = 2^-57.65`; the table size `|V| = 2^21.0`
  (Section 7.3).
- Inherited from ePrint 2026/1120: the characteristic itself, `c_unc = 57` (count
  reproduced and profile measured), and the SAT cost `2^39.8`.
- Proved given the heuristics: the fixed-budget success bound `> 0.503` and the
  worst-case work `2^52.43` (Sections 7.5, 7.7).
- Heuristic: independence of the uncontrolled conditions across steps and candidates,
  the lower bounds `q` and `y`, and the pricing of partial step evaluations (Section 8).

Not exploited: for a fixed `(CV1, W14)` the step-16 conditions depend on `W15` only
through `E15`, so they could be solved rather than scanned; this would reduce the tail
term (`2^51.77`) but not the block-1 term (`2^50.88`), i.e. at most about `0.9` bits,
and is not claimed.

No full-scale 32-step colliding message is exhibited (the attack costs about `2^52.4`
compressions), so the certificate manifest is empty. The claim is an advantage over the
generic bound at `time_log2 = 53.0` (fallback `57.9`), not an improvement over any
prior 32-step attack, since none has been published.

## Appendix A. Index: where each claim is stated and supported

Cross-reference from each statement of this document to the section where it is
established, with its nature (definition, proof from the definitions, trusted-verifier
measurement, lab measurement, or declared heuristic).

**Target and construction.**

- Target definition (profile, IV, padding, rounds `0..31` on every block, feed-forward,
  full digest, distinct messages): Section 1 (definition).
- Algorithm: Section 6 (preprocessing Step 1; table `V` by the explicit conditions
  (V1)-(V5), Step 1'; fixed budget `q, y, M, N_b, S_max`; Step 2 with the check
  equations; Step 3 with the per-candidate computation; output and failure rule).
- Cost vector: `claim.json:/claim`; time `53.0` (Section 7.5), memory `31` (Section 7.7),
  data `64` (Section 7.7), preprocessing `40` (Section 7.5), success `0.5` (Section
  7.7), advice `0` (Section 7.7).
- Probability space and success event: Section 7.7, first paragraph (coins = the `N_b`
  fresh first blocks; event = output of a colliding pair within the fixed budget).
- Declared heuristics: Section 8 (five premises; the success bound of Section 7.7 uses
  `cv-coverage`, `uncontrolled-independence` and `tail-table`).

**Collision correctness.**

- The condition set at 32 steps equals the published set and steps `24..31` run on
  identical states: Section 5(a) (proof from the definitions).
- Two published instances collide at 32 steps under
  `verifier/hash_functions.py:_compress`: Section 5(b) (trusted-verifier measurement);
  consistency of Tables 9/10 with the pair: Section 4.4.
- Padding block common to both messages: Section 6, last paragraph (definition).

**Probability of the characteristic.**

- `57` uncontrolled conditions counted from Tables 9 and 10: Section 4.3 (count).
- Per-step conditional profile, `42.94` versus `43` on the verified pair and
  `12.9 / 15.75 / 6.0 / 7.0` versus `13 / 15 / 6 / 7` over `V`, `p_c = 2^-57.65`:
  Section 7.4 (lab measurement).
- Exact probabilities of the seven two-operand expansion cancellations: Section 4.5
  (enumeration).
- Alternative partition of the same conditions and agreement of the totals: Section 7.8.
- Independence of the conditions across steps and across candidates: heuristic
  `uncontrolled-independence`, Section 8 (measured per step, assumed jointly).

**Cost.**

- Worst-case charged work over the fixed budget, `W = 2^52.43`: Section 7.5. The ledger
  charges a fixed worst-case budget of fixed counts (`N_b` trials, `M` scanned blocks
  with `K_max` candidates each, `S_max` continued survivors, the preprocessing, the
  finish), each at a fixed per-item charge.
- Charged categories: first-block trials including rejected ones; accepted-block
  preparation; the full table scan for `M` blocks; survivor continuation up to `S_max`;
  preprocessing including the table enumeration; padding block and final digests:
  Section 7.5.
- Pricing of partial evaluations: Section 7, opening paragraph, and heuristic
  `partial-step-pricing` (Section 8); whole-compression fallback `2^57.9` for the same
  budget: Section 7.6.
- Success probability of the fixed budget, `Pr[fail] <= Pr[A < M] + Pr[S > S_max] +
  Pr[F] < 0.497`: Section 7.7 (Chernoff lower tail for `A`, Chernoff upper tail for `S`,
  `exp(-M y)` for `F`; a proof given the three heuristics named there).
- Memory, data, preprocessing, advice: Section 7.7.
- Sensitivity to `y`, `q`, `K_max`: Section 7.5, last paragraphs.

**Measured parameters.**

- First-block acceptance `q = 2^-14.03` from the standard IV over `2^28` blocks:
  Section 7.2 (lab measurement; program `final/cvrate.c`).
- Table size `|V| = 2^20.98` and `2^21.12`: Section 7.3 (lab measurement; program
  `final/dcheck.c`).
- Per-block yield `K p_c = 2^-36.67`: Section 7.4 (lab measurement).
- These measurements were run in the lab, not by the organizer; Sections 8 and 10 say
  so.

**Experiments.**

- The seven declared experiments and what each establishes (finite local counts only;
  the trail probability is not derived from them): Section 9.
- Statistical treatment of the sampled experiments and the selection rule for the six
  cancellations: Section 9.
