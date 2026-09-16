# A 32-step SHA-256 ordinary collision from the 2026/1120 36-step local collision

This package describes a classical cryptanalytic collision attack on SHA-256 reduced
to its first 32 compression rounds (target profile `sha256-r32-prefix-v1`, cost model
`collision-frontier-v5`, review policy `paired-lanes-v1`). The claimed charged time is
at most `2^52.5` target-compression units (the reconstructed figure is `2^51.8`, or
`2^52.4` with the published rather than the measured first-block density; Section 7)
for algorithmic success probability at least `0.5`, with about `2^25` bytes of online
memory. Every compression that the attack evaluates in full is charged one unit;
partial step evaluations are charged by their primitive operations at `1/2224`. A
fully conservative variant that charges every uncontrolled-part candidate as a whole
compression costs `2^57.04` (Section 7.6) and is reported as a fallback.

The construction is structural, not generic: it reuses without change the 36-step
SHA-256 local collision and differential characteristic of Li, Zhang, Li, Liu, Qian
and Zhu, "Pushing Collision Attacks on SHA-2 to 39 Steps" (IACR ePrint 2026/1120,
Tables 9 and 10), together with the memory-efficient two-block conversion of that
work (CRYPTO 2026 framework of Li et al., and Li, Liu, Wang, ePrint 2024/349). The
central facts, proved and measured below, are (i) the whole characteristic lives in
step indices `0..30`, so a 32-step compression enforces exactly its conditions and no
others, and (ii) the state of both messages up to step 15 and the set of usable tail
words `(W14, W15)` do not depend on the chaining value, which allows the uncontrolled
part to be scanned with a few word operations per candidate.

The required reference identifier `sha256-r32-nominal-v2` names the organizer display
reference only. The claimed scalar `52.5` is below the nominal exponent `128`; this
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

**Step 1' (preprocessing, once): the tail table.** The state words at steps `14` and
`15` of both messages depend only on the dense part and on `(W14, W15)`:
`E14 = A10 + E10 + Sig1(E13) + IF(E13,E12,E11) + K14 + W14`, `A14 = E14 - A10 +
Sig0(A13) + MAJ(A13,A12,A11)`, and likewise for `E15, A15` and for the primed words
with `W'14 = W14 + (W'14 - W14)` fixed by `∇W14` and `W'15 = W15`. The difference
cancellations in `W16` (`W9` against `s1(W14)`), `W29` (`W13` against `s0(W14)`) and
`W30` (`W14` against `W23`, deterministic by the fixed signs) also depend only on
`W14` and the dense part. Hence the set `V` of pairs `(W14, W15)` that satisfy all
conditions imposable on rows 14 and 15 is independent of the chaining value; ePrint
2026/1120 reports `|V| = 2^20`. `V` is enumerated once and stored with, per entry,
`s1(W14)`, `s1(W15)`, `base16 = A12 + E12 + Sig1(E15) + IF(E15,E14,E13) + K16` and
`base'16` (its primed version), and `off16 = -A12 + Sig0(A15) + MAJ(A15,A14,A13)` and
`off'16`: six 32-bit fields, one 256-bit word per entry, `2^20` words (`2^25` bytes).
Enumerating `V` costs at most `2^32` step evaluations for `W14` plus `2^32` per
surviving `W14` for `W15` (fewer than `2^12` survive), below `2^40` compression
equivalents; it is part of the charged preprocessing.

**Step 2 (block-1 search).** Draw a fresh first block `B0` and compute
`CV1 = C32(IV, B0)` (one full compression, charged one unit). Check on the fly, from
`CV1` and the fixed `A_0..A_3`, `E_4..E_7`, whether the 15 first-block conditions hold,
in the order `E3` (reject with probability `1/2`), then `W7`, `W6`, `W5`:

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
Table 10 on `W5, W6, W7` hold. When `CV1` passes, the remaining early words follow by
inversion (`W0..W4` common to both messages):

```
E0 = A0 + A_{-4} - Sig0(A_{-1}) - MAJ(A_{-1},A_{-2},A_{-3})
W4 = E4 - A0 - E0 - Sig1(E3) - IF(E3,E2,E1) - K4
W3 = E3 - A_{-1} - E_{-1} - Sig1(E2) - IF(E2,E1,E0) - K3
W2 = E2 - A_{-2} - E_{-2} - Sig1(E1) - IF(E1,E0,E_{-1}) - K2
W1 = E1 - A_{-3} - E_{-3} - Sig1(E0) - IF(E0,E_{-1},E_{-2}) - K1
W0 = E0 - A_{-4} - E_{-4} - Sig1(E_{-1}) - IF(E_{-1},E_{-2},E_{-3}) - K0
```

so `W0..W13` of the second block are fixed for this `B0`. Also compute once per valid
`B0` the constants `c16 = W0 + s0(W1) + W9`, `c17 = W1 + s0(W2) + W10`,
`c18 = W2 + s0(W3) + W11`, `c19 = W3 + s0(W4) + W12` and their primed versions.

**Step 3 (uncontrolled part, scan of the tail table).** For each entry `j` of `V`:
`W16 = c16 + s1(W14_j)` (common to both messages, because `∇W16 = 0`);
`E16 = base16_j + W16`, `E'16 = base'16_j + W16`, `A16 = E16 + off16_j`,
`A'16 = E'16 + off'16_j`. Test the row-16 conditions: the XOR of `(E16, E'16)` equals
the `∇E16` difference mask with the signs of Table 9; the seven `0/1` value bits of
`∇E16`; `A16 = A'16`; and the Table 10 relations `E16[0]!=E16[13]`,
`E15[15]=E16[15]`, `E15[24]=E16[24]`, `A14[29]=A16[29]` (the last three are value
conditions on `E16`, `A16` because `E15`, `A14` are fixed per entry). A candidate
survives with probability `2^-13` (13 conditions; measured `2^-13.05`, Section 7.4).
Survivors continue with `W17 = c17 + s1(W15_j)` and step 17 (`15` conditions), then
steps 18 (`6`), 19 (`7`), 20 (`1`), 21 (`1`), with the expanded words `W18..W23`
computed from the fixed words and the candidate; the `W21` conditions (`6` glyphs and
`4` two-bit) and `W23` conditions (`1` glyph and `3` two-bit) are tested when those
words are formed. A candidate that passes all `57` uncontrolled conditions yields the
second blocks `M1 = (W0..W15)` and `M1' = (W'0..W'15)`; by Section 5 the pair then
collides at 32 steps. If no entry of `V` succeeds for this `B0`, return to Step 2.

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
compression is additionally charged per operation.

### 7.1 Parameters

| symbol | meaning | value used | status |
|---|---|---|---|
| `c_unc` | uncontrolled conditions, steps `>= 16` | `57` | reproduced by counting Tables 9/10 (Section 4.3); conditional profile measured (Section 7.4) |
| `d` | `log2 |V|`, usable `(W14,W15)` values per valid `B0` | `19.5` (measured `19.7`; published `20`) | measured by enumeration with the dense part fixed (Section 7.3) |
| `c_cv` | `-log2 P[random B0 passes the 15 first-block conditions]` | `14.1` (measured `14.03`; published `15`) | measured at 32 steps from the IV (Section 7.2) |
| SAT | one-time dense-part solve plus tail table | `2^40` | published `2^39.8`, table `< 2^40` |

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

### 7.3 Tail freedom `d` (measured)

ePrint 2026/1120 Section 4.2 states that `(W14, W15)` has `2^20` possible values after
all conditions that can be imposed on rows 14 and 15. Program `final/dcheck.c` re-derives
this with the dense part fixed to the verified pair. Every condition below depends only
on the dense part and on `(W14, W15)`, never on the chaining value, so the set is the
same at 32 and 36 steps and can be enumerated once (Section 6, Step 1').

- `W14`, exhaustive over `2^32`: `2^17.00` values satisfy every printed glyph of row 14
  on `(E14, A14, W14)`; `2^14.81` of them also give `∇W16 = 0` (the `W9`/`s1(W14)`
  cancellation of Section 4.5); `2^11.82` (3616 values) also give `∇W29 = 0`; `32`
  values (`2^5.00`) also give the modular differences of `E15` and `A15` prescribed by
  the characteristic (these are the unprinted sign conditions of the `Sig1(E14)` and
  `IF(E14,E13,E12)` differences at step 15). The pair's own `W14` is among the 32.
- `W15`, `2^24` (respectively `2^20`) random values per admissible `W14`: `2^-10.0` satisfy
  the printed glyphs of row 15 (`9` value bits on `E15`, one signed bit on `A15`);
  `2^-15.0` also give the modular differences of `E16` and `A16` prescribed by the
  characteristic, which do not depend on `W16` (`∇W16 = 0`, `∇Sig1(E15) = 0`) and are
  therefore conditions on `(W14, W15)` alone (the signs of the `Sig0(A15)` and
  `MAJ(A15,A14,A13)` differences and of the `IF(E15,E14,E13)` difference at step 16).
  For 16 of the 32 admissible `W14` no `W15` satisfies them (`0` of `2^24`); for the other
  16 the acceptance is `2^-14.93` to `2^-15.10`.
- Total: `|V| = 2^32 * sum_i p_i = 2^20.98` (run 1, `2^24` tries per `W14`) and `2^21.12`
  (run 2, `2^20` tries).
- A further chaining-value-independent condition appears at step 17: measuring the
  step-17 conditional probability (Section 7.4) on one admissible `(W14, W15)` per
  admissible `W14`, `6` of the `16` behave as counted (`2^-14.0` to `2^-15.4`, mean
  `2^-14.7`) and `10` give no success in `2^18` samples (`< 2^-18`). Restricting `V` to
  the pairs that pass this test (again enumerable offline, e.g. by the same sampling
  test, at fewer than `2^36` compression equivalents) gives
  `|V'| = 2^21.1 * 6/16 = 2^19.7`, the published `2^20` within the resolution of the
  fraction estimate (`6/16`, about `+-0.4` bits).

The cost uses `d = 19.5`, below the measured `19.7` and the published `20`. Section 7.8
shows how this measurement reconciles a different partition of the same conditions.

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

The same profile measured on the refined set `V'` of Section 7.3 (one admissible
`(W14, W15)` per admissible `W14`, `2^18` samples per step, weighted by each `W14`'s
share of `V`): step 16 `2^-12.9` (`13` counted, all 16 pairs between `2^-12.5` and
`2^-13.6`); step 17 `2^-14.7` on the 6 pairs of `V'` (`15` counted); steps 18 and 19
`2^-6.0` and `2^-7.0` on all pairs (`6`, `7` counted). Over `V'` the state conditions
therefore behave as counted, and the per-candidate probability `2^-57` is measured
step by step for steps `16..21` and counted for `W21`, `W23`. When the dense rows are instead sampled
uniformly within their printed glyphs (that is, without the unprinted dense-part
conditions that the SAT solution satisfies), steps 16 and 17 measure `2^-19.6` and
`2^-16.1`; this confirms that the printed dense rows underdetermine the dense
solution, which is why the attack fixes the dense part by SAT and why Section 7.3
inherits the published `|V|` rather than the visible glyph count.

### 7.5 Ledger and totals

Let `p = 0.5` be the declared success probability. Under the standard model that each
candidate `(B0, j)` succeeds independently with probability `2^-57` (declared
heuristic `uncontrolled-independence`), the number of candidates needed for success
probability `p` is `-ln(1-p) * 2^57 = 2^56.47`, requiring `2^(56.47 - 19.5) = 2^36.97`
valid first blocks and `2^(36.97 + 14.1) = 2^51.07` block-1 trials.

- **Block-1 trials.** Each trial: one full `C32` (1 unit) plus the on-the-fly check
  (`E3`: about 24 operations, then with probability `1/2` the `W7` derivation and
  tests, about 42, then with probability `2^-4` and `2^-10` the `W6`, `W5` parts):
  fewer than 48 operations on average, charged `60`. Per trial `1 + 60/2224 = 1.027`
  units. Term: `2^51.07 * 1.027 = 2^51.11`.
- **Per valid first block.** Inversion of `W0..W7` for both messages and the constants
  `c16..c19` (fewer than 300 operations): `2^36.97 * 300/2224 = 2^34.1`, negligible.
- **Tail scan.** `2^56.47` candidates. Per candidate (Section 6, Step 3): one load,
  one add for `W16`, four adds for `E16, E'16, A16, A'16`, the tests (xor and compare
  for the difference pattern; and and compare for the value mask; shift, xor, and,
  compare for `E16[0]!=E16[13]`; compare for `A16 = A'16`) and about six conditional
  branches: `21` operations, plus the survivors' continuation (`2^-13` of candidates,
  about `110` operations for step 17, geometrically less thereafter): `0.02`
  operations on average. Charged `32` operations per candidate (`1.5x` the ledger):
  `32/2224 = 2^-6.12` units. Term: `2^56.47 - 6.12 = 2^50.35`.
- **Preprocessing.** SAT solve of the dense part `2^39.8` plus tail-table enumeration
  `< 2^38.5`: charged `2^40`.
- **Padding block, final digests, collision check.** Fewer than `8` compressions.

```
T(p=0.5) = 2^51.11 (block-1) + 2^50.35 (tail) + 2^40 (preprocessing) + O(1)
         = 2^51.78.
```

With the published `c_cv = 15` instead of the measured `14.1`, the block-1 term is
`2^52.01` and the total `2^52.41`; with the published `d = 20` and measured `c_cv` the
total is `2^51.5`. The claimed bound `time_log2 = 52.5` exceeds the reconstruction by
`0.72` bits with the measured parameters and still covers the published-density
variant; the margin is on top of the ledger slack already included, the `+-0.02`-bit
error of `c_cv`, the `0.2`-bit rounding of `d` below its measurement, and the
`0.06`-bit disagreement of Section 7.4. Sensitivity: each extra uncontrolled condition
adds one bit; each bit less of `d` adds `0.7` bits (block-1 only): `d = 18.5` gives
`2^52.5`, `d = 17.5` gives `2^53.3`; charging every tail candidate as a whole
compression gives `2^56.5`.

Two structural remarks on the ledger. First, no evaluation of `C32` on a block is
charged below one unit: block-1 trials are full compressions charged `1` each; the
tail candidates evaluate one incremental step (and a few expansion adds) from
precomputed CV-independent state, and are charged by their operations, as the cost
model prescribes for ordinary word operations. Second, the state after step 15 and
the table `V` are shared across all `2^37` valid first blocks because they do not
depend on `CV1` (Section 6, Step 1'); this sharing is a property of the characteristic
(no difference and no condition on `W0..W4`, dense part fixed), not a parallelism or
lane-packing argument, and the total work is summed over all trials.

### 7.6 Conservative fallback

Charging every one of the `2^57` expected tail candidates as a full compression and
using the published `c_cv = 15` with expected (rather than `p = 0.5`) trial counts
reproduces the published skeleton: `2^52 + 2^57 + 2^39.8 = 2^57.04`. The script
`final/cost_model.py`/`final/cost32.py` reproduces the published 36-step (`2^57.04`)
and 38-step (`2^104.32`) figures with the same formula. This fallback is not claimed;
it is stated so that the claim can be assessed under a stricter reading of the pricing
of partial evaluations.

### 7.7 Success probability, memory, data, preprocessing, advice

**Success probability.** The success event is that the run outputs a pair of
distinct messages with equal 32-step digests. The random coins are the fresh first
blocks `B0` (uniform 64-byte strings) and nothing else; the table `V` is scanned
exhaustively per valid `B0`. Under the independence heuristic each candidate succeeds
with probability `2^-57`, and the budget of `2^56.47` candidates gives
`1 - (1 - 2^-57)^(2^56.47) = 0.5`. The declared `success_probability = 0.5` is an
algorithmic-coin probability for the fixed target and does not encode confidence in
any heuristic.

**Memory.** Online: the tail table `V` (`2^20` entries of 32 bytes = `2^25` bytes), the
dense part and constants (`< 2^12` bytes). The one-time SAT preprocessing used about
`2^30.5` bytes in the published run; `memory_log2_bytes = 31` covers that peak. Memory
is reported, not scored.

**Data.** Every block-1 trial hashes one 64-byte block (`2^50.6 * 64 = 2^56.6` bytes);
every tail candidate corresponds to one distinct second block (`2^56.5 * 64 = 2^62.5`
bytes of candidate message material, most of it never formed in full). `data_log2 =
63` is a conservative upper bound. No external, chosen-prefix or challenge data is used.

**Preprocessing.** `preprocessing_log2 = 40` covers the SAT solve and the tail-table
enumeration; both are included in `T` and are independent of the online coins.

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
there versus `14.03 + (64 - 19.7) + 57 = 115.3` bits here (`+-1` bit from the
`W29`/`W30` and `W23` attributions), which is the expected agreement of two partitions
of one probability mass. The cost difference is only where the conditions are enforced:
paying them per tail candidate multiplies the candidate count by about `2^17`, which
is why that accounting reaches `2^70`; enforcing them in the first-block filter (free,
the compression is computed anyway) and in the offline table (Section 7.3) yields the
published-style `2^57` candidate count. The joint measurements of that partition are
consistent with the counts used here: `8.0 = 2` (pattern bits) `+ 6` (step-16 implicit
conditions, `|V|` versus the visible `2^27`), `21.0 - 8.0 = 13.0` (row-16 value and
two-bit conditions plus the `E17` pattern, counted `14`), `33.4 - 21.0 = 12.4` (row-17
value and two-bit conditions, counted `12`).

## 8. Heuristics, evidence and limitations

Five premises are declared in `claim.json`.

- `cost-transfer-32` (score-critical). The condition set of the published 36-step
  characteristic, evaluated at rounds `0..31`, is the complete set of conditions for a
  32-step collision of the second block: no condition is added by truncation and none
  is lost. Evidence: the structural argument of Section 5(a) (support at index `<= 30`,
  `W31` difference-free, identical automatic behaviour of `W32..W35` at 36 steps) and
  the trusted-verifier measurements of Section 5(b) on two independent published
  instances. Limitation: the published condition set is taken as complete for the
  published attack; the lab reproduced its counts (Section 4.3) and its conditional
  profile (Section 7.4) but did not re-derive the characteristic from scratch.

- `uncontrolled-independence` (score-critical). A candidate `(B0, j)` passes the 57
  uncontrolled conditions with probability `2^-57`, and distinct candidates succeed
  independently. Evidence: the per-step conditional profile of Section 7.4 (`42.94`
  measured versus `43` counted for the state conditions, given conforming prefixes),
  the exact and sampled local cancellation experiments of Section 9, and the published
  36-step colliding pair obtained with the same accounting. Limitation: joint
  dependence across steps `16..21` and between the state and `W21/W23` conditions is
  not measured (the joint event is `2^-57`); the profile is measured for one dense
  solution and the verified pair's `(W14,W15)`.

- `cv-coverage` (score-critical). A random first block `B0` yields a chaining value
  passing the 15 first-block conditions with probability `2^-14.1` or less, so
  `2^14.1` block-1 trials produce one valid `B0`. Evidence: the direct measurement of
  Section 7.2 at 32 steps from the standard IV (`2^28` trials, `2^-14.03`); the
  published measurement at 36 steps (`2^-15` over `2^40` blocks). Limitation: the two
  measurements differ by one bit (explained by the `E3`/`W7` redundancy); the cost
  is reported for both.

- `tail-freedom-20` (score-critical). The set `V'` of `(W14, W15)` values that satisfy
  every chaining-value-independent condition of rows 14..17 has at least `2^19.5`
  elements, is enumerable offline within the charged preprocessing, and for its
  elements the uncontrolled conditions behave as counted. Evidence: the enumeration of
  Section 7.3 (`|V| = 2^21.0`, `6/16` pass the step-17 test, `|V'| = 2^19.7`), the
  profile of Section 7.4 on `V'`, and the published attack's `2^20`. Limitation: the
  step-17 membership test is a sampling test (`2^18` samples per candidate) rather than
  an explicit bit condition; the fraction `6/16` carries about `+-0.4` bits; each bit
  less of `d` adds `0.7` bits to the cost.

- `partial-step-pricing` (supporting). An incremental evaluation of one step of the
  compression from precomputed state, performed with ordinary 256-bit word operations,
  is charged at `1/2224` per operation, while every full compression is charged one
  unit. Evidence: the cost model text (`collision-frontier-v5`: one selected
  compression costs one unit; every other primitive word operation costs `1/C`) and
  the organizer's derivation of `C` from the operation count of one compression.
  Limitation: if partial evaluations were instead priced as whole compressions, the
  bound becomes `2^56.5` (`2^57.04` with all conservative choices, Section 7.6); the
  rest of the analysis is unchanged.

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
joint probability of the trail, which remains the declared heuristic. No
`python-message-pairs-v1` experiment is declared: an output-XOR-mask event on complete
messages from the standard IV would require the second-block collision itself (the
common padding block re-randomises any residual difference, and `W14` is active so the
second block cannot be the final padded block), which is the full `2^51.8` attack. A
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
- Measured with lab code checked against the reference: `c_cv = 14.03` at 32 steps
  from the IV (Section 7.2); the conditional profile `42.94` versus `43` (Section 7.4)
  and its typicality over `V'`; the tail freedom `|V'| = 2^19.7` (Section 7.3).
- Inherited from ePrint 2026/1120: the characteristic itself, `c_unc = 57` (count
  reproduced and profile measured), and the SAT cost `2^39.8`.
- Heuristic: independence of the uncontrolled conditions across steps, the enumerability
  of `V'` at the stated cost, and the pricing of partial step evaluations (Section 8).

Not exploited: for a fixed `(CV1, W14)` the step-16 conditions depend on `W15` only
through `E15`, so they could be solved rather than scanned; since the block-1 term
dominates (`2^51.1` of `2^51.8`), this can lower the total by at most `0.7` bits and
is not claimed.

No full-scale 32-step colliding message is exhibited (the attack costs about `2^51.8`
compressions), so the certificate manifest is empty. The claim is an advantage over the
generic bound at `time_log2 = 52.5` (fallback `57.04`), not an improvement over any
prior 32-step attack, since none has been published.
