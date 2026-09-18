# A 32-step SHA-256 ordinary collision from the 2026/1120 36-step local collision

This package describes a classical cryptanalytic collision attack on SHA-256 reduced
to its first 32 compression rounds (target profile `sha256-r32-prefix-v1`, cost model
`collision-frontier-v5`). The claimed charged time is
at most `2^71.5` target-compression units for a fixed, pre-declared work budget whose
worst-case charged work is `2^70.98` (Section 7.5) and whose success probability is at
least `0.503` (Section 7.7), with negligible online memory. The two measured parameters
that the success bound uses are taken below their one-sided lower confidence bounds
(Section 7.9). The cost is dominated by full 32-round compressions of first blocks,
each charged one unit; the success bound uses only the independence of distinct first
blocks (fresh random coins) and credits no amortisation over several second-block
candidates of one first block: an earlier version of this analysis multiplied the
conditional probabilities of the `2^21` candidates of one first block as if they were
independent, a premise that a direct measurement refuted (Section 7.3), and the present
accounting removes it.

The construction is structural, not generic: it reuses without change the 36-step
SHA-256 local collision and differential characteristic of Li, Zhang, Li, Liu, Qian
and Zhu, "Pushing Collision Attacks on SHA-2 to 39 Steps" (IACR ePrint 2026/1120,
Tables 9 and 10), together with the memory-efficient two-block conversion of that
work (CRYPTO 2026 framework of Li et al., and Li, Liu, Wang, ePrint 2024/349). The
central facts, proved and measured below, are (i) the whole characteristic lives in
step indices `0..30`, so a 32-step compression enforces exactly its conditions and no
others, and (ii) the state of both messages up to step 15 does not depend on the chaining
value, so one fixed second-block template can be tested against every accepted first
block with a few word operations. The algorithm is stated with a fixed budget (a fixed
number of first-block trials and a cap on accepted blocks); the charged work is the
worst case over that budget and the success probability is bounded below for that
same budget.

The required reference identifier `sha256-r32-nominal-v2` names the organizer display
reference only. The claimed scalar `71.5` is below the nominal exponent `128`; this
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
profile of the uncontrolled part for a fixed second-block template, and an explicit
fixed-budget ledger.

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

Under the characteristic the expanded words `W16..W20`, `W22`, `W24..W31` carry no
difference; only `W21` and `W23` do. For each expanded word `W_i = W_{i-16} +
s0(W_{i-15}) + W_{i-7} + s1(W_{i-2})` the active inputs (those with a difference) are:

```
W16: W9, s1(W14)          W17: none      W18: none      W19: none
W20: s0(W5), W13          W21: W5, s0(W6), W14   (output has a difference: row 21)
W22: W6, s0(W7)           W23: W7, s0(W8), s1(W21)   (output has a difference: row 23)
W24: W8, s0(W9)           W25: W9, s1(W23)          W26: none      W27: none
W28: s0(W13), W21         W29: W13, s0(W14)          W30: W14, W23  W31: none
```

`W17, W18, W19, W26, W27, W31` are difference-free automatically. The eight words
`W16, W20, W22, W24, W25, W28, W29, W30` are two-operand cancellations: the modular
differences of the two active inputs must sum to zero. Because `s0` and `s1` are
GF(2)-linear, the XOR difference of `s0(W_j)` or `s1(W_j)` is fixed by `∇W_j`. From the
pair of Section 4.4:

```
word  operand a   XOR diff  (HW)   operand b    XOR diff  (HW)   P[cancel], uniform   P[cancel | signs of a fixed]
W16  W9          00080c00 (HW 3)   sigma1(W14)  00081400 (HW 3)        4/64 = 2^-4      2^-3
W20  sigma0(W5)  04400800 (HW 3)   W13          04400800 (HW 3)        8/64 = 2^-3      2^-3
W22  W6          04400800 (HW 3)   sigma0(W7)   04400800 (HW 3)        8/64 = 2^-3      2^-3
W24  W8          0101108a (HW 6)   sigma0(W9)   0301119a (HW 9)    64/32768 = 2^-9      2^-9
W25  W9          00080c00 (HW 3)   sigma1(W23)  00081400 (HW 3)        4/64 = 2^-4      2^-3
W28  sigma0(W13) 02808000 (HW 3)   W21          01808000 (HW 3)        4/64 = 2^-4      2^-3
W29  W13         04400800 (HW 3)   sigma0(W14)  04400800 (HW 3)        8/64 = 2^-3      2^-3
W30  W14         20000000 (HW 1)   W23          20000000 (HW 1)         2/4 = 2^-1      2^-1
```

`P[cancel], uniform` is the exact probability, over uniform random operand values
with the given XOR input differences, that the two modular differences cancel (the
sum has XOR output difference `0`); it is obtained by enumerating all sign patterns of
the difference bits. The last column fixes the signs of operand `a` to those of the
characteristic, which is the situation inside the attack (the dense part or the
characteristic fixes them), and matches the corresponding condition counts. Where each
cancellation is enforced in the attack:

- `W16` (`W9` vs `s1(W14)`): `W9` is dense; the three sign conditions on `s1(W14)` hold
  for the fixed template word `W14*` (condition (T2) of Section 6).
- `W20` (`s0(W5)` vs `W13`): `W13` is dense; the three conditions on `W5` are the Table
  10 row `W5`, part of the first-block filter (Section 6, Step 2).
- `W22` (`W6` vs `s0(W7)`): the three conditions on `W7` are the Table 10 row `W7`,
  part of the first-block filter; the signs of `W6` are its `∇W6` row, also in the filter.
- `W24` (`W8` vs `s0(W9)`): both dense; the six Table 10 conditions on `W8` are solved
  by the SAT solver in Step 1.
- `W25` (`W9` vs `s1(W23)`): `W9` is dense; the three Table 10 conditions on `W23` are
  among the 57 uncontrolled conditions (tested when `W23` is formed in Step 3).
- `W28` (`s0(W13)` vs `W21`): `W13` is dense, so the modular difference of `s0(W13)` is
  fixed; the modular difference of `W21` is fixed by the `∇W21` row of Table 9 (three
  `n`/`u` glyphs and three value glyphs, which together fix the signed pattern and hence
  the modular difference `W'21 - W21 = +2^24 + 2^23 - 2^15`, the negative of `s0(W'13) - s0(W13)`);
  those six glyphs are among the 57 uncontrolled conditions (tested when `W21` is formed
  in Step 3). Given them the cancellation is deterministic, as the last column shows.
- `W29` (`W13` vs `s0(W14)`): `W13` is dense; the three sign conditions on `s0(W14)` hold
  for the fixed template word `W14*` (condition (T2) of Section 6).
- `W30` (`W14` vs `W23`): both differences are single bits at position 29 with opposite
  signs fixed by the `∇W14` and `∇W23` rows (`u` and `n`); the cancellation is
  deterministic once row 23 holds.

The words with a difference: `W21 = W5 + s0(W6) + W14 + s1(W19)` has three active
inputs whose signed differences are fixed by the filter (`W5`, `W6`) and by the template
(`W14*`); its own signed pattern (row 21) then holds with the probability of the three
value glyphs and the four Table 10 conditions, counted among the 57. `W23 = W7 + s0(W8)
+ W16 + s1(W21)` has active inputs `W7` (filter), `s0(W8)` (dense) and `s1(W21)` (whose
signed output difference is fixed by the four Table 10 conditions on `W21`); its single
`n` glyph and three Table 10 conditions are counted among the 57. The `W24`
cancellation is dense-only; the other seven are declared as organizer-run
`addition-xor-sampled-v1` experiments with exactly these input differences (Section 9).

## 5. Validity of the characteristic at 32 steps

**(a) Structural.** The characteristic's entire nonzero activity is confined to step
indices `<= 30`: the state difference `(∇A_i, ∇E_i)` is zero for `i >= 20` and the
last state condition is at `E21`; the last message word with a difference is `W23`;
the expansion cancellations (Section 4.5) are at indices `16, 20, 22, 24, 25, 28, 29,
30`, each of them enforced by conditions of Tables 9/10, of `V`, or of the dense part
as itemised in Section 4.5. A 32-step compression computes `W0..W31` and runs steps
`0..31`; therefore every condition of Tables 9 and 10 is present and enforced at 32
steps, and the only extra expanded word, `W31 = W15 + s0(W16) + W24 + s1(W29)`, has
four difference-free inputs and is difference-free automatically. Concretely, once the
dense part, the filter conditions, the template conditions (T1)-(T5) and the 57
uncontrolled conditions hold: `W16, W20, W22, W24, W29, W30` are difference-free by the
cancellations of Section 4.5; `W21` and `W23` carry exactly the differences of rows 21
and 23; `W25` and `W28` are difference-free by the `W23` and `W21` conditions; all
other expanded words up to `W31` have difference-free inputs. The state difference is
zero after step 19 except for the conditions at `E20`, `E21` (rows 20, 21); the
difference `∇E17` (three bits) is cancelled at step 21 by `∇W21`, and `∇E19` (one bit)
at step 23 by `∇W23`, which is what rows 21 and 23 encode. Conversely, at 36 steps the expanded words
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
4.2 instantiated at 32 steps, with one fixed second-block template. The colliding
messages are `m = B0 || M1` and `m' = B0 || M1'`, 128 bytes each; the target's padding
rule appends a common third block. Write `CV1 = C32(IV, B0) = (A_{-1},...,E_{-4})`.

**Step 1 (preprocessing, once).** Find one valid assignment of the dense part: the
expanded words `W8..W13` and the state words `A_0..A_13`, `E_4..E_13` of both messages,
consistent with the step function and with all Table 9/10 conditions at steps
`0..15` (including the `W8` conditions of Table 10). This is a SAT problem; the
published 36-step instance took about `2^39.8` compression-equivalents and the 32-step
instance is the same problem. The dense part of the verified pair of Section 4.4 is one
such assignment and is the one used below; the cost charges a fresh solve.

**Step 1' (preprocessing, once): the second-block template.** Fix the tail words
`(W14*, W15*)` to those of the verified pair (`W14* = 89c67ae2`, `W15* = ac5eb7f9`,
Section 4.4). The state words at steps 14 and 15 of both messages depend only on the
dense part and on `(W14, W15)`, never on the chaining value:
`E14 = A10 + E10 + Sig1(E13) + IF(E13,E12,E11) + K14 + W14`, `A14 = E14 - A10 +
Sig0(A13) + MAJ(A13,A12,A11)`, likewise `E15, A15`, and the primed words with
`W'14 = W14 + (W'14 - W14)` fixed by `∇W14` and `W'15 = W15`. The template satisfies the
following conditions, all of them checked on the verified pair (Section 4.4):

- (T1) `(W14*, W'14*)`, `(E14, E'14)`, `(A14, A'14)` satisfy every glyph of Table 9 row 14;
- (T2) `∇W16 = 0`: `W9 + s1(W14*) = W'9 + s1(W'14*) (mod 2^32)`; and `∇W29 = 0`:
  `W13 + s0(W14*) = W'13 + s0(W'14*)`;
- (T3) the modular differences `E'15 - E15` and `A'15 - A15` are those of the
  characteristic;
- (T4) `(E15, E'15)`, `(A15, A'15)` satisfy every glyph of Table 9 row 15;
- (T5) the modular differences `E'16 - E16` and `A'16 - A16` computed with `W16 = 0` are
  those of the characteristic (they do not depend on `W16`, which is common to both
  messages by (T2), nor on the chaining value).

Store `s1(W14*)`, `s1(W15*)`, `base16 = A12 + E12 + Sig1(E15) + IF(E15,E14,E13) + K16`,
`base'16`, `off16 = -A12 + Sig0(A15) + MAJ(A15,A14,A13)`, `off'16`, and the rows
`12..15` of both messages: a few dozen words. No table is built. (A table of all
`(W14, W15)` satisfying (T1)-(T5) has about `2^21` entries; scanning it for every
accepted block would credit the accepted block with `2^21` candidates, which Section
7.3 shows is not justified. The present algorithm tests exactly one candidate per
accepted block.)

**Fixed budget.** The following quantities are fixed before the run and never adapted:

```
q     = 2^-14.1        lower bound on the first-block acceptance probability (Section 7.2)
pi    = 2^-57.3        lower bound on the per-accepted-block success probability (Sections 7.4, 7.9)
M     = ceil(0.70 / pi) = 2^56.785   cap on the number of accepted first blocks that are tested
N_b   = ceil(M * (1 + 2^-10) / q) = 2^70.887   number of first-block trials (all charged)
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

so `W0..W13` of the second block are fixed for this `B0`, and Step 3 is run once for
this block. Accepted blocks beyond the `M`-th are ignored. All `N_b` trials are charged
whether or not they are accepted, and whether or not a collision has already been
found (the run may stop early at a collision; the work bound charges the full budget).

**Step 3 (one template test per accepted block).** With `W14 = W14*`, `W15 = W15*`:
`W16 = W0 + s0(W1) + W9 + s1(W14*)` (common to both messages, because `∇W16 = 0`);
`E16 = base16 + W16`, `E'16 = base'16 + W16`, `A16 = E16 + off16`, `A'16 = E'16 +
off'16`. Test the row-16 conditions: the XOR of `(E16, E'16)` equals the `∇E16`
difference mask with the signs of Table 9; the seven `0/1` value bits of `∇E16`;
`A16 = A'16`; and the Table 10 relations `E16[0]!=E16[13]`, `E15[15]=E16[15]`,
`E15[24]=E16[24]`, `A14[29]=A16[29]` (the last three are value conditions on `E16`,
`A16` because `E15`, `A14` are fixed by the template). If they hold, continue:
`W17 = W1 + s0(W2) + W10 + s1(W15*)` and step 17 (`15` conditions), then steps 18 (`6`),
19 (`7`), 20 (`1`), 21 (`1`), with the expanded words `W18..W23` computed from the fixed
words; the `W21` conditions (`6` glyphs and `4` two-bit) and `W23` conditions (`1` glyph
and `3` two-bit) are tested when those words are formed. If all `57` uncontrolled
conditions hold, form `W24..W31` for both messages and test `W_i = W'_i` for
`i = 24..31` (the `W24, W25, W28, W29, W30` cancellations of Section 4.5, deterministic
given the conditions already tested), run steps `22..31` on both messages and test
that the eight final state words agree; the second blocks are then `M1 = (W0..W15)` and
`M1' = (W'0..W'15)`, the pair collides at 32 steps by Section 5, and the run outputs
`(B0 || M1, B0 || M1')` after the collision check below. Otherwise the block is
finished and the run proceeds to the next trial. If the budget is exhausted without a
collision, the run outputs failure.

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
operations and one expanded message word at `30`. No compression evaluated in full is
ever charged below one unit. The work bound is the worst case over the fixed budget of
Section 6: every one of the `N_b` first-block trials and the template test for each of
at most `M` accepted blocks are charged regardless of the random outcomes; no term is
an expectation. The total is dominated by the `N_b` full compressions, so the pricing of
the few word operations per accepted block does not affect the claim (Section 7.6).

### 7.1 Parameters

| symbol | meaning | value used | status |
|---|---|---|---|
| `c_unc` | printed uncontrolled conditions, steps `>= 16` | `57` | reproduced by counting Tables 9/10 (Section 4.3) |
| `q` | first-block acceptance probability, lower bound | `2^-14.1` (measured `2^-14.03`; lower confidence bound `2^-14.07`; published `2^-15`) | measured at 32 steps from the IV (Sections 7.2, 7.9) |
| `pi` | per-accepted-block success probability of the fixed template, lower bound | `2^-57.3` (measured `2^-56.99`; combined lower confidence bound `2^-57.19`) | per-step conditional profile of the template (Sections 7.4, 7.9) |
| SAT | one-time dense-part solve | `2^40` | published `2^39.8`; witnessed satisfiable (Section 8) |
| `M`, `N_b` | fixed budget | `2^56.785`, `2^70.887` | derived from `q`, `pi` (Section 6) |

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

### 7.3 One template per block: the withdrawn amortisation

An earlier version of this analysis scanned, for every accepted first block, a table
`V` of about `2^21` tail pairs `(W14, W15)` satisfying (T1)-(T5), and bounded the
per-block success probability by `1 - exp(-|V| p_c)` with `p_c` the average
per-candidate probability, i.e. it treated the candidates of one block as independent
trials. A direct measurement in the lab (`eng/results/006-independence`, program
`indep.c`; dense states sampled by varying the free bits of `W8..W13` and re-validating
steps `8..13`, 350 dense states; per-state step-16 survivor counts over `2^20` candidates
for 60 states) refuted that premise for this characteristic: the number of usable `W14`
per dense state is bimodal (`0` for `35%` of states, `272` otherwise, mean `2^7.4`
against `2^14.8` admissible), the per-state step-16 survivor counts are overdispersed
by a factor `10` relative to a binomial (`43%` of states with none), and single-bit
flips of `W14` never preserve step-16 conformance (`W15` offers about `8` neutral bits).
The candidates of one block are therefore not independent trials, and the amortisation
of `2^21` candidates per block is not credited here. The same data show that the
*expected* number of conforming candidates per block equals `|V| p_c` by linearity of
expectation, so the earlier `2^52.6` figure is the expected-work figure of a different
(non-fixed-budget) accounting; it is not claimed.

The present algorithm tests one fixed template per accepted block. The per-block
success indicators of distinct accepted blocks are independent because distinct first
blocks are fresh independent uniform strings and the template is fixed: the event
"the template conforms for block `t`" is a function of `B0_t` alone (through
`CV1 -> W0..W7 -> W16..W23`). This independence is a property of the algorithm's coins,
not a premise; the only premise about the tail is the value of the per-block
probability `pi` (heuristic `template-tail`, Section 8), which is a single-candidate
quantity measured in Section 7.4 and bounded in Section 7.9. The variation of the
per-candidate probability across templates is visible in Appendix B.3 (256 other
templates from the same table average `2^-58.07` against `2^-56.99` for the one used);
that average is not used.

### 7.4 Uncontrolled-part conditional probabilities (measured)

Program `localrate.c` (Appendix B.2; mode 1: dense rows `< 16`, including rows 14 and
15, fixed to the verified pair, i.e. to the template of Section 6) samples, for each
step `i = 16..21`, the uncontrolled input rows `16..i-1` uniformly among values
conforming to their Table 9 glyphs and Table 10 relations, and `W_i` uniformly with the
row's `∇W_i` pattern, and measures the probability that `(A_i, E_i)` satisfy row `i`
and its Table 10 relations (`2^26` samples per step for steps 16 and 17, seed 9; `2^22`
samples per step for steps 16..21, seed 5):

```
step   counted conditions   measured -log2 P     events / samples
 16          13                12.996              8217 / 2^26   (13.049 at 2^22)
 17          15                14.989              2063 / 2^26   (14.881 at 2^22)
 18           6                 6.002             65427 / 2^22
 19           7                 7.004             32681 / 2^22
 20           1                 0.999           2098138 / 2^22
 21           1                 1.001           2095425 / 2^22
 sum         43                42.99
```

The `14` remaining uncontrolled conditions are on `W21` (`10`) and `W23` (`4`), i.e.
`c_unc = 57`. The counted and measured profiles agree to `0.01` bits in total. The
product of the six measured factors and `2^-14` is `2^-56.99`; this is the per-block
probability `pi` of Section 7.5 (its lower confidence bound is Section 7.9).

### 7.5 Fixed-budget ledger (worst case)

Every term is a fixed count multiplied by a fixed per-item charge; no expectation
enters. Charges per item (Section 6):

- **First-block trial.** One full `C32` (`1` unit) plus the on-the-fly check: `E3`
  (add, sub, `Sig0` 14 ops, `MAJ` 5 ops, bit test: 24 ops), then `W7` (about 30 ops
  including `Sig1`, `IF`, five add/sub) with its signed-difference and three two-bit
  tests (about 12 ops), and likewise `W6`, `W5` when reached: at most `24 + 3 * 42 =
  150` operations if every stage is reached, charged as the worst case: `1 + 150/2224 =
  1.0674` units. (The average is below 48 operations; the worst case is charged.)
- **Accepted block.** Inversion of `W0..W7` for both messages (fewer than 300
  operations) and the template test of Step 3 including the full continuation to step
  31 in the worst case (`W16..W31` and steps `16..31` for both messages with all tests:
  at most `2 * (16 * 54 + 16 * 30) + 150 < 2900` operations): charged `300 + 4096 = 4396`
  operations, at most `M` times.
- **Preprocessing.** SAT solve of the dense part `2^39.8`: charged `2^40`.
- **Padding block, final digests, collision check.** Fewer than `8` compressions.

```
W = N_b * 1.0674          = 2^70.887 * 1.0674                 = 2^70.98   (block-1 trials)
  + M * 4396/2224         = 2^56.785 * 2^0.98                 = 2^57.77   (accepted-block tests)
  + 2^40 + 8                                                             (preprocessing, finish)
  = 2^70.98.
```

The script of Appendix B.6 evaluates the same ledger (`2^70.981`). The claimed bound
`time_log2 = 71.5` exceeds `2^70.98` by `0.52` bits.

Sensitivity of the budget (recomputing `M`, `N_b` and the work): `pi = 2^-57.5` gives
`2^71.18`; `pi = 2^-58.0` gives `2^71.68` (above the claim); `q = 2^-15` (the published
density) gives `2^71.88` (above the claim; with the measured `q` and the published
density both reported in Section 7.2, the claim rests on the measured value and its
confidence bound). Each bit less of `pi` or of `q` adds one bit to the total.

### 7.6 Pricing variants

Charging the accepted-block work as one whole compression per accepted block instead
of `4396` operations changes the total from `2^70.981` to `2^70.981` (the term is
`2^56.8` against `2^70.98`), so the claim does not depend on the pricing of partial
step evaluations. The expected-trials skeleton of ePrint 2026/1120 (`2^52` first-block
compressions and `2^57` tail candidates, `2^57.04` in total for 36 steps) credits each
first block with `2^20` tail candidates as independent trials; Section 7.3 explains why
that credit is not taken here. With the number of trials for success probability
`0.39` instead of `0.5` the total would be `2^70.48`; the claim uses `0.5`.

### 7.7 Success probability of the fixed budget, memory, data, preprocessing, advice

**Success probability.** The success event is that the run of Section 6 (fixed `N_b`,
`M`) outputs a pair of distinct messages with equal 32-step digests. The random coins
are the `N_b` fresh uniform first blocks; the dense part and the template are fixed. Let
`A` be the number of accepted blocks among the `N_b` trials and `F` the event that none
of the first `min(A, M)` accepted blocks passes the template test. The run fails only if
`A < M` or `F`; hence `Pr[fail] <= Pr[A < M] + Pr[F]`.

- `A` is binomial with `N_b` trials: the trials are independent (fresh uniform blocks)
  and each is accepted with the same probability `q_true`; by the heuristic
  `cv-coverage`, `q_true >= q = 2^-14.1`, so `E[A] = N_b q_true >= N_b q = M (1 + 2^-10)
  = mu`. The Chernoff lower tail `Pr[A <= (1 - d) mu] <= exp(-d^2 mu / 2)` with
  `(1 - d) mu = M`, `d = 2^-10 / (1 + 2^-10)`, gives `Pr[A < M] <= exp(-2^-20 * 2^56.787
  / 2.004) = exp(-5.9 * 10^10)`. (Monotonicity in `q_true` holds because `A` is
  stochastically larger for larger acceptance probability.)
- Conditioned on which trials are accepted, the template-test outcomes of the `M`
  accepted blocks are independent, because each is a function of its own block `B0_t`
  and the blocks are independent uniform strings; the acceptance event of a block and
  its template outcome are both functions of `B0_t`, so the outcomes of the accepted
  blocks are independent draws from the conditional law given acceptance. By the
  heuristic `template-tail`, each accepted block passes with probability `pi_true >=
  pi = 2^-57.3`; hence `Pr[F] <= (1 - pi)^M <= exp(-M pi) = exp(-0.70) = 0.4966`.

Therefore `Pr[success] >= 1 - 0.4966 - exp(-5.9 * 10^10) > 0.503`, and the declared
`success_probability = 0.5` holds for the fixed budget whose worst-case work is bounded
in Section 7.5. No independence between candidates of the same block is used: each
block contributes exactly one candidate. This is an algorithmic-coin probability for
the fixed target under the declared heuristics; it does not encode confidence in any
heuristic.

**Memory.** Online: the dense part, the template constants and the current block
(`< 2^12` bytes). The one-time SAT preprocessing used about `2^30.5` bytes in the
published run; `memory_log2_bytes = 31` covers that peak. Memory is reported, not
scored. If the exhibited dense assignment of Section 4.4 is reused instead of a fresh
solve, the fixed data it represents is `2^7` bytes.

**Data.** Every block-1 trial hashes one 64-byte block (`2^70.89 * 64 = 2^76.9`
bytes); every accepted block forms one second block. `data_log2 = 77` is a conservative
upper bound. No external, chosen-prefix or challenge data is used.

**Preprocessing.** `preprocessing_log2 = 40` covers the SAT solve; it is included in
`W` and is independent of the online coins.

**Non-uniform advice.** `nonuniform_advice_log2_bytes = 0`. The characteristic and the
template are a fixed published `O(1)` description; the dense-part solution is
recomputed in the charged preprocessing (the published solution could be reused, which
would only reduce the cost).

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
there versus `14.03 + (64 - 20.98) + 58.07 = 115.1` bits for the table of `2^20.98`
templates measured in Appendix B.3 (`+-1` bit from the `W29`/`W30` and `W23`
attributions), which is the expected agreement of two partitions of one probability
mass. The present ledger uses none of that freedom: it fixes one template and pays
`q` and `pi` per first block. The difference between that `2^70`, the earlier `2^52.6`
of this analysis and the present `2^71` lies in how many second-block candidates per
first block are credited as independent trials: `2^30` there, `2^21` in the earlier
version, and one here (Section 7.3). The joint measurements of that partition are
consistent with the counts used here: `8.0 = 2` (pattern bits) `+ 6` (step-16 implicit
conditions, `|V|` versus the visible `2^27`), `21.0 - 8.0 = 13.0` (row-16 value and
two-bit conditions plus the `E17` pattern, counted `14`), `33.4 - 21.0 = 12.4` (row-17
value and two-bit conditions, counted `12`).

### 7.9 Confidence bounds for the measured parameters and the combined budget

Every measured factor of Sections 7.2 and 7.4 is a binomial proportion `k/n` from a
stated number of independent pseudo-random trials. For each, the one-sided
Clopper-Pearson lower bound at `alpha = 10^-3` is the largest `p` with
`Pr[Bin(n, p) >= k] <= 10^-3` (exact binomial tail, evaluated in log space; the script
and its output are Appendix B.5).

```
factor                        k          n        estimate     lower bound   (bits)
q   (cvrate, Section 7.2)     16024      2^28     2^-14.032    2^-14.067     -0.035
P16 (localrate, 7.4)          8217       2^26     2^-12.996    2^-13.045     -0.050
P17                           2063       2^26     2^-14.989    2^-15.089     -0.100
P18                           65427      2^22     2^-6.002     2^-6.020      -0.017
P19                           32681      2^22     2^-7.004     2^-7.028      -0.025
P20                           2098138    2^22     2^-0.999     2^-1.001      -0.002
P21                           2095425    2^22     2^-1.001     2^-1.003      -0.002
```

The per-block probability `pi = P16 * P17 * P18 * P19 * P20 * P21 * 2^-14` (the last
factor the `14` counted `W21`/`W23` conditions) has point estimate `2^-56.99` and, taking
every measured factor at its lower bound, the combined lower bound `2^-57.19`. The budget
uses `pi = 2^-57.3 < 2^-57.19` and `q = 2^-14.1 < 2^-14.067`. By the union bound over the
seven one-sided bounds, both inequalities hold simultaneously with probability at least
`1 - 7 * 10^-3 = 0.993` over the sampling randomness of the measurements, and the
success bound of Section 7.7 is then valid as stated with the work bound of Section 7.5.
These bounds quantify the sampling error of each factor; they do not bear on the
composition premise under which the factors are multiplied (Section 7.10).

### 7.10 Nature of the evidence for `q` and `pi`, and the composition of the per-step factors

The organizer's protocol distinguishes analytic constructions from empirical ones: "an
analytic proof need not include a meaningless empirical program"
(`docs/FRONTIER_LANES.md`, "Executable heuristic evidence"), and "no experiment
manifest is needed for a self-contained analytic argument that does not rely on
experiments" (`docs/CANDIDATE_QUALIFICATION.md`). The quantities on which the cost
bound depends are of the following kinds.

- `c_unc = 57`, the template conditions (T1)-(T5) and the eight cancellation
  probabilities of Section 4.5 are exact counts and exact enumerations from the
  published tables and the step function (Sections 4.3, 4.5, 6).
- `q` is the density of a fixed, explicitly stated event (fifteen conditions on
  `E3, W5, W6, W7` derived from `C32(IV, B0)` and the fixed dense part) under the uniform
  distribution of `B0`. It is measured with a program that computes the 32-round
  compression and is self-tested against the published first block and the 32-step
  second-block collision that the trusted reference confirms (Appendix B.1); the
  program, its seed and its output are in the package, and its lower confidence bound
  is in Section 7.9. The published attack measured the same density at 36 steps as
  `2^-15`; the difference is accounted for by the `E3`/`W7` redundancy (Section 7.2).
- The per-step factors `P16..P21` are conditional probabilities of explicitly stated
  events (row `i` of Table 9 and its Table 10 relations) under an explicitly stated input
  distribution (the fixed template rows `<= 15`; rows `16..i-1` uniform over their
  conforming values; `W_i` uniform with its prescribed difference); the program, seeds
  and outputs are Appendix B.2, with confidence bounds in Section 7.9. The published
  construction reports the same conditions in aggregate (`57`), and the measured sum of
  the six state factors is `42.99` bits against the count `43`.

**Composition of the per-step factors for one template.** For an accepted block, let
`C_i` be the event that row `i` and its Table 10 relations hold for the template
(`i = 16..21`), and `C_W` the event that the `W21` and `W23` conditions hold. By the
chain rule, exactly,

```
pi_true = Pr[C_16] * Pr[C_17 | C_16] * ... * Pr[C_21 | C_16..C_20] * Pr[C_W | C_16..C_21],
```

the probability being over the accepted block `B0`, which enters only through
`W0..W7` and hence through the expanded words `W16..W23` (`W16 = W0 + s0(W1) + W9 +
s1(W14*)`, `W17 = W1 + s0(W2) + W10 + s1(W15*)`, `W18 = W2 + s0(W3) + W11 + s1(W16)`,
`W19 = W3 + s0(W4) + W12 + s1(W17)`, `W20 = W4 + s0(W5) + W13 + s1(W18)`, and so on).
Each conditional factor is the probability of a condition on `(A_i, E_i)` whose inputs
are the four preceding rows and `W_i`. The measured factor `P_i` is the same
probability with the preceding uncontrolled rows distributed uniformly over their
conforming values and `W_i` uniform with its prescribed difference; the free bits of the
true prefix (given conformance) and the true `W_i` (a function of the block) are replaced
by uniform bits. This replacement is the content of the heuristic `template-tail`: for a
uniformly random accepted block, the words `W16..W23` are, for the purposes of these
conditions, uniformly distributed and carry no further information about the next
row beyond the conformance of the earlier rows. For step 16 the prefix is exactly the
template (rows `12..15` fixed), so `P16` is the true factor up to the uniformity of
`W16`; the replacement of the prefix distribution is assumed from step 17 onward and
for `C_W`. The factor `Pr[C_W | ...] = 2^-14` is the count of the fourteen `W21`/`W23`
glyph and two-bit conditions, each a single-bit condition on a word that is affine in
the block-dependent words with fixed additive constants, taken as independent. The
`W28` and `W25` cancellations then follow deterministically (Section 4.5). No
composition across candidates is involved: the template is one candidate, and the
success indicators of distinct blocks are independent by construction (Section 7.3).
The evidence for this composition is the agreement of the measured factors with the
printed counts (`12.996 / 14.989 / 6.002 / 7.004 / 0.999 / 1.001` against
`13 / 15 / 6 / 7 / 1 / 1`), the published colliding pair obtained with the same
condition set at 36 steps, and the organizer-run cancellation experiments for the local
transitions; the joint event itself, of probability about `2^-57`, is not observed, and
the composition remains a declared heuristic.

## 8. Heuristics, evidence and limitations

Four premises are declared in `claim.json`. The fixed-budget success bound of Section
7.7 is a theorem given `cv-coverage` and `template-tail`; no further premise is used
there. The programs behind the lab measurements cited below are reproduced in full,
with their recorded outputs, in Appendix B. The earlier premise that the candidates of
one first block succeed independently is not declared and not used (Section 7.3).

- `cost-transfer-32` (score-critical). The condition set of the published 36-step
  characteristic, evaluated at rounds `0..31`, is the complete set of conditions for a
  32-step collision of the second block: no condition is added by truncation and none
  is lost. Evidence: the structural argument of Section 5(a) (support at index `<= 30`,
  `W31` difference-free, identical automatic behaviour of `W32..W35` at 36 steps) and
  the trusted-verifier measurements of Section 5(b) on two independent published
  instances. Limitation: the published condition set is taken as complete for the
  published attack; the lab reproduced its counts (Section 4.3) and its conditional
  profile (Section 7.4) but did not re-derive the characteristic from scratch.

- `cv-coverage` (score-critical). A uniformly random first block `B0` is accepted by
  the 15-condition filter of Section 6, Step 2 with probability `q_true >= q = 2^-14.1`.
  Evidence: the measurement of Section 7.2 (program `cvrate.c`, Appendix B.1, with its
  recorded output: `2^28` uniform blocks compressed with 32 rounds from the standard IV,
  seed 7, `16024` accepted, `2^-14.03`, lower confidence bound `2^-14.07` at `alpha =
  10^-3`, Section 7.9, per-condition-group breakdown), and the published measurement at
  36 steps (`2^-15` over `2^40` blocks). Scope: the fixed dense solution of the verified
  pair; the standard IV; 32 rounds. Limitation: the measurement is lab-run, not
  organizer-run (the organizer's experiment harness checks only digest-XOR events on
  complete messages and cannot express this acceptance predicate, Section 9); another
  dense solution would have its own density with the same counted conditions; with
  the published `2^-15` the budget would exceed the claim by `0.4` bits (Section 7.5).

- `template-tail` (score-critical). For a uniformly random accepted first block, the
  fixed template `(W14*, W15*)` passes all `57` uncontrolled conditions with probability
  `pi_true >= pi = 2^-57.3`, where `pi_true` equals the chain-rule product of the
  per-step conditional probabilities measured under uniformly distributed conforming
  prefixes and uniform expanded words (Section 7.10). Evidence: the per-step profile of
  Section 7.4 (program `localrate.c`, Appendix B.2: `12.996 / 14.989 / 6.002 / 7.004 /
  0.999 / 1.001` bits against the counts `13 / 15 / 6 / 7 / 1 / 1`; product with `2^-14`:
  `2^-56.99`; combined lower confidence bound `2^-57.19`, Section 7.9), the published
  colliding pair obtained with the same condition set at 36 steps, and the organizer-run
  local cancellation experiments (Section 9). Scope: one candidate per block; the dense
  solution and template of the verified pair. Limitation: the joint event (probability
  about `2^-57`) is not observed; the replacement of the true conditional distribution
  of `W17..W23` and of the free prefix bits by uniform bits is assumed from step 17
  onward; the measurement is lab-run. Each bit less of `pi` adds one bit to the total
  (`pi = 2^-58` gives `2^71.68`, above the claim).

- `sat-preprocessing-bound` (supporting). The dense system of the characteristic is
  satisfiable and the one-time preprocessing of Step 1 costs at most `2^40`. Existence
  is witnessed: the dense assignment of Section 4.4 satisfies every dense condition
  (checked in Section 4.4 and realised by the trusted-verifier collision of Section
  5(b)); a fresh solve of the same instance is reported at `2^39.8` in ePrint 2026/1120
  Section 4.2 (the dense part lives at steps `0..15` and is the same instance at 32 and
  36 steps); `2^40` is charged. Limitation: the fresh-solve figure is not independently
  timed; the term is `2^40` of `2^70.98`, so a figure up to `2^30` larger would leave the
  claimed bound unchanged, and reusing the witness removes the term.

Not heuristic: the target definition, the padding block, the two-block collision
correctness given a conforming pair (Section 5), the condition counts (Section 4.3),
the characteristic/pair consistency (Section 4.4), the exact cancellation
probabilities (Section 4.5), the independence of the per-block outcomes (Section 7.3),
and the fixed-budget arithmetic (Sections 7.5, 7.7).

## 9. Experiments

The manifest declares nine organizer-run experiments. `add-3bit-aligned-cancel-exact`
is an exhaustive 8-bit count (`da = db = 0x15`, `dc = 0`, exactly `8192/65536 = 2^-3`),
the finite-width analogue of the `W20`, `W22`, `W29` cancellations (identical three-bit
patterns on both operands); `add-carry-cancel-exact` is an exhaustive 8-bit count
(`da = 0x4c`, `db = 0x54`, `dc = 0`, exactly `4096/65536 = 2^-4`), the analogue of the
`W16`, `W25`, `W28` cancellations (patterns differing in one position, cancelling
through a carry). `expansion-cancel-W16`, `-W20`, `-W22`, `-W25`, `-W28`, `-W29`, `-W30`
are 32-bit `addition-xor-sampled-v1` experiments with exactly the XOR input differences
of Section 4.5 and output difference `0`; their exact uniform-input probabilities are
`2^-4, 2^-3, 2^-3, 2^-4, 2^-4, 2^-3, 2^-1` (expected successes `16, 32, 32, 16, 16, 32,
128` of 256).

What these experiments establish and what they do not:

- Each is a local finite check of one isolated modular addition under uniform ordered
  inputs: the two exact counts are theorems about 8-bit addition; the seven sampled
  tests report organizer-recomputed success counts on 256 organizer-seeded samples
  each (the sample count is fixed by the organizer and cannot be raised by the
  candidate), with the Hoeffding intervals the organizer runner reports under its own
  stated assumption. The package makes no claim that the public-seed samples are
  representative beyond the reported counts, no holdout claim, and no
  multiple-comparison correction; the seven sampled experiments are all the
  two-operand cancellations of the characteristic except `W24` (expected `0.5`
  successes in 256 samples), a selection rule fixed before any sample was seen, and
  their expected counts were computed beforehand (Section 4.5).
- They do not establish the joint probability of the 57 uncontrolled conditions, the
  behaviour of conditioned operands inside the attack (where the signs of one operand
  are fixed, last column of Section 4.5), dependence across steps or across candidates
  sharing a first block (which the present accounting does not credit, Section 7.3),
  or the per-block probability `pi`. That quantity rests on the measured per-step
  factors of Section 7.4 composed by the chain rule (Section 7.10) and is the declared
  heuristic `template-tail`; it is not claimed as experimentally proven.
- The score-critical measurements (`q` and the per-step factors of `pi`) are not organizer-run. The
  organizer's `python-message-pairs-v1` harness checks only two events on complete
  messages, full collision or a digest-XOR mask, and the first-block acceptance
  predicate (fifteen conditions on `E3, W5, W6, W7` derived from one chaining value
  and the dense part) is not a function of a digest XOR of two messages, so it cannot
  be declared as an organizer-recomputed event; an output-XOR-mask event on complete
  messages from the standard IV would require the second-block collision itself (the
  common padding block re-randomises any residual difference, and `W14` is active so
  the second block cannot be the final padded block), which is the full `2^71`
  attack. Instead, the programs and their recorded outputs are reproduced in full in
  Appendix B so that the measurements can be repeated from the package alone. A fresh
  conforming pair was also not found by a one-hour nldtool search from the
  characteristic, as expected at this cost.

## 10. What is proved, measured and heuristic

- Proved (from the definitions): the target semantics; that a conforming second-block
  pair from a valid `CV1` gives equal digests after the common padding block; that the
  condition set at 32 steps equals the published set (Section 5(a)); the exact
  cancellation probabilities of Section 4.5; the independence of the per-block outcomes
  (Section 7.3).
- Measured with the trusted reference: the 32-step second-block collision of the Table
  2 pair from `CV1 = C36(IV, M0)` and of the Table 11 pair (Section 5(b)); the
  consistency of Table 9/10 with the pair (Section 4.4).
- Measured with lab code checked against the reference: `q = 2^-14.03` at 32 steps
  from the IV (Section 7.2); the per-step profile of the template, `42.99` bits versus
  `43` counted, giving `pi = 2^-56.99` (Section 7.4); their confidence bounds (Section
  7.9); the refutation of the earlier within-block independence premise (Section 7.3).
- Inherited from ePrint 2026/1120: the characteristic itself, `c_unc = 57` (count
  reproduced and profile measured), and the SAT cost `2^39.8` (declared as
  `sat-preprocessing-bound`).
- Proved given the heuristics: the fixed-budget success bound `> 0.503` and the
  worst-case work `2^70.98` (Sections 7.5, 7.7); the confidence bounds of Section 7.9
  place the two measured parameters used there below their lower bounds.
- Heuristic: the chain-rule composition for one template (`template-tail`), the lower
  bound `q`, and the SAT preprocessing cost (Section 8). The organizer experiments
  (Section 9) support only the local cancellation transitions, not these quantities.

Not exploited: any amortisation over several second-block candidates of one first
block. If a lower bound on the per-block probability with `T` candidates per block
could be established (for instance by measuring the distribution of the number of
conforming candidates per block at an intermediate step), the block count would fall
by up to a factor `T`; no such bound is claimed. The published expected-work figure
for 36 steps (`2^57`) rests on such an amortisation over `2^20` candidates per block.

No full-scale 32-step colliding message is exhibited (the attack costs about `2^71`
compressions), so the certificate manifest is empty. The claim is an advantage over the
generic bound at `time_log2 = 71.5`, not an improvement over any prior 32-step attack,
since none has been published.

## Appendix A. Index: where each claim is stated and supported

Cross-reference from each statement of this document to the section where it is
established, with its nature (definition, proof from the definitions, trusted-verifier
measurement, lab measurement, or declared heuristic).

**Target and construction.**

- Target definition (profile, IV, padding, rounds `0..31` on every block, feed-forward,
  full digest, distinct messages): Section 1 (definition).
- Algorithm: Section 6 (preprocessing Step 1; the template and its conditions
  (T1)-(T5), Step 1'; fixed budget `q, pi, M, N_b`; Step 2 with the check equations;
  Step 3, one template test per accepted block; output and failure rule).
- Cost vector: `claim.json:/claim`; time `71.5` (Section 7.5), memory `31` (Section 7.7),
  data `77` (Section 7.7), preprocessing `40` (Section 7.5), success `0.5` (Section
  7.7), advice `0` (Section 7.7).
- Probability space and success event: Section 7.7, first paragraph (coins = the `N_b`
  fresh first blocks; event = output of a colliding pair within the fixed budget).
- Declared heuristics: Section 8 (four premises; the success bound of Section 7.7 uses
  `cv-coverage` and `template-tail`; the preprocessing term uses
  `sat-preprocessing-bound`). The withdrawn within-block independence premise:
  Section 7.3.

**Collision correctness.**

- The condition set at 32 steps equals the published set and steps `24..31` run on
  identical states: Section 5(a) (proof from the definitions).
- Two published instances collide at 32 steps under
  `verifier/hash_functions.py:_compress`: Section 5(b) (trusted-verifier measurement);
  consistency of Tables 9/10 with the pair: Section 4.4.
- Padding block common to both messages: Section 6, last paragraph (definition).

**Probability of the characteristic.**

- `57` uncontrolled conditions counted from Tables 9 and 10: Section 4.3 (count).
- Per-step conditional profile of the template, `42.99` versus `43` bits, `pi =
  2^-56.99`: Section 7.4 (lab measurement); program and outputs: Appendix B.2.
- Exact probabilities of the eight two-operand expansion cancellations (`W16, W20,
  W22, W24, W25, W28, W29, W30`) and where each is enforced: Section 4.5 (enumeration);
  their role in the 32-step collision: Section 5(a); their check in the template test:
  Section 6, Step 3.
- Alternative partition of the same conditions and agreement of the totals: Section 7.8.
- Chain-rule composition for one template and where uniformity is assumed: heuristic
  `template-tail`, Sections 7.10 and 8.
- Independence of the per-block outcomes (fresh first blocks): Section 7.3 (proof from
  the algorithm's coins); the refuted within-block premise and its measurement:
  Section 7.3.

**Cost.**

- Worst-case charged work over the fixed budget, `W = 2^70.98`: Section 7.5. The ledger
  charges a fixed worst-case budget of fixed counts (`N_b` trials, `M` accepted-block
  tests, the preprocessing, the finish), each at a fixed per-item charge.
- Charged categories: first-block trials including rejected ones; accepted-block
  inversion and template test with full continuation; preprocessing; padding block and
  final digests: Section 7.5.
- Pricing variants and the expected-trials skeleton of the published attack: Section 7.6.
- Success probability of the fixed budget, `Pr[fail] <= Pr[A < M] + Pr[F] < 0.497`:
  Section 7.7 (Chernoff lower tail for `A`; `(1 - pi)^M` for `F` using only across-block
  independence; a proof given the two heuristics named there).
- Memory, data, preprocessing, advice: Section 7.7.
- Sensitivity to `pi`, `q`: Section 7.5, last paragraph.
- One-sided confidence bounds for every measured factor and the combined budget
  check: Section 7.9 (script and output: Appendix B.5); the budget computation: Appendix
  B.6.
- Kind of evidence behind `q` and `P16..P21` and the chain-rule composition: Section 7.10.

**Measured parameters.**

- First-block acceptance `q = 2^-14.03` from the standard IV over `2^28` blocks:
  Section 7.2 (lab measurement); program and recorded output: Appendix B.1.
- Per-step conditional profile of the template (`2^26` samples for steps 16, 17; `2^22`
  for steps 16..21): Section 7.4; program and recorded outputs: Appendix B.2.
- Variation of the per-candidate probability across other templates of the same table
  (not used in the cost): Section 7.3; program and output: Appendix B.3.
- Inputs shared by these programs (the verified pair's states and words; the Table 9
  glyph strings): Appendix B.4.
- These measurements were run in the lab, not by the organizer, and the organizer
  harness cannot express their predicates; Sections 8, 9 and 10 say so.

**Experiments.**

- The nine declared experiments and what each establishes (local finite counts of
  single additions only; neither the joint 57-condition probability nor the per-block
  probability is derived from them): Section 9.
- Statistical treatment of the sampled experiments and the selection rule for the seven
  cancellations: Section 9.

## Appendix B. Programs behind the lab measurements, with recorded outputs

Each program below is reproduced verbatim. They were compiled with `clang -O2` and
run single-threaded on one machine; every run is deterministic given the seed on its
command line (xoshiro-style generator seeded as shown in the source). The programs
use only the data of Sections 4.4 and 4.1 (Appendix B.4) and re-implement the SHA-256
step function; `cvrate.c` additionally re-implements the 32-round compression and
self-tests it against the published 36-step first block and the 32-step second-block
collision that the trusted reference confirms (Section 5(b)), so any discrepancy with
the reference would abort the run.

### B.1 cvrate.c: first-block acceptance from the standard IV (Section 7.2)

Measures the fraction of uniformly random 64-byte blocks `B0` whose 32-round chaining
value `C32(IV, B0)` passes the fifteen first-block conditions of Section 6, Step 2,
with the dense part fixed to the verified pair (`ref.h`, B.4). Command line:
`./cvrate 28 7` (`2^28` blocks, seed 7). Recorded output:

```text
self-tests ok
trials 2^28 seed 7
E3[29]=1             pass    134206884  cum log2 rate   -1.000
+W7 signed diff      pass    130335615  cum log2 rate   -1.042
+W7 2-bit (3)        pass     16293941  cum log2 rate   -4.042
+W6 signed diff      pass      2037434  cum log2 rate   -7.042
+W6 2-bit (3)        pass       254476  cum log2 rate  -10.043
+W5 signed diff      pass       127211  cum log2 rate  -11.043
+W5 2-bit (3)        pass        16024  cum log2 rate  -14.032
c_cv(32-step, from IV) = 14.032  (paper 36-step: 15; 95% rel. err ~ 1.5%)
```

Source:

```c
// cvrate: measure, at 32 steps and from the STANDARD IV, the density of first blocks B0 whose
// chaining value CV1 = C32(IV,B0) satisfies the 15 first-block conditions of the 2026/1120
// 36-step characteristic (1 on E3, 4 on W5, 6 on W6, 4 on W7; ePrint 2026/1120 Sec. 4.2 and
// Table 10) with the dense part fixed to the verified pair (eng/results/005-conditions-r32/ref.h,
// arrays indexed [i+4]).  Prints cumulative pass counts per condition group.
// Usage: cvrate <log2 trials> <seed>.   Single thread, O(1) memory.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "../eng/results/005-conditions-r32/ref.h"
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S0(a) (ROR(a,2)^ROR(a,13)^ROR(a,22))
#define S1(e) (ROR(e,6)^ROR(e,11)^ROR(e,25))
#define s0(x) (ROR(x,7)^ROR(x,18)^((x)>>3))
#define s1(x) (ROR(x,17)^ROR(x,19)^((x)>>10))
#define IF(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
static const uint32_t K[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static const uint32_t IV[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
static uint64_t st[2];
static inline uint64_t rotl(uint64_t x,int k){return (x<<k)|(x>>(64-k));}
static inline uint64_t nxt(void){uint64_t a=st[0],b=st[1],r=a+b;b^=a;st[0]=rotl(a,55)^b^(b<<14);st[1]=rotl(b,36);return r;}
static inline uint32_t r32(void){return (uint32_t)(nxt()>>32);}
// standard SHA-256 compression truncated to R rounds, with feed-forward (== verifier _compress)
static void compress(const uint32_t*in,const uint32_t*blk,int R,uint32_t*out){
  uint32_t w[64]; memcpy(w,blk,64);
  for(int i=16;i<R;i++) w[i]=w[i-16]+s0(w[i-15])+w[i-7]+s1(w[i-2]);
  uint32_t a=in[0],b=in[1],c=in[2],d=in[3],e=in[4],f=in[5],g=in[6],h=in[7];
  for(int i=0;i<R;i++){uint32_t t1=h+S1(e)+IF(e,f,g)+K[i]+w[i],t2=S0(a)+MJ(a,b,c);h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  out[0]=in[0]+a;out[1]=in[1]+b;out[2]=in[2]+c;out[3]=in[3]+d;out[4]=in[4]+e;out[5]=in[5]+f;out[6]=in[6]+g;out[7]=in[7]+h;
}
static inline int sgn_ok(uint32_t x,uint32_t xp,uint32_t rx,uint32_t rxp){uint32_t d=rx^rxp;return ((x^xp)==d)&&((x&d)==(rx&d));}
#define B(x,k) (((x)>>(k))&1u)
// returns number of condition groups passed in order: 1 E3, 2 W7 signed, 3 W7 2-bit, 4 W6 signed, 5 W6 2-bit, 6 W5 signed, 7 W5 2-bit
static int check(const uint32_t*cv){
  uint32_t Am1=cv[0],Am2=cv[1],Am3=cv[2]; // A_{-1},A_{-2},A_{-3}; E_{-i} unused by the 15 conditions
  const uint32_t A0=RA[4],A1=RA[5],A2=RA[6],A3=RA[7];
  const uint32_t E4=RE[8],E5=RE[9],E6=RE[10],E7=RE[11],E5p=REp[9],E6p=REp[10],E7p=REp[11];
  uint32_t E3=A3+Am1-S0(A2)-MJ(A2,A1,A0);
  if(B(E3,29)!=1) return 0;
  uint32_t E2=A2+Am2-S0(A1)-MJ(A1,A0,Am1);
  uint32_t E1=A1+Am3-S0(A0)-MJ(A0,Am1,Am2);
  uint32_t W7=E7-A3-E3-S1(E6)-IF(E6,E5,E4)-K[7], W7p=E7p-A3-E3-S1(E6p)-IF(E6p,E5p,E4)-K[7];
  if(!sgn_ok(W7,W7p,RW[7],RWp[7])) return 1;
  if(!(B(W7,1)!=B(W7,12) && B(W7,8)==B(W7,25) && B(W7,14)!=B(W7,18))) return 2;
  uint32_t W6=E6-A2-E2-S1(E5)-IF(E5,E4,E3)-K[6], W6p=E6p-A2-E2-S1(E5p)-IF(E5p,E4,E3)-K[6];
  if(!sgn_ok(W6,W6p,RW[6],RWp[6])) return 3;
  if(!(B(W6,0)!=B(W6,28) && B(W6,9)==B(W6,30) && B(W6,1)!=B(W6,18))) return 4;
  uint32_t W5=E5-A1-E1-S1(E4)-IF(E4,E3,E2)-K[5], W5p=E5p-A1-E1-S1(E4)-IF(E4,E3,E2)-K[5];
  if(!sgn_ok(W5,W5p,RW[5],RWp[5])) return 5;
  if(!(B(W5,1)!=B(W5,12) && B(W5,8)!=B(W5,25) && B(W5,18)!=B(W5,14))) return 6;
  return 7;
}
int main(int argc,char**argv){
  int lg=argc>1?atoi(argv[1]):24; uint64_t seed=argc>2?strtoull(argv[2],0,0):1;
  st[0]=0x9e3779b97f4a7c15ull^(seed*0x100000001b3ull); st[1]=0xbf58476d1ce4e5b9ull; for(int i=0;i<50;i++)nxt();
  // self-test 1: the verified pair's CV1 (= C36(IV,M0) of the published attack) passes all 7 groups
  uint32_t cvref[8]={RA[3],RA[2],RA[1],RA[0],RE[3],RE[2],RE[1],RE[0]};
  if(check(cvref)!=7){fprintf(stderr,"self-test FAILED: reference CV1 passes only %d groups\n",check(cvref));return 1;}
  // self-test 2: compress() matches the published 36-step first block: C36(IV,M0) == CV1
  uint32_t M0[16]={0xd7c6ac05,0x3be3567b,0x33c02b26,0x3a6dfd82,0xed46810e,0x8dacae35,0x3e004584,0x26d29992,0x39cff659,0x0acc2223,0x8e77b3b0,0xcc7f4bba,0x9ff3abea,0x17606f86,0xce693676,0xc3bc18aa};
  uint32_t o[8]; compress(IV,M0,36,o); if(memcmp(o,cvref,32)){fprintf(stderr,"self-test FAILED: compress(36) != CV1\n");return 1;}
  // self-test 3: 32-step second-block collision from CV1 with the published pair
  uint32_t o1[8],o2[8]; compress(cvref,RW,32,o1); compress(cvref,RWp,32,o2); if(memcmp(o1,o2,32)){fprintf(stderr,"self-test FAILED: no 32-step collision\n");return 1;}
  fprintf(stderr,"self-tests ok\n");
  uint64_t N=1ull<<lg, cum[8]={0}; uint32_t blk[16],cv[8];
  for(uint64_t n=0;n<N;n++){ for(int i=0;i<16;i++)blk[i]=r32(); compress(IV,blk,32,cv); int g=check(cv); for(int k=1;k<=g;k++)cum[k]++; }
  const char*names[8]={"","E3[29]=1","+W7 signed diff","+W7 2-bit (3)","+W6 signed diff","+W6 2-bit (3)","+W5 signed diff","+W5 2-bit (3)"};
  printf("trials 2^%d seed %llu\n",lg,(unsigned long long)seed);
  for(int k=1;k<=7;k++) printf("%-20s pass %12llu  cum log2 rate %8.3f\n",names[k],(unsigned long long)cum[k],cum[k]?log2((double)cum[k]/N):-INFINITY);
  printf("c_cv(32-step, from IV) = %.3f  (paper 36-step: 15; 95%% rel. err ~ %.1f%%)\n",-log2((double)cum[7]/N),cum[7]?196.0/sqrt((double)cum[7]):0.0);
  return 0;
}
```

### B.2 localrate.c: per-step conditional profile of the template (Section 7.4)

For each step `i` in the requested range, samples the input rows conforming to Table 9
(and the Table 10 relations at rows `>= 16`), with the dense rows `< 16` (including the
template rows 14, 15) fixed to the verified pair (mode 1) or sampled within their
printed glyphs (mode 0), and measures the probability that `(A_i, E_i)` satisfy row `i`
and its Table 10 relations. Command lines: `./localrate 26 9 1 16 17` (mode 1, `2^26`
samples per step, steps 16 and 17, seed 9), `./localrate 22 5 1` (mode 1, `2^22`
samples per step, steps 16..21, seed 5) and `./localrate 24 3` (mode 0, `2^24` samples
per step, seed 3). Recorded outputs:

```text
mode: dense rows <16 fixed to the verified pair; uncontrolled rows 16..i-1 sampled conforming
trials per step 2^26, seed 9
step 16: counted conditions 13 (A 0, E 9, two-bit 4) | measured -log2 P = 12.996  (8217/67108864, prefix rejections 0)
step 17: counted conditions 15 (A 0, E 12, two-bit 3) | measured -log2 P = 14.989  (2063/67108864, prefix rejections 1006598404)
sum steps 16..17: counted 28, measured 27.985  (+ 14 counted conditions on W21,W23 => c_unc counted 57)
```

```text
mode: dense rows <16 fixed to the verified pair; uncontrolled rows 16..i-1 sampled conforming
trials per step 2^22, seed 5
step 16: counted conditions 13 (A 0, E 9, two-bit 4) | measured -log2 P = 13.049  (495/4194304, prefix rejections 0)
step 17: counted conditions 15 (A 0, E 12, two-bit 3) | measured -log2 P = 14.881  (139/4194304, prefix rejections 62946111)
step 18: counted conditions  6 (A 0, E 6, two-bit 0) | measured -log2 P =  6.002  (65427/4194304, prefix rejections 532910842)
step 19: counted conditions  7 (A 0, E 6, two-bit 1) | measured -log2 P =  7.004  (32681/4194304, prefix rejections 532511439)
step 20: counted conditions  1 (A 0, E 1, two-bit 0) | measured -log2 P =  0.999  (2098138/4194304, prefix rejections 1069285195)
step 21: counted conditions  1 (A 0, E 1, two-bit 0) | measured -log2 P =  1.001  (2095425/4194304, prefix rejections 62919016)
sum steps 16..21: counted 43, measured 42.937  (+ 14 counted conditions on W21,W23 => c_unc counted 57)
```

```text
trials per step 2^24, seed 3
step 16: counted conditions 13 (A 0, E 9, two-bit 4) | measured -log2 P = 19.608  (21/16777216, prefix rejections 0)
step 17: counted conditions 15 (A 0, E 12, two-bit 3) | measured -log2 P = 16.063  (245/16777216, prefix rejections 251658136)
step 18: counted conditions  6 (A 0, E 6, two-bit 0) | measured -log2 P =  5.999  (262373/16777216, prefix rejections 2129902975)
step 19: counted conditions  7 (A 0, E 6, two-bit 1) | measured -log2 P =  7.004  (130741/16777216, prefix rejections 2130991405)
step 20: counted conditions  1 (A 0, E 1, two-bit 0) | measured -log2 P =  0.999  (8393415/16777216, prefix rejections 4279045745)
step 21: counted conditions  1 (A 0, E 1, two-bit 0) | measured -log2 P =  1.000  (8387259/16777216, prefix rejections 251570456)
sum steps 16..21: counted 43, measured 50.673  (+ 14 counted conditions on W21,W23 => c_unc counted 57)
```

Source:

```c
// localrate: measured conditional probabilities of the UNCONTROLLED state conditions of the
// 2026/1120 36-step SHA-256 characteristic (Table 9 rows 16..21 for A_i,E_i plus the Table 10
// two-bit relations at i>=16), one step at a time, under the standard "conforming prefix" model:
//   inputs A_{i-4..i-1}, E_{i-4..i-1}, W_i are sampled uniformly among values that satisfy their own
//   Table 9 row (glyphs 0/1/n/u fixed, '=' and '+' free) and the Table 10 relations on rows < i;
//   the event is that (A_i, E_i) satisfy row i (all glyphs, '+' read as '=') and the Table 10
//   relations of row i.
// Steps 22..31 carry no state conditions (rows all '='); W-word conditions (W21: 10, W23: 4) are not
// measured here (they are message-expansion conditions; see the sampled experiments).
// Prints per-step -log2 rate next to the counted number of conditions; the counted sum is 43.
// Usage: localrate <log2 trials per step> <seed> [fixdense 0/1] [first step] [last step]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "rows.h"
#include "../eng/results/005-conditions-r32/ref.h"   // RA,RE,RAp,REp,RW,RWp indexed [i+4]: verified pair (dense part fixed)
static int FIXDENSE=0;
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S0(a) (ROR(a,2)^ROR(a,13)^ROR(a,22))
#define S1(e) (ROR(e,6)^ROR(e,11)^ROR(e,25))
#define IF(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define B(x,k) (((x)>>(k))&1u)
static const uint32_t K[32]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967};
static uint64_t st[2];
static inline uint64_t rotl(uint64_t x,int k){return (x<<k)|(x>>(64-k));}
static inline uint64_t nxt(void){uint64_t a=st[0],b=st[1],r=a+b;b^=a;st[0]=rotl(a,55)^b^(b<<14);st[1]=rotl(b,36);return r;}
static inline uint32_t r32(void){return (uint32_t)(nxt()>>32);}
// glyph masks per row string: v0/v1 bits fixed to 0/1 ; n: x=1,x'=0 ; u: x=0,x'=1 (paper convention)
typedef struct{uint32_t m0,m1,mn,mu;} G;
static G glyph(const char*s){G g={0,0,0,0};for(int k=0;k<32;k++){uint32_t b=1u<<(31-k);switch(s[k]){case '0':g.m0|=b;break;case '1':g.m1|=b;break;case 'n':g.mn|=b;break;case 'u':g.mu|=b;break;default:break;}}return g;}
static inline void sample(const G*g,uint32_t*x,uint32_t*xp){uint32_t r=r32();uint32_t fixed=g->m0|g->m1|g->mn|g->mu;uint32_t v=(r&~fixed)|g->m1|g->mn;uint32_t vp=(r&~fixed)|g->m1|g->mu;*x=v;*xp=vp;}
static inline int conform(const G*g,uint32_t x,uint32_t xp){uint32_t fixed=g->m0|g->m1|g->mn|g->mu; if((x&fixed)!=(g->m1|g->mn))return 0; if((xp&fixed)!=(g->m1|g->mu))return 0; return ((x^xp)&~fixed)==0;}
static int ncond(const G*g){return __builtin_popcount(g->m0|g->m1|g->mn|g->mu);}
// Table 10 relations at i>=16 (A: A14[29]=A16[29]; A16[29]=A17[29]; E16[0]!=E16[13], E15[15]=E16[15], E15[24]=E16[24];
// E17[6]!=E17[19], E17[2]=E17[20]; E19[2]=E19[16])
static int t10_ok(int i,const uint32_t*A,const uint32_t*E){ // arrays indexed [i+4]
  switch(i){
    case 16: return B(A[18],29)==B(A[20],29) && B(E[20],0)!=B(E[20],13) && B(E[19],15)==B(E[20],15) && B(E[19],24)==B(E[20],24);
    case 17: return B(A[20],29)==B(A[21],29) && B(E[21],6)!=B(E[21],19) && B(E[21],2)==B(E[21],20);
    case 19: return B(E[23],2)==B(E[23],16);
    default: return 1; } }
static int t10_count(int i){return i==16?4:i==17?3:i==19?1:0;}
int main(int argc,char**argv){
  int lg=argc>1?atoi(argv[1]):22; uint64_t seed=argc>2?strtoull(argv[2],0,0):1; FIXDENSE=argc>3?atoi(argv[3]):0; int I0=argc>4?atoi(argv[4]):16, I1=argc>5?atoi(argv[5]):21;
  printf("mode: %s\n",FIXDENSE?"dense rows <16 fixed to the verified pair; uncontrolled rows 16..i-1 sampled conforming":"all input rows sampled conforming to their printed glyphs");
  st[0]=0x9e3779b97f4a7c15ull^(seed*0x100000001b3ull); st[1]=0xbf58476d1ce4e5b9ull; for(int i=0;i<50;i++)nxt();
  G GA[40],GE[40],GW[40]; for(int r=0;r<40;r++){GA[r]=glyph(RA9[r]);GE[r]=glyph(RE9[r]);GW[r]=glyph(RW9[r]);}
  uint64_t N=1ull<<lg; double total_meas=0; int total_cnt=0;
  printf("trials per step 2^%d, seed %llu\n",lg,(unsigned long long)seed);
  for(int i=I0;i<=I1;i++){
    uint64_t ok=0, rej=0;
    for(uint64_t n=0;n<N;n++){
      uint32_t A[40],E[40],Ap[40],Ep[40],w,wp;
      // sample the four preceding rows of A and E, conforming to Table 9 and to Table 10 relations for rows < i
      for(;;){ for(int j=i-4;j<i;j++){ if(FIXDENSE && j<16){A[j+4]=RA[j+4];Ap[j+4]=RAp[j+4];E[j+4]=RE[j+4];Ep[j+4]=REp[j+4];continue;}
                                     sample(&GA[j+4],&A[j+4],&Ap[j+4]);sample(&GE[j+4],&E[j+4],&Ep[j+4]);}
        if(FIXDENSE && i==16){A[18]=RA[18];} // A14 (needed by the A16 relation) is dense
        int good=1; for(int j=i-4;j<i;j++){ if(j>=16 && !t10_ok(j,A,E)){good=0;break;} }
        // relations that reach back beyond the four sampled rows (A14 for row 16) are sampled too
        if(good) break; rej++; }
      sample(&GW[i+4],&w,&wp);
      uint32_t e=A[i]+E[i]+S1(E[i+3])+IF(E[i+3],E[i+2],E[i+1])+K[i]+w, ep=Ap[i]+Ep[i]+S1(Ep[i+3])+IF(Ep[i+3],Ep[i+2],Ep[i+1])+K[i]+wp;
      uint32_t a=e-A[i]+S0(A[i+3])+MJ(A[i+3],A[i+2],A[i+1]), ap=ep-Ap[i]+S0(Ap[i+3])+MJ(Ap[i+3],Ap[i+2],Ap[i+1]);
      E[i+4]=e;Ep[i+4]=ep;A[i+4]=a;Ap[i+4]=ap;
      if(conform(&GE[i+4],e,ep)&&conform(&GA[i+4],a,ap)&&t10_ok(i,A,E)) ok++;
    }
    int cnt=ncond(&GA[i+4])+ncond(&GE[i+4])+t10_count(i);
    double meas=ok?-log2((double)ok/N):INFINITY;
    printf("step %2d: counted conditions %2d (A %d, E %d, two-bit %d) | measured -log2 P = %6.3f  (%llu/%llu, prefix rejections %llu)\n",
           i,cnt,ncond(&GA[i+4]),ncond(&GE[i+4]),t10_count(i),meas,(unsigned long long)ok,(unsigned long long)N,(unsigned long long)rej);
    total_meas+=meas; total_cnt+=cnt;
  }
  printf("sum steps %d..%d: counted %d, measured %.3f  (+ 14 counted conditions on W21,W23 => c_unc counted 57)\n",I0,I1,total_cnt,total_meas);
  return 0;
}
```

### B.3 dcheck17.c: per-step factors of other templates of the same table (Section 7.3; not used in the cost)

Enumerates all `W14` satisfying (T1)-(T3) (32 values), draws up to sixteen `W15` per
`W14` satisfying (T4)-(T5), and for each of the 256 resulting templates measures the
step-16..19 conditional probabilities with `2^18` samples each under conforming
uncontrolled prefixes; the totals give `2^-13.00, 2^-16.07, 2^-6.00, 2^-7.00`, i.e. an
average per-candidate probability `2^-58.07` over these templates against `2^-56.99` for
the template used. Command line: `./dcheck17 22 18 31`. Recorded output:

```text
W14: row-14 conforming 131072 (2^17.00); + dW16=0: 28672 (2^14.81); + dW29=0: 3616 (2^11.82); + modular dE15/dA15 right: 32 (2^5.00)
pair's W14 in list: 1
PAIR W14=89667ace W15=ab6eb5ef E14=21adda91 E15=b03e6d53 A15=86474456 ok16=34 ok17=9 ok18=4124 ok19=2026 of 2^18
PAIR W14=89667ace W15=fb4eb1e5 E14=21adda91 E15=001e6949 A15=d627404c ok16=25 ok17=0 ok18=4191 ok19=2137 of 2^18
PAIR W14=89667ace W15=7b6ed5eb E14=21adda91 E15=803e8d4f A15=56476452 ok16=29 ok17=0 ok18=4160 ok19=2055 of 2^18
PAIR W14=89667ace W15=b96ed5e8 E14=21adda91 E15=be3e8d4c A15=9447644f ok16=38 ok17=0 ok18=4195 ok19=2062 of 2^18
PAIR W14=89667ace W15=b15774bd E14=21adda91 E15=b6272c21 A15=8c300324 ok16=24 ok17=0 ok18=4137 ok19=2018 of 2^18
PAIR W14=89667ace W15=7b56d610 E14=21adda91 E15=80268d74 A15=562f6477 ok16=36 ok17=15 ok18=4071 ok19=2049 of 2^18
PAIR W14=89667ace W15=ad3fb0b4 E14=21adda91 E15=b20f6818 A15=88183f1b ok16=32 ok17=5 ok18=4151 ok19=2007 of 2^18
PAIR W14=89667ace W15=0336b207 E14=21adda91 E15=0806696b A15=de0f406e ok16=29 ok17=0 ok18=4020 ok19=2154 of 2^18
PAIR W14=89667ace W15=7b3790c5 E14=21adda91 E15=80074829 A15=56101f2c ok16=42 ok17=0 ok18=4140 ok19=2085 of 2^18
PAIR W14=89667ace W15=2557d0cb E14=21adda91 E15=2a27882f A15=00305f32 ok16=35 ok17=0 ok18=4088 ok19=1974 of 2^18
PAIR W14=89667ace W15=a736d60a E14=21adda91 E15=ac068d6e A15=820f6471 ok16=29 ok17=0 ok18=4078 ok19=1964 of 2^18
PAIR W14=89667ace W15=2d6eb5dd E14=21adda91 E15=323e6d41 A15=08474444 ok16=43 ok17=0 ok18=4130 ok19=2090 of 2^18
PAIR W14=89667ace W15=ff6e760b E14=21adda91 E15=043e2d6f A15=da470472 ok16=34 ok17=0 ok18=4011 ok19=2000 of 2^18
PAIR W14=89667ace W15=255f74b7 E14=21adda91 E15=2a2f2c1b A15=0038031e ok16=25 ok17=8 ok18=4081 ok19=2069 of 2^18
PAIR W14=89667ace W15=033f74ca E14=21adda91 E15=080f2c2e A15=de180331 ok16=24 ok17=0 ok18=4143 ok19=2111 of 2^18
PAIR W14=89667ace W15=3936d20c E14=21adda91 E15=3e068970 A15=140f6073 ok16=38 ok17=5 ok18=4094 ok19=1998 of 2^18
PAIR W14=89667acf W15=f586d07b E14=21adda92 E15=06368961 A15=9c476464 ok16=28 ok17=0 ok18=4095 ok19=2042 of 2^18
PAIR W14=89667acf W15=f76f8f51 E14=21adda92 E15=081f4837 A15=9e30233a ok16=35 ok17=10 ok18=4157 ok19=2107 of 2^18
PAIR W14=89667acf W15=f566b45b E14=21adda92 E15=06166d41 A15=9c274844 ok16=31 ok17=0 ok18=4131 ok19=1983 of 2^18
PAIR W14=89667acf W15=f3867465 E14=21adda92 E15=04362d4b A15=9a47084e ok16=27 ok17=0 ok18=4211 ok19=1987 of 2^18
PAIR W14=89667acf W15=ef667465 E14=21adda92 E15=00162d4b A15=9627084e ok16=41 ok17=0 ok18=3981 ok19=1992 of 2^18
PAIR W14=89667acf W15=6f6f9349 E14=21adda92 E15=801f4c2f A15=16302732 ok16=38 ok17=0 ok18=4161 ok19=2026 of 2^18
PAIR W14=89667acf W15=a18fb33e E14=21adda92 E15=b23f6c24 A15=48504727 ok16=29 ok17=0 ok18=4201 ok19=2047 of 2^18
PAIR W14=89667acf W15=2d778f99 E14=21adda92 E15=3e27487f A15=d4382382 ok16=27 ok17=8 ok18=4033 ok19=2012 of 2^18
PAIR W14=89667acf W15=f177cf23 E14=21adda92 E15=02278809 A15=9838630c ok16=32 ok17=0 ok18=4169 ok19=2147 of 2^18
PAIR W14=89667acf W15=1f577324 E14=21adda92 E15=30072c0a A15=c618070d ok16=32 ok17=0 ok18=4156 ok19=2082 of 2^18
PAIR W14=89667acf W15=f38fb332 E14=21adda92 E15=043f6c18 A15=9a50471b ok16=30 ok17=6 ok18=4122 ok19=2083 of 2^18
PAIR W14=89667acf W15=a96e7471 E14=21adda92 E15=ba1e2d57 A15=502f085a ok16=27 ok17=15 ok18=4232 ok19=2106 of 2^18
PAIR W14=89667acf W15=1d8f6f47 E14=21adda92 E15=2e3f282d A15=c4500330 ok16=23 ok17=0 ok18=4006 ok19=2012 of 2^18
PAIR W14=89667acf W15=a98f8f55 E14=21adda92 E15=ba3f483b A15=5050233e ok16=35 ok17=5 ok18=4071 ok19=2053 of 2^18
PAIR W14=89667acf W15=6f778f3a E14=21adda92 E15=80274820 A15=16382323 ok16=32 ok17=0 ok18=4085 ok19=1945 of 2^18
PAIR W14=89667acf W15=7157af43 E14=21adda92 E15=82076829 A15=1818432c ok16=29 ok17=0 ok18=4101 ok19=2011 of 2^18
PAIR W14=89667aee W15=2c6ee5d5 E14=21addab1 E15=b53ead39 A15=8c470464 ok16=30 ok17=9 ok18=4117 ok19=2000 of 2^18
PAIR W14=89667aee W15=fa6f45ca E14=21addab1 E15=833f0d2e A15=5a476459 ok16=42 ok17=0 ok18=4073 ok19=2094 of 2^18
PAIR W14=89667aee W15=7e582119 E14=21addab1 E15=0727e87d A15=de303fa8 ok16=24 ok17=5 ok18=4047 ok19=2063 of 2^18
PAIR W14=89667aee W15=a64ee5ca E14=21addab1 E15=2f1ead2e A15=06270459 ok16=38 ok17=0 ok18=4143 ok19=2045 of 2^18
PAIR W14=89667aee W15=b44ee5c9 E14=21addab1 E15=3d1ead2d A15=14270458 ok16=24 ok17=0 ok18=4075 ok19=2063 of 2^18
PAIR W14=89667aee W15=b64f41e9 E14=21addab1 E15=3f1f094d A15=16276078 ok16=27 ok17=0 ok18=4020 ok19=2067 of 2^18
PAIR W14=89667aee W15=303701e1 E14=21addab1 E15=b906c945 A15=900f2070 ok16=36 ok17=0 ok18=4026 ok19=2083 of 2^18
PAIR W14=89667aee W15=246004ad E14=21addab1 E15=ad2fcc11 A15=8438233c ok16=39 ok17=10 ok18=4123 ok19=2054 of 2^18
PAIR W14=89667aee W15=285fe4f2 E14=21addab1 E15=b12fac56 A15=88380381 ok16=21 ok17=8 ok18=4030 ok19=2069 of 2^18
PAIR W14=89667aee W15=ae60210f E14=21addab1 E15=372fe873 A15=0e383f9e ok16=35 ok17=11 ok18=4002 ok19=2020 of 2^18
PAIR W14=89667aee W15=7a4e45b2 E14=21addab1 E15=031e0d16 A15=da266441 ok16=17 ok17=5 ok18=4009 ok19=2032 of 2^18
PAIR W14=89667aee W15=364f21d3 E14=21addab1 E15=bf1ee937 A15=96274062 ok16=27 ok17=11 ok18=4076 ok19=2015 of 2^18
PAIR W14=89667aee W15=a26ee1dc E14=21addab1 E15=2b3ea940 A15=0247006b ok16=31 ok17=0 ok18=4142 ok19=2008 of 2^18
PAIR W14=89667aee W15=266f25d5 E14=21addab1 E15=af3eed39 A15=86474464 ok16=21 ok17=16 ok18=4114 ok19=2084 of 2^18
PAIR W14=89667aee W15=7c36e1bb E14=21addab1 E15=0506a91f A15=dc0f004a ok16=22 ok17=5 ok18=4102 ok19=2014 of 2^18
PAIR W14=89667aee W15=784f25b6 E14=21addab1 E15=011eed1a A15=d8274445 ok16=27 ok17=11 ok18=4092 ok19=2006 of 2^18
PAIR W14=89667aef W15=1c8fff99 E14=21addab2 E15=a93fc87f A15=405023aa ok16=30 ok17=8 ok18=4078 ok19=1919 of 2^18
PAIR W14=89667aef W15=2a6f005f E14=21addab2 E15=b71ec945 A15=4e2f2470 ok16=35 ok17=0 ok18=4046 ok19=2109 of 2^18
PAIR W14=89667aef W15=2277df29 E14=21addab2 E15=af27a80f A15=4638033a ok16=45 ok17=0 ok18=4044 ok19=2028 of 2^18
PAIR W14=89667aef W15=2487006d E14=21addab2 E15=b136c953 A15=4847247e ok16=27 ok17=6 ok18=3973 ok19=2064 of 2^18
PAIR W14=89667aef W15=1e8f4431 E14=21addab2 E15=ab3f0d17 A15=424f6842 ok16=29 ok17=8 ok18=4081 ok19=2082 of 2^18
PAIR W14=89667aef W15=f66e4450 E14=21addab2 E15=831e0d36 A15=1a2e6861 ok16=40 ok17=7 ok18=4123 ok19=2035 of 2^18
PAIR W14=89667aef W15=76674467 E14=21addab2 E15=03170d4d A15=9a276878 ok16=32 ok17=0 ok18=4062 ok19=2065 of 2^18
PAIR W14=89667aef W15=288e445c E14=21addab2 E15=b53e0d42 A15=4c4e686d ok16=18 ok17=0 ok18=4202 ok19=2088 of 2^18
PAIR W14=89667aef W15=a4874056 E14=21addab2 E15=3137093c A15=c8476467 ok16=34 ok17=5 ok18=4138 ok19=1984 of 2^18
PAIR W14=89667aef W15=a08fe376 E14=21addab2 E15=2d3fac5c A15=c4500787 ok16=32 ok17=15 ok18=4045 ok19=2009 of 2^18
PAIR W14=89667aef W15=f46fff2b E14=21addab2 E15=811fc811 A15=1830233c ok16=38 ok17=6 ok18=4043 ok19=2038 of 2^18
PAIR W14=89667aef W15=22701f87 E14=21addab2 E15=af1fe86d A15=46304398 ok16=25 ok17=0 ok18=4092 ok19=2104 of 2^18
PAIR W14=89667aef W15=9c77ff92 E14=21addab2 E15=2927c878 A15=c03823a3 ok16=33 ok17=5 ok18=4044 ok19=2013 of 2^18
PAIR W14=89667aef W15=24872441 E14=21addab2 E15=b136ed27 A15=48474852 ok16=36 ok17=0 ok18=3985 ok19=2078 of 2^18
PAIR W14=89667aef W15=a0902376 E14=21addab2 E15=2d3fec5c A15=c4504787 ok16=38 ok17=9 ok18=4147 ok19=2045 of 2^18
PAIR W14=89667aef W15=206f0450 E14=21addab2 E15=ad1ecd36 A15=442f2861 ok16=25 ok17=6 ok18=4180 ok19=2170 of 2^18
PAIR W14=89667ece W15=9b70b4e1 E14=21adde91 E15=203e6c55 A15=16574258 ok16=31 ok17=8 ok18=4027 ok19=2061 of 2^18
PAIR W14=89667ece W15=1f4991a3 E14=21adde91 E15=a4174917 A15=9a301f1a ok16=27 ok17=7 ok18=3941 ok19=2065 of 2^18
PAIR W14=89667ece W15=9d5175b5 E14=21adde91 E15=221f2d29 A15=1838032c ok16=38 ok17=0 ok18=4039 ok19=2074 of 2^18
PAIR W14=89667ece W15=1b3874dc E14=21adde91 E15=a0062c50 A15=961f0253 ok16=27 ok17=13 ok18=4087 ok19=2089 of 2^18
PAIR W14=89667ece W15=1370f0d8 E14=21adde91 E15=983ea84c A15=8e577e4f ok16=29 ok17=0 ok18=4134 ok19=1982 of 2^18
PAIR W14=89667ece W15=937094d9 E14=21adde91 E15=183e4c4d A15=0e572250 ok16=35 ok17=0 ok18=4057 ok19=2079 of 2^18
PAIR W14=89667ece W15=0771f1c5 E14=21adde91 E15=8c3fa939 A15=82587f3c ok16=25 ok17=6 ok18=4104 ok19=2107 of 2^18
PAIR W14=89667ece W15=8538b4e6 E14=21adde91 E15=0a066c5a A15=001f425d ok16=44 ok17=4 ok18=4182 ok19=2132 of 2^18
PAIR W14=89667ece W15=0b69d1a0 E14=21adde91 E15=90378914 A15=86505f17 ok16=40 ok17=6 ok18=4157 ok19=2043 of 2^18
PAIR W14=89667ece W15=8f38b4cc E14=21adde91 E15=14066c40 A15=0a1f4243 ok16=27 ok17=0 ok18=4074 ok19=1992 of 2^18
PAIR W14=89667ece W15=1769d197 E14=21adde91 E15=9c37890b A15=92505f0e ok16=25 ok17=0 ok18=4101 ok19=2167 of 2^18
PAIR W14=89667ece W15=0b51d597 E14=21adde91 E15=901f8d0b A15=8638630e ok16=21 ok17=0 ok18=4137 ok19=2055 of 2^18
PAIR W14=89667ece W15=0f5090d7 E14=21adde91 E15=941e484b A15=8a371e4e ok16=44 ok17=0 ok18=3994 ok19=2036 of 2^18
PAIR W14=89667ece W15=8d49d598 E14=21adde91 E15=12178d0c A15=0830630f ok16=41 ok17=0 ok18=4123 ok19=2060 of 2^18
PAIR W14=89667ece W15=0d7074fd E14=21adde91 E15=923e2c71 A15=88570274 ok16=36 ok17=7 ok18=4106 ok19=2013 of 2^18
PAIR W14=89667ece W15=8d69b59f E14=21adde91 E15=12376d13 A15=08504316 ok16=22 ok17=9 ok18=4079 ok19=2115 of 2^18
PAIR W14=89667ecf W15=0f61b434 E14=21adde92 E15=a00f6d2a A15=5630472d ok16=25 ok17=0 ok18=4112 ok19=2048 of 2^18
PAIR W14=89667ecf W15=95687375 E14=21adde92 E15=26162c6b A15=dc37066e ok16=31 ok17=0 ok18=4044 ok19=2007 of 2^18
PAIR W14=89667ecf W15=0190cf60 E14=21adde92 E15=923e8856 A15=485f6259 ok16=32 ok17=12 ok18=4067 ok19=2110 of 2^18
PAIR W14=89667ecf W15=0f90b370 E14=21adde92 E15=a03e6c66 A15=565f4669 ok16=35 ok17=0 ok18=4151 ok19=1992 of 2^18
PAIR W14=89667ecf W15=0d70d34e E14=21adde92 E15=9e1e8c44 A15=543f6647 ok16=26 ok17=0 ok18=4081 ok19=2048 of 2^18
PAIR W14=89667ecf W15=7f617440 E14=21adde92 E15=100f2d36 A15=c6300739 ok16=29 ok17=10 ok18=4147 ok19=2078 of 2^18
PAIR W14=89667ecf W15=8f619045 E14=21adde92 E15=200f493b A15=d630233e ok16=26 ok17=6 ok18=4124 ok19=2007 of 2^18
PAIR W14=89667ecf W15=0f90cf77 E14=21adde92 E15=a03e886d A15=565f6270 ok16=41 ok17=0 ok18=4127 ok19=2072 of 2^18
PAIR W14=89667ecf W15=9370d358 E14=21adde92 E15=241e8c4e A15=da3f6651 ok16=37 ok17=0 ok18=4072 ok19=2062 of 2^18
PAIR W14=89667ecf W15=8961b023 E14=21adde92 E15=1a0f6919 A15=d030431c ok16=28 ok17=12 ok18=4197 ok19=2034 of 2^18
PAIR W14=89667ecf W15=fd90b36b E14=21adde92 E15=8e3e6c61 A15=445f4664 ok16=19 ok17=0 ok18=4087 ok19=2054 of 2^18
PAIR W14=89667ecf W15=8368b37d E14=21adde92 E15=14166c73 A15=ca374676 ok16=33 ok17=15 ok18=4106 ok19=1987 of 2^18
PAIR W14=89667ecf W15=15688f50 E14=21adde92 E15=a6164846 A15=5c372249 ok16=32 ok17=0 ok18=4124 ok19=2001 of 2^18
PAIR W14=89667ecf W15=0981743a E14=21adde92 E15=9a2f2d30 A15=50500733 ok16=35 ok17=10 ok18=4182 ok19=2069 of 2^18
PAIR W14=89667ecf W15=8190b381 E14=21adde92 E15=123e6c77 A15=c85f467a ok16=38 ok17=6 ok18=3975 ok19=2111 of 2^18
PAIR W14=89667ecf W15=0f81b489 E14=21adde92 E15=a02f6d7f A15=56504782 ok16=33 ok17=9 ok18=4067 ok19=1993 of 2^18
PAIR W14=89667eee W15=1e7040ca E14=21addeb1 E15=273e083e A15=1e565e69 ok16=34 ok17=8 ok18=4102 ok19=1958 of 2^18
PAIR W14=89667eee W15=803860b7 E14=21addeb1 E15=8906282b A15=801e7e56 ok16=36 ok17=0 ok18=4146 ok19=2039 of 2^18
PAIR W14=89667eee W15=8a5944db E14=21addeb1 E15=93270c4f A15=8a3f627a ok16=25 ok17=0 ok18=4101 ok19=2073 of 2^18
PAIR W14=89667eee W15=023944db E14=21addeb1 E15=0b070c4f A15=021f627a ok16=31 ok17=0 ok18=4137 ok19=2017 of 2^18
PAIR W14=89667eee W15=0e7124d0 E14=21addeb1 E15=173eec44 A15=0e57426f ok16=32 ok17=0 ok18=4075 ok19=2024 of 2^18
PAIR W14=89667eee W15=847040af E14=21addeb1 E15=8d3e0823 A15=84565e4e ok16=30 ok17=0 ok18=4121 ok19=2074 of 2^18
PAIR W14=89667eee W15=1e4a21e3 E14=21addeb1 E15=2717e957 A15=1e303f82 ok16=32 ok17=7 ok18=4109 ok19=2068 of 2^18
PAIR W14=89667eee W15=1458e4b0 E14=21addeb1 E15=1d26ac24 A15=143f024f ok16=27 ok17=0 ok18=4112 ok19=2071 of 2^18
PAIR W14=89667eee W15=1e5160c4 E14=21addeb1 E15=271f2838 A15=1e377e63 ok16=37 ok17=4 ok18=4111 ok19=1971 of 2^18
PAIR W14=89667eee W15=846a01ff E14=21addeb1 E15=8d37c973 A15=84501f9e ok16=28 ok17=14 ok18=4065 ok19=2024 of 2^18
PAIR W14=89667eee W15=107044e0 E14=21addeb1 E15=193e0c54 A15=1056627f ok16=40 ok17=9 ok18=4043 ok19=2005 of 2^18
PAIR W14=89667eee W15=1e69e606 E14=21addeb1 E15=2737ad7a A15=1e5003a5 ok16=28 ok17=5 ok18=4190 ok19=2039 of 2^18
PAIR W14=89667eee W15=0c5904df E14=21addeb1 E15=1526cc53 A15=0c3f227e ok16=34 ok17=10 ok18=4030 ok19=2058 of 2^18
PAIR W14=89667eee W15=125144cc E14=21addeb1 E15=1b1f0c40 A15=1237626b ok16=31 ok17=0 ok18=4073 ok19=2011 of 2^18
PAIR W14=89667eee W15=165100a5 E14=21addeb1 E15=1f1ec819 A15=16371e44 ok16=30 ok17=12 ok18=4057 ok19=2085 of 2^18
PAIR W14=89667eee W15=844a219f E14=21addeb1 E15=8d17e913 A15=84303f3e ok16=32 ok17=11 ok18=4111 ok19=2119 of 2^18
PAIR W14=89667eef W15=7c61e065 E14=21addeb2 E15=890fa95b A15=40300386 ok16=34 ok17=6 ok18=4117 ok19=2036 of 2^18
PAIR W14=89667eef W15=fe8a2016 E14=21addeb2 E15=0b37e90c A15=c2584337 ok16=39 ok17=0 ok18=4016 ok19=2009 of 2^18
PAIR W14=89667eef W15=9888e321 E14=21addeb2 E15=a536ac17 A15=5c570642 ok16=26 ok17=10 ok18=4007 ok19=2055 of 2^18
PAIR W14=89667eef W15=1a62206a E14=21addeb2 E15=270fe960 A15=de30438b ok16=38 ok17=0 ok18=4071 ok19=2102 of 2^18
PAIR W14=89667eef W15=1489e473 E14=21addeb2 E15=2137ad69 A15=d8580794 ok16=27 ok17=0 ok18=4078 ok19=2053 of 2^18
PAIR W14=89667eef W15=84710321 E14=21addeb2 E15=911ecc17 A15=483f2642 ok16=29 ok17=12 ok18=4076 ok19=2044 of 2^18
PAIR W14=89667eef W15=16693f48 E14=21addeb2 E15=2317083e A15=da376269 ok16=28 ok17=8 ok18=4100 ok19=2019 of 2^18
PAIR W14=89667eef W15=868a2486 E14=21addeb2 E15=9337ed7c A15=4a5847a7 ok16=32 ok17=7 ok18=4088 ok19=2031 of 2^18
PAIR W14=89667eef W15=0a8a046d E14=21addeb2 E15=1737cd63 A15=ce58278e ok16=28 ok17=0 ok18=4116 ok19=2159 of 2^18
PAIR W14=89667eef W15=9681e40a E14=21addeb2 E15=a32fad00 A15=5a50072b ok16=33 ok17=0 ok18=4167 ok19=2086 of 2^18
PAIR W14=89667eef W15=026a0419 E14=21addeb2 E15=0f17cd0f A15=c638273a ok16=36 ok17=0 ok18=4015 ok19=1998 of 2^18
PAIR W14=89667eef W15=8461e470 E14=21addeb2 E15=910fad66 A15=48300791 ok16=40 ok17=0 ok18=4179 ok19=2044 of 2^18
PAIR W14=89667eef W15=1a704333 E14=21addeb2 E15=271e0c29 A15=de3e6654 ok16=29 ok17=0 ok18=4140 ok19=1986 of 2^18
PAIR W14=89667eef W15=92820462 E14=21addeb2 E15=9f2fcd58 A15=56502783 ok16=35 ok17=7 ok18=3972 ok19=2060 of 2^18
PAIR W14=89667eef W15=80690349 E14=21addeb2 E15=8d16cc3f A15=4437266a ok16=37 ok17=10 ok18=4069 ok19=2113 of 2^18
PAIR W14=89667eef W15=8670e337 E14=21addeb2 E15=931eac2d A15=4a3f0658 ok16=38 ok17=0 ok18=4008 ok19=2098 of 2^18
PAIR W14=89c67ac2 W15=354586fe E14=220dda85 E15=bc26a86d A15=12476c66 ok16=33 ok17=11 ok18=4120 ok19=2103 of 2^18
PAIR W14=89c67ac2 W15=2b2566f8 E14=220dda85 E15=b2068867 A15=08274c60 ok16=36 ok17=9 ok18=4079 ok19=2085 of 2^18
PAIR W14=89c67ac2 W15=a945270c E14=220dda85 E15=3026487b A15=86470c74 ok16=32 ok17=0 ok18=4131 ok19=2077 of 2^18
PAIR W14=89c67ac2 W15=7d3e6ba8 E14=220dda85 E15=041f8d17 A15=5a405110 ok16=24 ok17=0 ok18=4146 ok19=2052 of 2^18
PAIR W14=89c67ac2 W15=fb4647c6 E14=220dda85 E15=82276935 A15=d8482d2e ok16=33 ok17=0 ok18=4164 ok19=2033 of 2^18
PAIR W14=89c67ac2 W15=33458b0f E14=220dda85 E15=ba26ac7e A15=10477077 ok16=34 ok17=0 ok18=4102 ok19=1948 of 2^18
PAIR W14=89c67ac2 W15=7d2d2794 E14=220dda85 E15=040e4903 A15=5a2f0cfc ok16=30 ok17=10 ok18=4080 ok19=2010 of 2^18
PAIR W14=89c67ac2 W15=334546e2 E14=220dda85 E15=ba266851 A15=10472c4a ok16=33 ok17=0 ok18=4095 ok19=1974 of 2^18
PAIR W14=89c67ac2 W15=af262ba5 E14=220dda85 E15=36074d14 A15=8c28110d ok16=31 ok17=0 ok18=4027 ok19=1987 of 2^18
PAIR W14=89c67ac2 W15=793e87a4 E14=220dda85 E15=001fa913 A15=56406d0c ok16=32 ok17=0 ok18=4104 ok19=2026 of 2^18
PAIR W14=89c67ac2 W15=79458ae7 E14=220dda85 E15=0026ac56 A15=5647704f ok16=24 ok17=0 ok18=4038 ok19=2067 of 2^18
PAIR W14=89c67ac2 W15=b3456aeb E14=220dda85 E15=3a268c5a A15=90475053 ok16=24 ok17=0 ok18=4142 ok19=2010 of 2^18
PAIR W14=89c67ac2 W15=81452aff E14=220dda85 E15=08264c6e A15=5e471067 ok16=37 ok17=10 ok18=4164 ok19=2101 of 2^18
PAIR W14=89c67ac2 W15=ff5e87c8 E14=220dda85 E15=863fa937 A15=dc606d30 ok16=28 ok17=0 ok18=4125 ok19=2004 of 2^18
PAIR W14=89c67ac2 W15=2d2d46ed E14=220dda85 E15=b40e685c A15=0a2f2c55 ok16=34 ok17=0 ok18=4061 ok19=2113 of 2^18
PAIR W14=89c67ac2 W15=a54d86dd E14=220dda85 E15=2c2ea84c A15=824f6c45 ok16=37 ok17=4 ok18=4176 ok19=2041 of 2^18
PAIR W14=89c67ac3 W15=a1752985 E14=220dda86 E15=34364c76 A15=4a4f146f ok16=38 ok17=0 ok18=4098 ok19=1953 of 2^18
PAIR W14=89c67ac3 W15=75462647 E14=220dda86 E15=08074938 A15=1e201131 ok16=42 ok17=0 ok18=4164 ok19=2000 of 2^18
PAIR W14=89c67ac3 W15=294e6a46 E14=220dda86 E15=bc0f8d37 A15=d2285530 ok16=27 ok17=0 ok18=4135 ok19=2101 of 2^18
PAIR W14=89c67ac3 W15=f36d4560 E14=220dda86 E15=862e6851 A15=9c47304a ok16=25 ok17=0 ok18=4198 ok19=2091 of 2^18
PAIR W14=89c67ac3 W15=ab664636 E14=220dda86 E15=3e276927 A15=54403120 ok16=29 ok17=12 ok18=4174 ok19=2094 of 2^18
PAIR W14=89c67ac3 W15=9755698d E14=220dda86 E15=2a168c7e A15=402f5477 ok16=30 ok17=0 ok18=3984 ok19=2133 of 2^18
PAIR W14=89c67ac3 W15=ab6e2a2c E14=220dda86 E15=3e2f4d1d A15=54481516 ok16=23 ok17=0 ok18=4163 ok19=2028 of 2^18
PAIR W14=89c67ac3 W15=a36e8a20 E14=220dda86 E15=362fad11 A15=4c48750a ok16=34 ok17=0 ok18=4169 ok19=1982 of 2^18
PAIR W14=89c67ac3 W15=1b666624 E14=220dda86 E15=ae278915 A15=c440510e ok16=35 ok17=0 ok18=4078 ok19=1999 of 2^18
PAIR W14=89c67ac3 W15=176e262b E14=220dda86 E15=aa2f491c A15=c0481115 ok16=38 ok17=0 ok18=3963 ok19=2027 of 2^18
PAIR W14=89c67ac3 W15=25758585 E14=220dda86 E15=b836a876 A15=ce4f706f ok16=32 ok17=0 ok18=4048 ok19=2064 of 2^18
PAIR W14=89c67ac3 W15=994d8965 E14=220dda86 E15=2c0eac56 A15=4227744f ok16=30 ok17=0 ok18=4089 ok19=1965 of 2^18
PAIR W14=89c67ac3 W15=19752a14 E14=220dda86 E15=ac364d05 A15=c24f14fe ok16=33 ok17=14 ok18=4100 ok19=2143 of 2^18
PAIR W14=89c67ac3 W15=2146861e E14=220dda86 E15=b407a90f A15=ca207108 ok16=34 ok17=8 ok18=4162 ok19=1924 of 2^18
PAIR W14=89c67ac3 W15=254d858e E14=220dda86 E15=b80ea87f A15=ce277078 ok16=26 ok17=0 ok18=4101 ok19=2090 of 2^18
PAIR W14=89c67ac3 W15=196e6a4c E14=220dda86 E15=ac2f8d3d A15=c2485536 ok16=34 ok17=0 ok18=4187 ok19=2019 of 2^18
PAIR W14=89c67ae2 W15=3026dbad E14=220ddaa5 E15=3b07ed1c A15=9228313d ok16=30 ok17=0 ok18=4064 ok19=2011 of 2^18
PAIR W14=89c67ae2 W15=7c2db6be E14=220ddaa5 E15=870ec82d A15=de2f0c4e ok16=24 ok17=15 ok18=4143 ok19=2057 of 2^18
PAIR W14=89c67ae2 W15=a624f6c5 E14=220ddaa5 E15=b1060834 A15=08264c55 ok16=34 ok17=0 ok18=4091 ok19=2041 of 2^18
PAIR W14=89c67ae2 W15=f846dbf7 E14=220ddaa5 E15=0327ed66 A15=5a483187 ok16=36 ok17=4 ok18=4185 ok19=2081 of 2^18
PAIR W14=89c67ae2 W15=a64616b2 E14=220ddaa5 E15=b1272821 A15=08476c42 ok16=35 ok17=9 ok18=4158 ok19=2023 of 2^18
PAIR W14=89c67ae2 W15=782dbaca E14=220ddaa5 E15=830ecc39 A15=da2f105a ok16=23 ok17=0 ok18=4129 ok19=2043 of 2^18
PAIR W14=89c67ae2 W15=222516ef E14=220ddaa5 E15=2d06285e A15=84266c7f ok16=39 ok17=0 ok18=4110 ok19=2052 of 2^18
PAIR W14=89c67ae2 W15=762df6b2 E14=220ddaa5 E15=810f0821 A15=d82f4c42 ok16=31 ok17=8 ok18=4118 ok19=2057 of 2^18
PAIR W14=89c67ae2 W15=9e25b6b4 E14=220ddaa5 E15=a906c823 A15=00270c44 ok16=35 ok17=6 ok18=4154 ok19=2020 of 2^18
PAIR W14=89c67ae2 W15=344dd6cb E14=220ddaa5 E15=3f2ee83a A15=964f2c5b ok16=36 ok17=0 ok18=4001 ok19=2079 of 2^18
PAIR W14=89c67ae2 W15=f62d1ace E14=220ddaa5 E15=010e2c3d A15=582e705e ok16=26 ok17=0 ok18=4259 ok19=2049 of 2^18
PAIR W14=89c67ae2 W15=2e26dbab E14=220ddaa5 E15=3907ed1a A15=9028313b ok16=34 ok17=0 ok18=4099 ok19=1975 of 2^18
PAIR W14=89c67ae2 W15=b046dbaa E14=220ddaa5 E15=bb27ed19 A15=1248313a ok16=28 ok17=0 ok18=4118 ok19=2034 of 2^18
PAIR W14=89c67ae2 W15=a42d1ab6 E14=220ddaa5 E15=af0e2c25 A15=062e7046 ok16=35 ok17=8 ok18=4014 ok19=2092 of 2^18
PAIR W14=89c67ae2 W15=b446bbfa E14=220ddaa5 E15=bf27cd69 A15=1648118a ok16=24 ok17=6 ok18=4144 ok19=2007 of 2^18
PAIR W14=89c67ae2 W15=fc2dbadd E14=220ddaa5 E15=070ecc4c A15=5e2f106d ok16=29 ok17=7 ok18=4070 ok19=2007 of 2^18
PAIR W14=89c67ae3 W15=1e66d67c E14=220ddaa6 E15=2d27e96d A15=4440318e ok16=38 ok17=3 ok18=4227 ok19=2127 of 2^18
PAIR W14=89c67ae3 W15=f26df952 E14=220ddaa6 E15=012f0c43 A15=18475464 ok16=31 ok17=7 ok18=4050 ok19=2024 of 2^18
PAIR W14=89c67ae3 W15=9e4d1542 E14=220ddaa6 E15=ad0e2833 A15=c4267054 ok16=33 ok17=0 ok18=4023 ok19=2029 of 2^18
PAIR W14=89c67ae3 W15=7475f930 E14=220ddaa6 E15=83370c21 A15=9a4f5442 ok16=30 ok17=5 ok18=4226 ok19=2159 of 2^18
PAIR W14=89c67ae3 W15=ac54f56c E14=220ddaa6 E15=bb16085d A15=d22e507e ok16=39 ok17=0 ok18=4168 ok19=2049 of 2^18
PAIR W14=89c67ae3 W15=ac46d684 E14=220ddaa6 E15=bb07e975 A15=d2203196 ok16=41 ok17=0 ok18=4113 ok19=2086 of 2^18
PAIR W14=89c67ae3 W15=f66e1955 E14=220ddaa6 E15=052f2c46 A15=1c477467 ok16=24 ok17=10 ok18=4072 ok19=2000 of 2^18
PAIR W14=89c67ae3 W15=a84eda28 E14=220ddaa6 E15=b70fed19 A15=ce28353a ok16=37 ok17=0 ok18=3992 ok19=2108 of 2^18
PAIR W14=89c67ae3 W15=2a75d549 E14=220ddaa6 E15=3936e83a A15=504f305b ok16=30 ok17=0 ok18=4128 ok19=2019 of 2^18
PAIR W14=89c67ae3 W15=9c561569 E14=220ddaa6 E15=ab17285a A15=c22f707b ok16=38 ok17=0 ok18=4116 ok19=2012 of 2^18
PAIR W14=89c67ae3 W15=726e155a E14=220ddaa6 E15=812f284b A15=9847706c ok16=32 ok17=7 ok18=4125 ok19=2063 of 2^18
PAIR W14=89c67ae3 W15=2a6eb620 E14=220ddaa6 E15=392fc911 A15=50481132 ok16=34 ok17=0 ok18=4074 ok19=2123 of 2^18
PAIR W14=89c67ae3 W15=1e6dd96b E14=220ddaa6 E15=2d2eec5c A15=4447347d ok16=34 ok17=0 ok18=4135 ok19=2121 of 2^18
PAIR W14=89c67ae3 W15=9a75f556 E14=220ddaa6 E15=a9370847 A15=c04f5068 ok16=38 ok17=2 ok18=4070 ok19=1981 of 2^18
PAIR W14=89c67ae3 W15=3056195a E14=220ddaa6 E15=3f172c4b A15=562f746c ok16=44 ok17=4 ok18=4149 ok19=2036 of 2^18
PAIR W14=89c67ae3 W15=224e1963 E14=220ddaa6 E15=310f2c54 A15=48277475 ok16=32 ok17=0 ok18=4005 ok19=1975 of 2^18
PAIR W14=89c67ec2 W15=994b8bd1 E14=220dde85 E15=a02ead50 A15=163f7249 ok16=30 ok17=0 ok18=4088 ok19=2003 of 2^18
PAIR W14=89c67ec2 W15=933426c3 E14=220dde85 E15=9a174842 A15=10280d3b ok16=36 ok17=9 ok18=4066 ok19=2021 of 2^18
PAIR W14=89c67ec2 W15=1d544abd E14=220dde85 E15=24376c3c A15=9a483135 ok16=23 ok17=0 ok18=3952 ok19=2150 of 2^18
PAIR W14=89c67ec2 W15=13544a89 E14=220dde85 E15=1a376c08 A15=90483101 ok16=46 ok17=13 ok18=4027 ok19=2004 of 2^18
PAIR W14=89c67ec2 W15=15344ab5 E14=220dde85 E15=1c176c34 A15=9228312d ok16=29 ok17=0 ok18=4051 ok19=2018 of 2^18
PAIR W14=89c67ec2 W15=21438be0 E14=220dde85 E15=2826ad5f A15=9e377258 ok16=35 ok17=0 ok18=4124 ok19=2069 of 2^18
PAIR W14=89c67ec2 W15=852367e2 E14=220dde85 E15=8c068961 A15=02174e5a ok16=23 ok17=6 ok18=4013 ok19=2115 of 2^18
PAIR W14=89c67ec2 W15=1b4c8ab1 E14=220dde85 E15=222fac30 A15=98407129 ok16=34 ok17=0 ok18=4057 ok19=2065 of 2^18
PAIR W14=89c67ec2 W15=9d5446a8 E14=220dde85 E15=a4376827 A15=1a482d20 ok16=31 ok17=7 ok18=4032 ok19=1984 of 2^18
PAIR W14=89c67ec2 W15=195b2687 E14=220dde85 E15=203e4806 A15=964f0cff ok16=27 ok17=7 ok18=4217 ok19=2039 of 2^18
PAIR W14=89c67ec2 W15=0d348a8b E14=220dde85 E15=1417ac0a A15=8a287103 ok16=45 ok17=5 ok18=4043 ok19=2042 of 2^18
PAIR W14=89c67ec2 W15=87232bcf E14=220dde85 E15=8e064d4e A15=04171247 ok16=19 ok17=8 ok18=4107 ok19=2094 of 2^18
PAIR W14=89c67ec2 W15=8b438bfd E14=220dde85 E15=9226ad7c A15=08377275 ok16=40 ok17=0 ok18=4105 ok19=2055 of 2^18
PAIR W14=89c67ec2 W15=034c4a95 E14=220dde85 E15=0a2f6c14 A15=8040310d ok16=34 ok17=0 ok18=4044 ok19=2096 of 2^18
PAIR W14=89c67ec2 W15=095426bb E14=220dde85 E15=1037483a A15=86480d33 ok16=35 ok17=0 ok18=4137 ok19=2048 of 2^18
PAIR W14=89c67ec2 W15=833466c7 E14=220dde85 E15=8a178846 A15=00284d3f ok16=40 ok17=13 ok18=4152 ok19=1935 of 2^18
PAIR W14=89c67ec3 W15=09548940 E14=220dde86 E15=1c17ac41 A15=5220753a ok16=33 ok17=9 ok18=4087 ok19=2070 of 2^18
PAIR W14=89c67ec3 W15=957c8930 E14=220dde86 E15=a83fac31 A15=de48752a ok16=28 ok17=0 ok18=4108 ok19=2047 of 2^18
PAIR W14=89c67ec3 W15=05532662 E14=220dde86 E15=18164963 A15=4e1f125c ok16=34 ok17=6 ok18=4058 ok19=2116 of 2^18
PAIR W14=89c67ec3 W15=7d5c4940 E14=220dde86 E15=901f6c41 A15=c628353a ok16=35 ok17=9 ok18=4023 ok19=2004 of 2^18
PAIR W14=89c67ec3 W15=074b2a5a E14=220dde86 E15=1a0e4d5b A15=50171654 ok16=30 ok17=0 ok18=4106 ok19=2121 of 2^18
PAIR W14=89c67ec3 W15=114b4651 E14=220dde86 E15=240e6952 A15=5a17324b ok16=40 ok17=0 ok18=4202 ok19=2062 of 2^18
PAIR W14=89c67ec3 W15=79738a5d E14=220dde86 E15=8c36ad5e A15=c23f7657 ok16=36 ok17=0 ok18=4005 ok19=2031 of 2^18
PAIR W14=89c67ec3 W15=7774253d E14=220dde86 E15=8a37483e A15=c0401137 ok16=33 ok17=0 ok18=4160 ok19=2078 of 2^18
PAIR W14=89c67ec3 W15=936b6675 E14=220dde86 E15=a62e8976 A15=dc37526f ok16=36 ok17=0 ok18=4063 ok19=2074 of 2^18
PAIR W14=89c67ec3 W15=f9738a56 E14=220dde86 E15=0c36ad57 A15=423f7650 ok16=35 ok17=0 ok18=4071 ok19=2065 of 2^18
PAIR W14=89c67ec3 W15=03734a56 E14=220dde86 E15=16366d57 A15=4c3f3650 ok16=39 ok17=0 ok18=4176 ok19=1973 of 2^18
PAIR W14=89c67ec3 W15=937b2502 E14=220dde86 E15=a63e4803 A15=dc4710fc ok16=32 ok17=10 ok18=4049 ok19=2023 of 2^18
PAIR W14=89c67ec3 W15=fd542541 E14=220dde86 E15=10174842 A15=4620113b ok16=41 ok17=9 ok18=4076 ok19=2086 of 2^18
PAIR W14=89c67ec3 W15=f94b6677 E14=220dde86 E15=0c0e8978 A15=42175271 ok16=30 ok17=0 ok18=4212 ok19=2092 of 2^18
PAIR W14=89c67ec3 W15=95538a63 E14=220dde86 E15=a816ad64 A15=de1f765d ok16=32 ok17=6 ok18=4123 ok19=2161 of 2^18
PAIR W14=89c67ec3 W15=8574650a E14=220dde86 E15=9837880b A15=ce405104 ok16=35 ok17=8 ok18=4098 ok19=2056 of 2^18
PAIR W14=89c67ee2 W15=82431bcd E14=220ddea5 E15=0d262d4c A15=8436726d ok16=26 ok17=7 ok18=4069 ok19=1982 of 2^18
PAIR W14=89c67ee2 W15=062bf7c7 E14=220ddea5 E15=910f0946 A15=081f4e67 ok16=25 ok17=6 ok18=3926 ok19=2028 of 2^18
PAIR W14=89c67ee2 W15=842cd6ed E14=220ddea5 E15=0f0fe86c A15=86202d8d ok16=32 ok17=5 ok18=4180 ok19=2067 of 2^18
PAIR W14=89c67ee2 W15=0e2cda9c E14=220ddea5 E15=990fec1b A15=1020313c ok16=32 ok17=0 ok18=4114 ok19=1939 of 2^18
PAIR W14=89c67ee2 W15=7e241bbe E14=220ddea5 E15=09072d3d A15=8017725e ok16=30 ok17=0 ok18=4109 ok19=2017 of 2^18
PAIR W14=89c67ee2 W15=882bdbc9 E14=220ddea5 E15=130eed48 A15=8a1f3269 ok16=29 ok17=5 ok18=4101 ok19=2105 of 2^18
PAIR W14=89c67ee2 W15=fe4bf7d7 E14=220ddea5 E15=892f0956 A15=003f4e77 ok16=24 ok17=0 ok18=4142 ok19=2043 of 2^18
PAIR W14=89c67ee2 W15=142b1bc5 E14=220ddea5 E15=9f0e2d44 A15=161e7265 ok16=38 ok17=6 ok18=4047 ok19=2069 of 2^18
PAIR W14=89c67ee2 W15=1643fbb5 E14=220ddea5 E15=a1270d34 A15=18375255 ok16=26 ok17=0 ok18=4081 ok19=2067 of 2^18
PAIR W14=89c67ee2 W15=162bdbb1 E14=220ddea5 E15=a10eed30 A15=181f3251 ok16=30 ok17=0 ok18=4071 ok19=2072 of 2^18
PAIR W14=89c67ee2 W15=8e54baed E14=220ddea5 E15=1937cc6c A15=9048118d ok16=29 ok17=14 ok18=4191 ok19=1914 of 2^18
PAIR W14=89c67ee2 W15=8234da92 E14=220ddea5 E15=0d17ec11 A15=84283132 ok16=22 ok17=0 ok18=4075 ok19=2018 of 2^18
PAIR W14=89c67ee2 W15=fe2317cb E14=220ddea5 E15=8906294a A15=00166e6b ok16=34 ok17=12 ok18=4036 ok19=2000 of 2^18
PAIR W14=89c67ee2 W15=9c42fbb8 E14=220ddea5 E15=27260d37 A15=9e365258 ok16=42 ok17=0 ok18=4152 ok19=2033 of 2^18
PAIR W14=89c67ee2 W15=9823b7de E14=220ddea5 E15=2306c95d A15=9a170e7e ok16=33 ok17=0 ok18=4149 ok19=1936 of 2^18
PAIR W14=89c67ee2 W15=9c34b6f9 E14=220ddea5 E15=2717c878 A15=9e280d99 ok16=27 ok17=0 ok18=4075 ok19=2077 of 2^18
PAIR W14=89c67ee3 W15=104bb649 E14=220ddea6 E15=9f0ec94a A15=d617126b ok16=33 ok17=9 ok18=4063 ok19=2080 of 2^18
PAIR W14=89c67ee3 W15=8a6bd658 E14=220ddea6 E15=192ee959 A15=5037327a ok16=23 ok17=0 ok18=4129 ok19=1922 of 2^18
PAIR W14=89c67ee3 W15=7e54b576 E14=220ddea6 E15=0d17c877 A15=44201198 ok16=35 ok17=0 ok18=4021 ok19=2073 of 2^18
PAIR W14=89c67ee3 W15=166c1a21 E14=220ddea6 E15=a52f2d22 A15=dc377643 ok16=34 ok17=10 ok18=4136 ok19=1992 of 2^18
PAIR W14=89c67ee3 W15=1453fa1e E14=220ddea6 E15=a3170d1f A15=da1f5640 ok16=28 ok17=0 ok18=4024 ok19=1964 of 2^18
PAIR W14=89c67ee3 W15=144c1a3c E14=220ddea6 E15=a30f2d3d A15=da17765e ok16=32 ok17=0 ok18=4155 ok19=2068 of 2^18
PAIR W14=89c67ee3 W15=884bb638 E14=220ddea6 E15=170ec939 A15=4e17125a ok16=36 ok17=0 ok18=4179 ok19=2053 of 2^18
PAIR W14=89c67ee3 W15=fa4bba2a E14=220ddea6 E15=890ecd2b A15=c017164c ok16=28 ok17=9 ok18=4079 ok19=2001 of 2^18
PAIR W14=89c67ee3 W15=fc4c1a27 E14=220ddea6 E15=8b0f2d28 A15=c2177649 ok16=34 ok17=13 ok18=4077 ok19=2064 of 2^18
PAIR W14=89c67ee3 W15=8653b648 E14=220ddea6 E15=1516c949 A15=4c1f126a ok16=31 ok17=10 ok18=4124 ok19=1985 of 2^18
PAIR W14=89c67ee3 W15=187cb908 E14=220ddea6 E15=a73fcc09 A15=de48152a ok16=36 ok17=7 ok18=4197 ok19=2025 of 2^18
PAIR W14=89c67ee3 W15=8c6b1639 E14=220ddea6 E15=1b2e293a A15=5236725b ok16=27 ok17=0 ok18=4053 ok19=2093 of 2^18
PAIR W14=89c67ee3 W15=7a6af655 E14=220ddea6 E15=092e0956 A15=40365277 ok16=30 ok17=0 ok18=4114 ok19=2049 of 2^18
PAIR W14=89c67ee3 W15=8a741622 E14=220ddea6 E15=19372923 A15=503f7244 ok16=38 ok17=15 ok18=4035 ok19=2034 of 2^18
PAIR W14=89c67ee3 W15=006bb62c E14=220ddea6 E15=8f2ec92d A15=c637124e ok16=33 ok17=8 ok18=4045 ok19=2074 of 2^18
PAIR W14=89c67ee3 W15=966bfa1f E14=220ddea6 E15=252f0d20 A15=5c375641 ok16=29 ok17=6 ok18=4044 ok19=2057 of 2^18
TOTAL pairs 256 samples/step/pair 2^18: ok16 8167 (2^-13.004) ok17 978 (2^-16.066) ok18 1048929 (2^-6.000) ok19 523736 (2^-7.002)
```

Source:

```c
// dcheck: measure the (W14,W15) freedom "d" of the 2026/1120 36-step characteristic at 32 steps and
// whether the tail conditions counted at steps 16..19 are typical over that freedom (not just for the
// verified pair's own (W14,W15)).  Dense part (rows <= 13, W8..W13) fixed to the verified pair (ref.h).
//  1. exhaustive W14: row-14 glyphs on (E14, A14, W14) + zero modular difference of W16 (W9 vs sigma1(W14))
//     and of W29 (W13 vs sigma0(W14)); W30 (W14 vs W23) cancels deterministically by the fixed signs.
//  2. for random valid W14, W15 by rejection: row-15 glyphs on (E15, A15).   d_vis = log2 #visible-valid pairs.
//  3. for each sampled valid (W14,W15) = j: P16(j) with W16 uniform (both messages share W16 since dW16=0);
//     P17(j), P18(j), P19(j) with uncontrolled rows 16..i-1 sampled conforming (glyphs + Table 10) and W_i uniform.
//     The average over j of P16*..*P19 relative to the counted 2^-(13+15+6+7) gives the "implicit" conditions
//     that the paper absorbs into its (W14,W15) count: d_eff = d_vis - implicit.  Paper: d = 20.
// Usage: dcheck <log2 W15 tries per W14> <log2 trials per step for the profile> <seed>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "rows.h"
#include "../eng/results/005-conditions-r32/ref.h"
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S0(a) (ROR(a,2)^ROR(a,13)^ROR(a,22))
#define S1(e) (ROR(e,6)^ROR(e,11)^ROR(e,25))
#define s0(x) (ROR(x,7)^ROR(x,18)^((x)>>3))
#define s1(x) (ROR(x,17)^ROR(x,19)^((x)>>10))
#define IF(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define B(x,k) (((x)>>(k))&1u)
static const uint32_t K[32]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967};
static uint64_t st[2];
static inline uint64_t rotl(uint64_t x,int k){return (x<<k)|(x>>(64-k));}
static inline uint64_t nxt(void){uint64_t a=st[0],b=st[1],r=a+b;b^=a;st[0]=rotl(a,55)^b^(b<<14);st[1]=rotl(b,36);return r;}
static inline uint32_t r32(void){return (uint32_t)(nxt()>>32);}
typedef struct{uint32_t m0,m1,mn,mu;} G;
static G glyph(const char*s){G g={0,0,0,0};for(int k=0;k<32;k++){uint32_t b=1u<<(31-k);switch(s[k]){case '0':g.m0|=b;break;case '1':g.m1|=b;break;case 'n':g.mn|=b;break;case 'u':g.mu|=b;break;default:break;}}return g;}
static inline void sample(const G*g,uint32_t*x,uint32_t*xp){uint32_t r=r32();uint32_t f=g->m0|g->m1|g->mn|g->mu;*x=(r&~f)|g->m1|g->mn;*xp=(r&~f)|g->m1|g->mu;}
static inline int conform(const G*g,uint32_t x,uint32_t xp){uint32_t f=g->m0|g->m1|g->mn|g->mu; if((x&f)!=(g->m1|g->mn))return 0; if((xp&f)!=(g->m1|g->mu))return 0; return ((x^xp)&~f)==0;}
static G GA[40],GE[40],GW[40];
static int t10_ok(int i,const uint32_t*A,const uint32_t*E){
  switch(i){
    case 16: return B(A[18],29)==B(A[20],29) && B(E[20],0)!=B(E[20],13) && B(E[19],15)==B(E[20],15) && B(E[19],24)==B(E[20],24);
    case 17: return B(A[20],29)==B(A[21],29) && B(E[21],6)!=B(E[21],19) && B(E[21],2)==B(E[21],20);
    case 19: return B(E[23],2)==B(E[23],16);
    default: return 1; } }
// step i for both messages given arrays (indexed [i+4]) and W_i values
static inline void stepi(int i,uint32_t*A,uint32_t*E,uint32_t*Ap,uint32_t*Ep,uint32_t w,uint32_t wp){
  E[i+4]=A[i]+E[i]+S1(E[i+3])+IF(E[i+3],E[i+2],E[i+1])+K[i]+w; A[i+4]=E[i+4]-A[i]+S0(A[i+3])+MJ(A[i+3],A[i+2],A[i+1]);
  Ep[i+4]=Ap[i]+Ep[i]+S1(Ep[i+3])+IF(Ep[i+3],Ep[i+2],Ep[i+1])+K[i]+wp; Ap[i+4]=Ep[i+4]-Ap[i]+S0(Ap[i+3])+MJ(Ap[i+3],Ap[i+2],Ap[i+1]); }
static uint32_t *W14L; static uint64_t n14=0;
int main(int argc,char**argv){
  setvbuf(stdout,NULL,_IOLBF,0);
  int lg15=argc>1?atoi(argv[1]):24; int lg=argc>2?atoi(argv[2]):15; uint64_t seed=argc>3?strtoull(argv[3],0,0):1;
  st[0]=0x9e3779b97f4a7c15ull^(seed*0x100000001b3ull); st[1]=0xbf58476d1ce4e5b9ull; for(int i=0;i<50;i++)nxt();
  for(int r=0;r<40;r++){GA[r]=glyph(RA9[r]);GE[r]=glyph(RE9[r]);GW[r]=glyph(RW9[r]);}
  uint32_t A[40],E[40],Ap[40],Ep[40]; memcpy(A,RA,sizeof A);memcpy(E,RE,sizeof E);memcpy(Ap,RAp,sizeof A);memcpy(Ep,REp,sizeof E);
  // sanity: the pair's own rows 14..21 conform, Table 10 holds
  for(int i=14;i<=21;i++){ if(!conform(&GA[i+4],RA[i+4],RAp[i+4])||!conform(&GE[i+4],RE[i+4],REp[i+4])||!conform(&GW[i+4],RW[i],RWp[i])||!t10_ok(i,RA,RE)){fprintf(stderr,"pair row %d does not conform\n",i);return 1;} }
  // 1. exhaustive W14
  W14L=malloc(sizeof(uint32_t)<<20); uint64_t n14row=0,n14w16=0,n14w29=0;
  uint32_t dW9=RWp[9]-RW[9], dW13=RWp[13]-RW[13], dW14=RWp[14]-RW[14];
  uint32_t b14=A[14]+E[14]+S1(E[17])+IF(E[17],E[16],E[15])+K[14], b14p=Ap[14]+Ep[14]+S1(Ep[17])+IF(Ep[17],Ep[16],Ep[15])+K[14];
  for(uint64_t x=0;x<(1ull<<32);x++){ uint32_t w=(uint32_t)x, wp=w+dW14; if(!conform(&GW[18],w,wp))continue;
    if(!conform(&GE[18],b14+w,b14p+wp))continue;
    stepi(14,A,E,Ap,Ep,w,wp); if(!conform(&GA[18],A[18],Ap[18]))continue; n14row++;
    if((uint32_t)(dW9+(s1(wp)-s1(w)))!=0)continue; n14w16++;
    if((uint32_t)(dW13+(s0(wp)-s0(w)))!=0)continue; n14w29++;
    // implicit row-14 conditions needed for row 15: modular dE15 = 0 and modular dA15 as prescribed
    { uint32_t b15=A[15]+E[15]+S1(E[18])+IF(E[18],E[17],E[16])+K[15], b15p=Ap[15]+Ep[15]+S1(Ep[18])+IF(Ep[18],Ep[17],Ep[16])+K[15];
      if(b15!=b15p)continue;
      uint32_t ca=-A[15]+S0(A[18])+MJ(A[18],A[17],A[16]), cap=-Ap[15]+S0(Ap[18])+MJ(Ap[18],Ap[17],Ap[16]);
      if((uint32_t)(cap-ca)!=(uint32_t)(RAp[19]-RA[19]))continue; }
    if(n14<(1u<<20))W14L[n14]=w; n14++; }
  printf("W14: row-14 conforming %llu (2^%.2f); + dW16=0: %llu (2^%.2f); + dW29=0: %llu (2^%.2f); + modular dE15/dA15 right: %llu (2^%.2f)\n",
    (unsigned long long)n14row,log2(n14row),(unsigned long long)n14w16,log2(n14w16),(unsigned long long)n14w29,log2(n14w29),(unsigned long long)n14,log2(n14));
  int refin=0; for(uint64_t k=0;k<n14&&k<(1u<<20);k++) if(W14L[k]==RW[14])refin=1; printf("pair's W14 in list: %d\n",refin);
  // MODE 17b: for each admissible W14, up to 16 admissible W15 (row-15 glyphs + step-16 modular diffs); for each pair
  // measure P16, P17, P18, P19 (2^lg samples each, conforming uncontrolled prefixes) and print the counts.
  uint64_t N=1ull<<lg, T15=1ull<<lg15; uint64_t tot16=0,tot17=0,tot18=0,tot19=0,npairs=0;
  for(uint64_t k=0;k<n14;k++){
    uint32_t w14=W14L[k], w14p=w14+dW14; stepi(14,A,E,Ap,Ep,w14,w14p); int got=0;
    for(uint64_t t=0;t<T15&&got<16;t++){ uint32_t w15=r32(); stepi(15,A,E,Ap,Ep,w15,w15); if(!(conform(&GE[19],E[19],Ep[19])&&conform(&GA[19],A[19],Ap[19])))continue;
      stepi(16,A,E,Ap,Ep,0,0); if(!((uint32_t)(Ep[20]-E[20])==(uint32_t)(REp[20]-RE[20]) && Ap[20]==A[20]))continue; got++; npairs++;
      uint64_t ok16=0,ok17=0,ok18=0,ok19=0;
      for(uint64_t n=0;n<N;n++){ uint32_t w16=r32(); stepi(16,A,E,Ap,Ep,w16,w16); if(conform(&GE[20],E[20],Ep[20])&&conform(&GA[20],A[20],Ap[20])&&t10_ok(16,A,E))ok16++; }
      for(uint64_t n=0;n<N;n++){ do{sample(&GA[20],&A[20],&Ap[20]);sample(&GE[20],&E[20],&Ep[20]);}while(!t10_ok(16,A,E));
        uint32_t w=r32(); stepi(17,A,E,Ap,Ep,w,w); if(conform(&GE[21],E[21],Ep[21])&&conform(&GA[21],A[21],Ap[21])&&t10_ok(17,A,E))ok17++; }
      for(uint64_t n=0;n<N;n++){ do{sample(&GA[20],&A[20],&Ap[20]);sample(&GE[20],&E[20],&Ep[20]);}while(!t10_ok(16,A,E));
        do{sample(&GA[21],&A[21],&Ap[21]);sample(&GE[21],&E[21],&Ep[21]);}while(!t10_ok(17,A,E));
        uint32_t w=r32(); stepi(18,A,E,Ap,Ep,w,w); if(conform(&GE[22],E[22],Ep[22])&&conform(&GA[22],A[22],Ap[22]))ok18++; }
      for(uint64_t n=0;n<N;n++){ do{sample(&GA[20],&A[20],&Ap[20]);sample(&GE[20],&E[20],&Ep[20]);}while(!t10_ok(16,A,E));
        do{sample(&GA[21],&A[21],&Ap[21]);sample(&GE[21],&E[21],&Ep[21]);}while(!t10_ok(17,A,E));
        sample(&GA[22],&A[22],&Ap[22]);sample(&GE[22],&E[22],&Ep[22]);
        uint32_t w=r32(); stepi(19,A,E,Ap,Ep,w,w); if(conform(&GE[23],E[23],Ep[23])&&conform(&GA[23],A[23],Ap[23])&&t10_ok(19,A,E))ok19++; }
      tot16+=ok16;tot17+=ok17;tot18+=ok18;tot19+=ok19;
      printf("PAIR W14=%08x W15=%08x E14=%08x E15=%08x A15=%08x ok16=%llu ok17=%llu ok18=%llu ok19=%llu of 2^%d\n",w14,w15,E[18],E[19],A[19],(unsigned long long)ok16,(unsigned long long)ok17,(unsigned long long)ok18,(unsigned long long)ok19,lg);
    }
  }
  printf("TOTAL pairs %llu samples/step/pair 2^%d: ok16 %llu (2^%.3f) ok17 %llu (2^%.3f) ok18 %llu (2^%.3f) ok19 %llu (2^%.3f)\n",(unsigned long long)npairs,lg,
    (unsigned long long)tot16,log2((double)tot16/(npairs*N)),(unsigned long long)tot17,log2((double)tot17/(npairs*N)),(unsigned long long)tot18,log2((double)tot18/(npairs*N)),(unsigned long long)tot19,log2((double)tot19/(npairs*N)));
  return 0;
}
```

### B.4 Shared inputs: ref.h and rows.h

`ref.h` holds the state words `A_i, E_i` (index `i + 4`, `i = -4..31`) and expanded
words `W_i` of both messages of the verified pair of Section 4.4, as computed from `CV1`
and `M1, M1'` with the step function (the same values as the table of Section 4.4).
`rows.h` holds the Table 9 glyph strings of Section 4.1 (rows `-4..35`).

```c
#include <stdint.h>
static const uint32_t RA[36] = {0xedfda8bcu,0x1d78c430u,0x72d495bdu,0xa7214391u,0x25625f6bu,0xbb010228u,0x5f4b195du,0xb47c4ebau,0x5818293eu,0x98da02c7u,0xa0d0d7f7u,0xb0c47881u,0xd8dc8ce5u,0x53bde152u,0xa976d96au,0x5a75d8aau,0xb876c407u,0x678756b9u,0xe47ee1f0u,0x0e600d89u,0x69357198u,0x75d1efffu,0xac90fd09u,0x334f67b5u,0x37a0c32du,0x81e441e7u,0xaff03f51u,0x0f6ca519u,0x469e92d8u,0x9131d1aau,0x0d4a6a27u,0xd4af8bddu,0xe12c905cu,0x113b9e91u,0x1acb4324u,0xd0f7adddu};
static const uint32_t RE[36] = {0x92c65d9du,0x44d8d7adu,0x506e84f8u,0x725cf553u,0xeba41304u,0xf59d5e42u,0xef713183u,0x6afd2d70u,0x944123d4u,0x3832c7c3u,0xcfc28e94u,0xb791d54cu,0xc645c49cu,0xd8989476u,0x0f721babu,0x76d03080u,0xb1306a95u,0xed9df38bu,0x220ddaa5u,0xb73fc968u,0x0b5f9b8bu,0x2d9c70b7u,0x3e6e48b9u,0x137ffa2eu,0x1e1fadadu,0xe8a811a6u,0xaa5a7759u,0x494f927fu,0x14d3fa96u,0x05ea6ae0u,0xc79fc040u,0x233ef15du,0xfcb526acu,0xd45186e7u,0xf829e832u,0x61dd10aeu};
static const uint32_t RAp[36] = {0xedfda8bcu,0x1d78c430u,0x72d495bdu,0xa7214391u,0x25625f6bu,0xbb010228u,0x5f4b195du,0xb47c4ebau,0x5818293eu,0x78da02c7u,0xa491d367u,0xb0c47881u,0xd8dc8ce5u,0x53bdc952u,0xa356db78u,0x3a75d8aau,0xb0744497u,0x6607d6b9u,0xe47ee1f0u,0x2e600d89u,0x69357198u,0x75d1efffu,0xac90fd09u,0x334f67b5u,0x37a0c32du,0x81e441e7u,0xaff03f51u,0x0f6ca519u,0x469e92d8u,0x9131d1aau,0x0d4a6a27u,0xd4af8bddu,0xe12c905cu,0x113b9e91u,0x1acb4324u,0xd0f7adddu};
static const uint32_t REp[36] = {0x92c65d9du,0x44d8d7adu,0x506e84f8u,0x725cf553u,0xeba41304u,0xf59d5e42u,0xef713183u,0x6afd2d70u,0x944123d4u,0x1832c7c3u,0xeb7e8684u,0xb753f50fu,0xc645c49cu,0xb8988076u,0x4db33f2au,0x6ee038d6u,0xb92cea95u,0xed9dfb0bu,0x624fc8a5u,0xb73fc968u,0x0b5b9b9bu,0x2c1cf0b7u,0x3e6e48b9u,0x337ffa2eu,0x1e1fadadu,0xe8a811a6u,0xaa5a7759u,0x494f927fu,0x14d3fa96u,0x05ea6ae0u,0xc79fc040u,0x233ef15du,0xfcb526acu,0xd45186e7u,0xf829e832u,0x61dd10aeu};
static const uint32_t RW[32] = {0x09abc425u,0x0e8b8121u,0x85808046u,0xfadb1bcau,0x394268e3u,0xb9dfbd34u,0xae156845u,0x74169a81u,0x1ea03337u,0xa3210f16u,0x79b82017u,0x91059d10u,0x97294babu,0x65ceec9cu,0x89c67ae2u,0xac5eb7f9u,0x42605c04u,0xd31745a9u,0x8874bab9u,0x37bb854au,0xfa40a444u,0xba37d83eu,0x4bd335dfu,0x2ed17fd8u,0x68e5fc72u,0xe5741ae8u,0x4767824bu,0x3078128eu,0x12338fe1u,0x0750c48au,0xb9cd22fdu,0xa7e4277eu};
static const uint32_t RWp[32] = {0x09abc425u,0x0e8b8121u,0x85808046u,0xfadb1bcau,0x394268e3u,0x99dfbd34u,0xaa556045u,0x54169a81u,0x1fa123bdu,0xa3290316u,0x79b82017u,0x91059d10u,0x97294babu,0x618ee49cu,0xa9c67ae2u,0xac5eb7f9u,0x42605c04u,0xd31745a9u,0x8874bab9u,0x37bb854au,0xfa40a444u,0xbbb7583eu,0x4bd335dfu,0x0ed17fd8u,0x68e5fc72u,0xe5741ae8u,0x4767824bu,0x3078128eu,0x12338fe1u,0x0750c48au,0xb9cd22fdu,0xa7e4277eu};
```

```c
// generated from ePrint 2026/1120 Table 9 (rows -4..35): A,E,W 32-glyph strings, MSB first
static const char *RA9[40] = {
  "================================", // -4
  "================================", // -3
  "================================", // -2
  "================================", // -1
  "================================", // 0
  "================================", // 1
  "================================", // 2
  "================================", // 3
  "================================", // 4
  "nuu=============================", // 5
  "=====u===n=====u=====n==n==n====", // 6
  "================================", // 7
  "================================", // 8
  "==================n=u===========", // 9
  "====n=u===n===========u====u==n=", // 10
  "=nu=============================", // 11
  "====n=========n=n=======u==u====", // 12
  "=======nn=======u===============", // 13
  "================================", // 14
  "==u=============================", // 15
  "================================", // 16
  "================================", // 17
  "================================", // 18
  "================================", // 19
  "================================", // 20
  "================================", // 21
  "================================", // 22
  "================================", // 23
  "================================", // 24
  "================================", // 25
  "================================", // 26
  "================================", // 27
  "================================", // 28
  "================================", // 29
  "================================", // 30
  "================================", // 31
  "================================", // 32
  "================================", // 33
  "================================", // 34
  "================================", // 35
};
static const char *RE9[40] = {
  "================================", // -4
  "================================", // -3
  "================================", // -2
  "================================", // -1
  "================================", // 0
  "================================", // 1
  "================================", // 2
  "==1=============================", // 3
  "==0==1==0=00++======+======1====", // 4
  "==n==0==0011++1===0=+====1=0==11", // 5
  "11u0=n11n1uuuu101000n1==100n0100", // 6
  "10110111nu0100u=11u10101=n001=uu", // 7
  "=10==11=01000101==0001==10=1==00", // 8
  "1nu110001001==00==0n0n==01110110", // 9
  "0u0011n1un110+1u00u11u11n010101n", // 10
  "=11nu11011un0+000011u0001u=u0uu0", // 11
  "1011u=01001nuu+0u11010101001=101", // 12
  "=1=0=10==00111+11==1u=1=n0=0=01=", // 13
  "=u==00===u=011u11==n1=n=1==+====", // 14
  "=0=====+00===11=+==01=0=0==+====", // 15
  "=0=====+01===n1=+==1==1===0u====", // 16
  "==10===nn====1==u===000===11==1=", // 17
  "==1====00====1==0==========1====", // 18
  "==u====10=======1===10==========", // 19
  "==0=============================", // 20
  "==1=============================", // 21
  "================================", // 22
  "================================", // 23
  "================================", // 24
  "================================", // 25
  "================================", // 26
  "================================", // 27
  "================================", // 28
  "================================", // 29
  "================================", // 30
  "================================", // 31
  "================================", // 32
  "================================", // 33
  "================================", // 34
  "================================", // 35
};
static const char *RW9[40] = {
  "================================", // -4
  "================================", // -3
  "================================", // -2
  "================================", // -1
  "================================", // 0
  "================================", // 1
  "================================", // 2
  "================================", // 3
  "================================", // 4
  "==n=============================", // 5
  "=====n===u==========n===========", // 6
  "==n=============================", // 7
  "=======u=======u===n====u=1=u=n=", // 8
  "============u=======nn==========", // 9
  "================================", // 10
  "================================", // 11
  "================================", // 12
  "=====n===n==========n===========", // 13
  "==u=============================", // 14
  "================================", // 15
  "================================", // 16
  "================================", // 17
  "================================", // 18
  "================================", // 19
  "================================", // 20
  "=====0=uu=====1=n=0=============", // 21
  "================================", // 22
  "==n=============================", // 23
  "================================", // 24
  "================================", // 25
  "================================", // 26
  "================================", // 27
  "================================", // 28
  "================================", // 29
  "================================", // 30
  "================================", // 31
  "================================", // 32
  "================================", // 33
  "================================", // 34
  "================================", // 35
};
```

### B.5 interval2.py: confidence bounds (Section 7.9)

Reads the recorded outputs of B.1 and B.2 and computes, for each measured factor, the
exact one-sided Clopper-Pearson lower bound at `alpha = 10^-3`, the combined lower
bound on `pi`, and the comparison with the values used in the budget. Recorded output:

```text
q (cvrate, 2^28 blocks from the IV) k=    16024 n=2^28.00  estimate 2^ -14.032  lower bound 2^ -14.067  (-0.035 bits)
P16 (localrate mode 1, fixdense_2p26_) k=     8217 n=2^26.00  estimate 2^ -12.996  lower bound 2^ -13.045  (-0.050 bits)
P17 (localrate mode 1, fixdense_2p26_) k=     2063 n=2^26.00  estimate 2^ -14.989  lower bound 2^ -15.089  (-0.100 bits)
P18 (localrate mode 1, fixdense_2p22_) k=    65427 n=2^22.00  estimate 2^  -6.002  lower bound 2^  -6.020  (-0.017 bits)
P19 (localrate mode 1, fixdense_2p22_) k=    32681 n=2^22.00  estimate 2^  -7.004  lower bound 2^  -7.028  (-0.025 bits)
P20 (localrate mode 1, fixdense_2p22_) k=  2098138 n=2^22.00  estimate 2^  -0.999  lower bound 2^  -1.001  (-0.002 bits)
P21 (localrate mode 1, fixdense_2p22_) k=  2095425 n=2^22.00  estimate 2^  -1.001  lower bound 2^  -1.003  (-0.002 bits)

pi (fixed template, per accepted block) = product x 2^-14: estimate 2^-56.992; combined lower bound 2^-57.187
used in the budget: q = 2^-14.1 <= 2^-14.067;  pi = 2^-57.3 <= 2^-57.187
joint coverage of the 7 bounds (union bound): >= 0.993
```

Source:

```python
#!/usr/bin/env python3
"""One-sided lower confidence bounds (exact Clopper-Pearson, alpha = 1e-3 per factor) for the
first-block acceptance q (cvrate) and for the six per-step conditional factors of the fixed
second-block template (localrate, dense rows and rows 14/15 fixed to the verified pair), and the
resulting lower bound on the per-block probability pi = P16*...*P21*2^-14 used in the budget."""
import math, re
from pathlib import Path
F = Path(__file__).resolve().parent
ALPHA = 1e-3
def log_binom_cdf(k, n, p):
    if p <= 0: return 0.0
    lp, lq = math.log(p), math.log1p(-p); terms = []; lc = 0.0
    for j in range(0, k + 1):
        if j > 0: lc += math.log(n - j + 1) - math.log(j)
        terms.append(lc + j * lp + (n - j) * lq)
    m = max(terms); return m + math.log(sum(math.exp(t - m) for t in terms))
def cp_lower(k, n, alpha=ALPHA):
    lo, hi = 0.0, k / n
    for _ in range(60):
        mid = (lo + hi) / 2
        if log_binom_cdf(k - 1, n, mid) >= math.log1p(-alpha): lo = mid
        else: hi = mid
    return lo
def report(name, k, n):
    ph = k / n; lo = cp_lower(k, n)
    print(f'{name:34s} k={k:>9d} n=2^{math.log2(n):5.2f}  estimate 2^{math.log2(ph):8.3f}  lower bound 2^{math.log2(lo):8.3f}  ({math.log2(lo/ph):+.3f} bits)')
    return lo, ph
t = (F / 'cvrate_2p28_s7.log').read_text()
k_q = int(re.search(r'\+W5 2-bit \(3\)\s+pass\s+(\d+)', t).group(1)); q_lo, q_hat = report('q (cvrate, 2^28 blocks from the IV)', k_q, 1 << 28)
counts = {}
for fn in ('localrate_fixdense_2p26_s9_16_17.log', 'localrate_fixdense_2p22_s5.log'):
    for m in re.finditer(r'step (\d+):.*measured -log2 P = *[\d.]+ +\((\d+)/(\d+)', (F / fn).read_text()):
        i, k, n = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if i not in counts: counts[i] = (k, n, fn)
los, hats = [], []
for i in range(16, 22):
    k, n, fn = counts[i]; lo, ph = report(f'P{i} (localrate mode 1, {fn[10:24]})', k, n); los.append(lo); hats.append(ph)
pi_hat = math.log2(math.prod(hats)) - 14; pi_lo = math.log2(math.prod(los)) - 14
print(f'\npi (fixed template, per accepted block) = product x 2^-14: estimate 2^{pi_hat:.3f}; combined lower bound 2^{pi_lo:.3f}')
print(f'used in the budget: q = 2^-14.1 {"<=" if -14.1 <= math.log2(q_lo) else ">"} 2^{math.log2(q_lo):.3f};  pi = 2^-57.3 {"<=" if -57.3 <= pi_lo else ">"} 2^{pi_lo:.3f}')
print(f'joint coverage of the 7 bounds (union bound): >= {1 - 7 * ALPHA:.3f}')
```

### B.6 cost32_block.py: the fixed budget and its success bound (Sections 7.5, 7.7)

Evaluates `M`, `N_b`, the two failure terms and the worst-case work from the parameters
`q` and `pi`, with the sensitivities quoted in Section 7.5. Recorded output:

```text
pi = 2^-57.3, q = 2^-14.1: M = 2^56.785 accepted blocks needed, N_b = 2^70.887 block trials (mu = 2^56.787)
Pr[A < M] <= exp(-5.92e+10);  (1-pi)^M <= exp(-0.7) = 0.4966;  success >= 0.5034
work: block trials 2^70.981 + accepted-block work 2^55.33 + preprocessing 2^40 + O(1) = 2^70.981
claimed time_log2 = 71.5; margin 0.52 bits
variant: accepted-block work charged as one whole compression each -> 2^70.981
trials for success >= 0.39: M = 2^56.283, work 2^70.479
trials for success >= 0.5: M = 2^56.771, work 2^70.967
sensitivity: pi = 2^-57.5 -> 2^71.18
sensitivity: pi = 2^-58.0 -> 2^71.68
sensitivity: q = 2^-15 -> 2^71.88
```

Source:

```python
#!/usr/bin/env python3
"""Fixed-budget cost and success bound with block-level independence only.
Blocks: N_b fresh uniform first blocks (independent). Each accepted block (probability q_true >= q) gets ONE
fixed second-block template (W14*, W15* of the verified pair) and succeeds with probability >= pi, where pi is
the per-block probability that this template conforms at steps 16..23 for the block's W16..W23.  No
within-block amortisation over several candidates is credited.
Pr[fail] <= Pr[A < M] + (1 - pi)^M,  A ~ Bin(N_b, q_true),  M = ceil(c / pi)."""
import math
C = 2224.0
def l2(x): return math.log2(x)
q_log2 = -14.1; pi_log2 = -57.3; c = 0.70; delta = 2**-10
M = c * 2**(-pi_log2); N_b = M * (1 + delta) / 2**q_log2; mu = N_b * 2**q_log2
p_fail_A = math.exp(-(delta/(1+delta))**2 * mu / 2); p_fail_C = math.exp(-c)
print(f'pi = 2^{pi_log2}, q = 2^{q_log2}: M = 2^{l2(M):.3f} accepted blocks needed, N_b = 2^{l2(N_b):.3f} block trials (mu = 2^{l2(mu):.3f})')
print(f'Pr[A < M] <= exp(-{(delta/(1+delta))**2*mu/2:.3g});  (1-pi)^M <= exp(-{c}) = {p_fail_C:.4f};  success >= {1 - p_fail_A - p_fail_C:.4f}')
w_block = N_b * (1 + 150/C)          # one full compression + worst-case check (150 ops)
w_acc = M * (300 + 512) / C          # inversion W0..W7 + template evaluation incl. survivors, per accepted block
w_pre = 2**40; W = w_block + w_acc + w_pre + 8
print(f'work: block trials 2^{l2(w_block):.3f} + accepted-block work 2^{l2(w_acc):.2f} + preprocessing 2^40 + O(1) = 2^{l2(W):.3f}')
claim = 71.5
print(f'claimed time_log2 = {claim}; margin {claim - l2(W):.2f} bits')
W_fb = N_b * (1 + 150/C) + M * 1.0 + w_pre
print(f'variant: accepted-block work charged as one whole compression each -> 2^{l2(W_fb):.3f}')
for p in (0.39, 0.5):
    Mx = -math.log(1-p) * 2**(-pi_log2) * (1 + 1e-9); Nx = Mx*(1+delta)/2**q_log2
    print(f'trials for success >= {p}: M = 2^{l2(Mx):.3f}, work 2^{l2(Nx*(1+150/C) + Mx*812/C + w_pre):.3f}')
for pl in (-57.5, -58.0):
    Mx = c*2**(-pl); Nx = Mx*(1+delta)/2**q_log2; print(f'sensitivity: pi = 2^{pl} -> 2^{l2(Nx*(1+150/C)+Mx*812/C+w_pre):.2f}')
Mx = c*2**(-pi_log2); Nx = Mx*(1+delta)/2**-15; print(f'sensitivity: q = 2^-15 -> 2^{l2(Nx*(1+150/C)+Mx*812/C+w_pre):.2f}')
```
