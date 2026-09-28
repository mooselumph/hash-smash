# SHA-256 r32 ordinary-collision attack

> Status: **READY**. Claimed score: time `98`, memory `25`, success `0.9`.
> Updated: 2026-09-28.

This package gives a finite two-block ordinary-collision algorithm for
`sha256-r32-prefix-v1`. It adapts the published 36-step construction in ePrint
2026/1120 to rounds 0 through 31, enumerates the complete `(W14,W15)` tail set,
and assigns a fresh uniform first block to every tail trial. The algorithm runs
exactly `2^94` trials, uses less than `2^98` charged target-compression units,
and uses less than `2^25` bytes at peak. The complete tail set has been counted
exactly: `|V| = 2,088,960`.

The success claim is conditional on two disclosed population bounds: the
first-block filter has density at least `2^-18`, and the complete-tail average
conditional yield is at least `2^-74`. These are exploratory cryptanalytic
premises with three and seventeen bits of slack, respectively, relative to the
published construction's measurements and accounting. Full digest recomputation
prevents either premise from producing an invalid witness if it is wrong.

The primary source is Li et al., ePrint 2026/1120, especially its Tables 9-10 and
Section 4.2: <https://eprint.iacr.org/2026/1120>. The target and cost model are the
repository's `sha256-r32-prefix-v1` and `collision-frontier-v5` definitions.

---

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

E1120 reports an ordinary 36-step SHA-256 collision attack with time about
`2^57`, negligible memory, and a published colliding pair. Its two-block method
first finds a dense internal solution, filters first blocks against that
solution, then uses freedom in `W14,W15` to satisfy 57 remaining conditions.

The published complete 36-step messages do not become a complete 32-step
collision when simply truncated: reducing the first block changes its chaining
value. The reusable object is the differential construction and conversion
algorithm, not the published digest witness itself.

This package applies that construction to the exact 32-step target and uses a
fixed conservative budget. It claims time below `2^98`, peak memory
below `2^25` bytes, and success at least `0.9`, subject to the disclosed
first-block-density and average-tail-yield hypotheses. The previous `2^71.5`
submission used participant-seeded confidence intervals with less than one bit
of score slack and was not evaluable. Those intervals and that score are not
reused here.

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
  one and three: `1+4+6+4 = 15`, the paper's count. E1120 reports an observed
  first-block acceptance rate near `2^-15`; Section 7.2 uses the weaker premise
  `q >= 2^-18`.
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
and expanded words of this pair at 32 steps, recomputed independently with the exact
step function (columns as in Table 9, followed by the expanded words `W_i`, `W'_i`
in hex), are:

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

The independent replay checked that every `n`/`u` glyph of Table 9 rows `0..31`
for `A`, `E` and `W` coincides with the pair's signed
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
  for every retained tail entry by Section 6.1.
- `W20` (`s0(W5)` vs `W13`): `W13` is dense; the three conditions on `W5` are the Table
  10 row `W5`, part of the first-block filter (Section 6.2, item 2).
- `W22` (`W6` vs `s0(W7)`): the three conditions on `W7` are the Table 10 row `W7`,
  part of the first-block filter; the signs of `W6` are its `∇W6` row, also in the filter.
- `W24` (`W8` vs `s0(W9)`): both dense; the six Table 10 conditions on `W8` are solved
  by the fixed dense solution of Section 6.1.
- `W25` (`W9` vs `s1(W23)`): `W9` is dense; the three Table 10 conditions on `W23` are
  among the 57 uncontrolled conditions covered by the tail-yield premise.
- `W28` (`s0(W13)` vs `W21`): `W13` is dense, so the modular difference of `s0(W13)` is
  fixed; the modular difference of `W21` is fixed by the `∇W21` row of Table 9 (three
  `n`/`u` glyphs and three value glyphs, which together fix the signed pattern and hence
  the modular difference `W'21 - W21 = +2^24 + 2^23 - 2^15`, the negative of `s0(W'13) - s0(W13)`);
  those six glyphs are among the 57 uncontrolled conditions. Given them the
  cancellation is deterministic, as the last column shows.
- `W29` (`W13` vs `s0(W14)`): `W13` is dense; the three sign conditions on `s0(W14)` hold
  for every retained tail entry by Section 6.1.
- `W30` (`W14` vs `W23`): both differences are single bits at position 29 with opposite
  signs fixed by the `∇W14` and `∇W23` rows (`u` and `n`); the cancellation is
  deterministic once row 23 holds.

The words with a difference: `W21 = W5 + s0(W6) + W14 + s1(W19)` has three active
inputs whose signed differences are fixed by the filter (`W5`, `W6`) and the current
tail entry (`W14`); its own signed pattern (row 21) then holds with the probability of the three
value glyphs and the four Table 10 conditions, counted among the 57. `W23 = W7 + s0(W8)
+ W16 + s1(W21)` has active inputs `W7` (filter), `s0(W8)` (dense) and `s1(W21)` (whose
signed output difference is fixed by the four Table 10 conditions on `W21`); its single
`n` glyph and three Table 10 conditions are counted among the 57. The `W24`
cancellation is dense-only; the other seven are included in the deterministic
tail-entry conditions or the disclosed average tail-yield premise of Section 7.2.

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
dense part, the filter conditions, the complete tail-entry conditions of Section 6.1 and the 57
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

## 6. Finite attack algorithm

This construction uses the two-block conversion of E1120, Section 4.2, with a
deliberately conservative budget. The two candidate messages are
`m = B0 || M1` and `m' = B0 || M1'`. Both are 128 bytes; normal SHA-256 padding
adds the same third block. Every compression uses rounds 0 through 31.

### 6.1 Fixed dense solution and complete tail set

Use the published dense assignment for `W8..W13`, `A0..A13`, and `E4..E13`
from the verified E1120 pair. The attack reuses these fixed public constants as
fewer than `2^10` bytes of nonuniform advice; it does not rerun the historical SAT
search. It verifies the assignment against the displayed characteristic before
using it.

Build the tail array `V` in two exhaustive stages. First scan all `2^32` values
of `W14` and retain those satisfying the row-14 conditions, the `W16` and `W29`
cancellations, and the step-15 modular-difference conditions that are already
determined by `W14`. Exactly 32 values survive. Sixteen are live after the
second stage:

```text
89667ace 89667acf 89667aee 89667aef
89667ece 89667ecf 89667eee 89667eef
89c67ac2 89c67ac3 89c67ae2 89c67ae3
89c67ec2 89c67ec3 89c67ee2 89c67ee3
```

The other 16 first-stage values are these values plus `0x10000000`; each has
zero valid `W15` completions. For a retained `W14`, addition by the known step-15
constant is a bijection between `W15` and `E15`. The row-15 `E` pattern fixes nine
bits, so enumerate its `2^23` free assignments, recover the unique `W15`, and
test the remaining predicates. Thus the second stage examines exactly
`32 * 2^23 = 2^28` candidates rather than all `2^64` word pairs.

For each candidate, derive `(W14',W15')` from the published message differences,
run steps 14 through 16 for both branches, and retain the pair exactly when all
five deterministic tail conditions hold:

1. `(W14,W14')`, `(E14,E14')`, and `(A14,A14')` satisfy every Table 9 row-14
   glyph.
2. The schedule cancellations `W16 = W16'` and `W29 = W29'` hold.
3. The modular differences of `(E15,E15')` and `(A15,A15')` equal the
   characteristic's step-15 differences.
4. `(W15,W15')`, `(E15,E15')`, and `(A15,A15')` satisfy every Table 9 row-15
   glyph.
5. With the common `W16`, the modular differences of `(E16,E16')` and
   `(A16,A16')` equal the characteristic's step-16 differences.

These are the same deterministic tail-entry conditions used before the 57
uncontrolled conditions in E1120. Fifteen live `W14` values each have exactly
`2^17 = 131,072` valid completions; `W14 = 89667aee` has exactly
`15 * 2^13 = 122,880`. Therefore

```text
s = |V| = 15 * 131,072 + 122,880 = 2,088,960
log2(s) = 20.9943534369.
```

The published `(89c67ae2, ac5eb7f9)` entry is among them. Store the pairs in
lexicographic order as eight-byte records, occupying exactly 16,711,680 bytes.

This enumeration does not need the future first-block chaining value. Rows 14
and 15 use only the fixed dense states and the candidate tail. The difference
`W16'-W16` depends only on the already fixed differences in `W9` and `W14`;
requiring it to be zero makes the unknown absolute `W16` a common addend in the
two step-16 updates. It therefore cancels from both `E16'-E16` and `A16'-A16`.
The `W29` cancellation likewise depends only on the fixed `W13` difference and
the candidate `W14`. Thus membership in `V` is a deterministic preprocessing
predicate, while the later 57-condition outcome remains dependent on `B0` and
is exactly what `pi_v` measures.

### 6.2 Fixed online budget

Run exactly `N = 2^94` trials. Maintain a tail index `j`, initially zero. Trial
`t` uses `V[j]`; increment `j` and reset it to zero after `s-1`, so every
complete cycle uses each tail entry once. For each trial:

1. Draw a fresh uniform 64-byte `B0` from two independent 256-bit random words
   and compute `CV1 = C32(IV,B0)`.
2. Apply E1120's on-the-fly first-block filter. In the paper's notation, derive
   `E3,W7,E2,W6,E1,W5` from `CV1` and the fixed dense solution. Reject unless
   the Table 9 signed differences and Table 10 bit relations on
   `(E3,W5,W6,W7)` all hold.
3. For an accepted block, invert the step equations to obtain `W0..W4`. The
   words `W5..W7` are the trial-derived values from step 2; only `W8..W13` are
   fixed by the dense assignment. Combine these fourteen words with the current
   `(W14,W15)` tail entry, apply the fixed characteristic differences to obtain
   the primed words, and serialize the resulting `M1,M1'`.
4. Compute both second-block compressions. Continue only if the complete eight
   chaining words agree. Then compute both common padding-block compressions
   and compare all 256 digest bits. Output only if the messages differ and the
   complete digests agree.

If all `2^94` trials fail, output failure. The verifier check in step 4 means a
wrong differential prediction can reduce success but cannot create a false
collision witness.

## 7. Cost and success ledger

### 7.1 Deterministic resource bound

The cost model charges one full `C32` as one unit and each other word-RAM
primitive as `1/2224` unit.

- Fixed dense assignment: fewer than `2^10` public advice bytes. Verifying all
  displayed state, message, and cancellation relations costs less than `2^20`
  RAM primitives.
- Tail enumeration: charge at most `2^12` RAM primitives for each of the `2^32`
  first-stage candidates and each of the `2^28` second-stage candidates. Including
  verification, indexing, and storage, the preprocessing costs less than `2^34`
  target-compression units.
- One online trial: charge five complete compressions (one first block, two
  second blocks, and two padding blocks) even when an early test rejects. Add a
  blanket `2^14` RAM primitives for randomness, inversion, formatting,
  comparisons, indexing, loop control, and storage. This is less than
  `5 + 2^14/2224 = 12.36691 < 2^3.629` units.
- All online trials therefore cost less than `2^97.629` units.

The complete total satisfies

```text
2^94 * (5 + 2^14/2224) + 2^34 < 2^98,
```

which is the declared `time_log2`. This is a worst-case fixed budget, not
expected work. The tail array occupies 16,711,680 bytes; code, constants,
counters, one candidate pair, and generation state fit in the remaining space
below the declared `2^25`-byte peak.

### 7.2 Success probability

Let `q` be the probability that a fresh uniform first block passes the exact
filter in Section 6.2. For `v in V`, let `pi_v` be the conditional probability
that tail entry `v` reaches the full second-block equality given acceptance.
The two score-critical conservative hypotheses are

```text
q >= 2^-18
(1/s) * sum_{v in V} pi_v >= 2^-74.
```

E1120 reports `q about 2^-15` after `2^40` first-block trials and counts 57
uncontrolled tail conditions. The package uses three extra bits on the first
filter and seventeen extra bits on the tail. The bounded participant runs in
Section 8 found 32,871 acceptances among 560,988,160 deterministic PRNG-generated
blocks, a raw rate of about `2^-14.059`. This observation is directional only:
fixed seeds do not establish population coverage, and no confidence interval or
iid claim is made from them.

E1120's published ledger treats `2^20` usable tail values against 57 remaining
conditions as requiring `2^(57-20) = 2^37` accepted first blocks, leading to its
`2^57` total. That calculation implicitly uses an average tail yield near
`2^-57`. This package allows a seventeen-bit degradation to `2^-74` and assigns a
fresh independent first block to every tail trial, so it does not treat the
`2^20` continuations of one first block as independent. The average-yield lower
bound remains a disclosed heuristic rather than a theorem derived from the
paper's count.

Each trial's success event is a function of its fresh independent `B0` and its
fixed cyclic tail entry. The events are therefore independent across trials,
although their probabilities may differ by tail entry. Every entry is used at
least `floor(N/s)` times. Since `s = 2,088,960 < 2^21`, the sum of the trial success
probabilities is at least

```text
(N - s) * 2^-18 * 2^-74
  > (2^94 - 2^21) * 2^-92
  = 4 - 2^-71.
```

Thus the failure probability is at most
`product_t(1-p_t) <= exp(-sum_t p_t) < exp(-(4-2^-71)) < 0.019`, and success is
greater than `0.981`. The claim records `0.9`.

## 8. Bounded joint-distribution checks

The exact tail count and two bounded participant runs were independently replayed
inside this research session. The generator computes `C32(IV,B0)` for uniform
512-bit first blocks, applies the exact first-block filter, and retains the first
16,384 accepted chaining values. For every retained value it evaluates all
2,088,960 tail entries, preserving the actual chaining state through steps 16
and 17. A separate scalar checker reconstructs every surviving message pair,
checks each characteristic row, and compares its result with
`verifier/hash_functions.py:_compress`. The published reference pair is a
self-test and reaches a full second-block collision.

```text
seed       generated B0   raw accepts   P16 paths   P17 paths   P18 paths   P19 paths
20260929     278,921,216        16,417   4,176,468          76           1           0
20260930     282,066,944        16,454   4,172,865          71           0           0
combined     560,988,160        32,871   8,349,333         147           1           0
```

Each run evaluates `16,384 * 2,088,960 = 34,225,520,640` concrete
accepted-state/tail pairs. Combined observed exponents are `13.0011` for P16,
an additional `15.7936` from P16 to P17, and `28.7947` from `V` to P17. These
agree closely with the 13 and approximately 16 local-condition bits in the
published ledger. One of the 68,451,041,280 combined pairs reaches P18; none
reaches P19. Tails sharing one first block are dependent, so these totals are
not treated as binomial trials and establish no confidence interval or full
57-condition yield.

Two selection ideas were stopped. Ranking individual tails by their P16 count
on 8,192 training blocks produced no P16 enrichment on 8,192 holdout blocks and
reduced P17 yield. A one-bit `W14` partition selected after that run gave only a
1.10-fold aggregate P17 rate increase on the second seed and reversed direction
between its two halves. Neither selector is used by the attack or its cost claim.

## 9. Evidence boundary

The construction, target, iteration cap, and deterministic accounting are fully
specified. Three cryptanalytic premises remain visible:

1. The published 36-step characteristic and its deterministic cancellations
   transfer unchanged to the 32-step prefix because their support ends by
   schedule index 30.
2. The exact r32 first-block filter has density at least `2^-18`.
3. Averaged across the complete finite tail set, an accepted first block reaches
   the collision with probability at least `2^-74`.

The first premise has two exact reference replays and a structural index check.
The second and third are conservative extrapolations from E1120's executed
36-step attack, its reported `2^-15` first-block measurement, its 57-condition
ledger, and the bounded joint checks through P18. The exact tail count and
preprocessing bounds are deterministic; the fixed-seed population measurements
are directional. No organizer experiment or theorem establishes the two
population lower bounds, so they remain explicit exploratory heuristics.
