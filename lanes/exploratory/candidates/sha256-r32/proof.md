# SHA-256/32 fixed-budget ordinary-collision construction

## 1. Claim and scope

This exploratory candidate supplies an ordinary collision for the organizer target
`sha256-r32-prefix-v1` and reports the conservative vector
`time=62`, `preprocessing=57`, `memory=39`, `advice=33`, and
`success_probability=1` under `collision-frontier-v5`.

The time bound is an upper-bound scenario for a finite, fully charged construction.
The collision relation and paid-range lineage are mechanically replayed. Historical
preprocessing and historical peak memory remain disclosed premises. Review should
accept, reject, or request evidence for those premises explicitly rather than infer
them from the witness.

This is a track improvement claim. It is not a claim that SHA-256 is broken at all
64 steps, that this is the highest attacked round count, or that the construction is
a new generic theorem.

## 2. Exact selected target

The target is SHA-256 with:

- the fixed FIPS 180-4 IV;
- standard SHA-256 padding and 64-bit big-endian bit length;
- original compression steps 0 through 31 on every padded block;
- normal message expansion, constants, and feed-forward; and
- equality of all 256 output bits.

The target profile hash is
`93d2e5d9ca93540633798d58cbab2d6d8447916db2b127e9abe71f45d14f6835`.
The organizer reference implementation `verifier/hash_functions.py` has SHA-256
`514fa8ab8a461e4a41080efa27b4ba2a3b499eeedf0a2d2346e6562835d040f5`.
The organizer base commit is `fc56c3fa38ac40043d8291649c78148bc4872995`.

## 3. Certificate and collision relation

The certificate manifest declares two distinct 128-byte messages:

| artifact | bytes | ordinary file SHA-256 |
|---|---:|---|
| `certificates/message-a.bin` | 128 | `92e9ab74fd94956893727406209e64ed6645d3af8748c56a8bc45096b7f33a84` |
| `certificates/message-b.bin` | 128 | `0a3f5c00ffacbceda4fa2dd7092b59b01a34ca865ca589c30c9d8b3858c80da8` |

The organizer checker computes for both complete padded messages:

```text
f8a3db111360e5ed2e63041ecfa82b01c95a25882910bc0f21671949296a4e77
```

The messages share their first 64-byte block and differ in their second block.
Each unpadded message is 128 bytes, so standard padding adds an identical third
block ending in the big-endian bit length `0x0000000000000400`. The independently
reconstructed states agree after the differing second block, and processing the
identical padding block preserves equality.

A bounded clean-room replay has certificate SHA-256
`2561e1239f203f4b1f7b4405e764f58a6a12bc5870e915a572fc4c1df8e2aa87`
and source SHA-256
`49d89cdec78081ae6358a69d92a62612afb68a730da11cfe8cf89d7963ba6ee0`.
It reconstructs the seed-derived first block, recomputes C32, derives both second
blocks from the bound tuple/table/tail records, checks the padding block, and
cross-checks the organizer implementation. Live and relocated offline executions
both return `PASS`. Semantic tuple and derivation-record mutations fail closed.

The replay full-hashes the 46,881,968-byte retained tuple file and the 9,437,184-byte
tail file. It embeds and hashes the exact consumed slices of the 5.69 GB lookup
corpus while inheriting the complete lookup-file hashes from sealed provenance.
This certificate establishes the witness and its paid-range coordinates. It does
not establish the resource bounds or a fresh-search probability.

## 4. Paid-range lineage

The construction is pinned to:

```text
runner SHA-256       4aa2673044202dce8a4da370ab512b8a5ff23cfcc9ac16a179a19a9490595786
config SHA-256       4a86485d80c3609aa488590273f9aa6b0150120c07a5ce16b620a1bb9e969a22
provenance commit    d9afb19649446dc89c92c484e82e17139a4d52e8
provenance JSON      0083ce59d8b48f325f881a5c16ac325d72c732fbb64f7dac32acba6133bc0685
```

The successful coordinate is:

```text
chunk                              34
seed                               202610040034
first-block counter                2149248237
counter limit, exclusive           68719476736
local tuple index, zero based      15529
prior admitted tuple records       14224648
global tuple index, zero based     14240177
tuple cap, exclusive               1073741824
tail index, zero based             131794
tails per tuple                    196608
```

The complete chunk-34 tuple file is 46,881,968 bytes and has SHA-256
`c3ea41e428beae328693cef62f32beb8f7753f2a7def98280ecd5cf847ba86ad`.
The winning 112-byte record begins at offset 1,739,248 and has SHA-256
`d650d9eb55ae375e9380583c28fd92e37ef31fa8540ff2d7b10a20cc7cb0c51e`.
The winning manifest names `full.tuples.bin` as both match output and Step-3 input,
with equal byte and tuple counts and exact record divisibility.

A one-record replay with the pinned C implementation recomputed the record's C32,
rebuilt the Step-2 tuple, audited the prefix, enumerated the sealed tail set, and
found the winner at tail 131,794. It emitted the same two message blocks, reserved
one verification, performed two C32 checks for each branch, and ended with
`STATUS exit_code 0`.

The terminal auditor is the corrected 324,716-byte source with SHA-256
`e53f50ee913194b8200a37814d50da6d4aee7bdbf5864a33303c243374788269`.
Terminal audit SHA-256
`181b7fe2ba0ce6cfa0bc2733dc6e3f18f385524f1e9100ec7fd05604adf74097`
reports a quiescent offline snapshot with no errors or warnings.

The terminal audit records:

| quantity | measured count |
|---|---:|
| completed match attempts | 35 |
| completed Step-3 attempts | 35 |
| first blocks processed | 2,405,181,685,760 |
| valid tuple records | 14,643,237 |
| tuple-tail pairs processed | 2,799,733,071,213 |
| independently verified collisions | 1 |

The hit occurred at chunk 34. Review checkpoints 640 and 1292 were never reached,
so this candidate claims no checkpoint manifest, approval, or consumed-token record.

## 5. Exact score arithmetic

The submitted score charges the declared full campaign rather than the lucky
observed stopping point. It includes all failed work and one complete rerun allowance.
The cost model converts ordinary operations at `C = 2224` operations per target
compression.

For first-block matching, charge `2^49` executions. Each execution costs at most
one baseline C32 plus `2^24` ordinary operations:

```text
T_match <= 2^49 * (1 + 2^24 / 2224)
        = 590374060402231214080 / 139.
```

For tail completion, charge `2^31` tuple records and all 196,608 tails per record,
so `Q = 3 * 2^47` tuple-tail evaluations. Each costs at most two C32 evaluations
plus `2^16` ordinary operations:

```text
T_tail <= (3 * 2^47) * (2 + 2^16 / 2224)
       = 1846757322198614016 / 139.
```

The remaining aggregate allowances are:

```text
T_preprocessing      <= 2^57
T_final_verification <= 2^45
```

Therefore:

```text
T_total <= T_match + T_tail + 2^57 + 2^45
        = 612257719494694141952 / 139
log2(T_total) = 61.9337598837787
T_total < 2^62 target-compression units.
```

The candidate reports 62 conservatively. It does not round the early-hit execution
downward. The remaining margin below `2^62` is about 4.4876 percent.

The source-path ceiling and conversion remain reviewable evidence. If a reachable
paid path exceeds either per-item ceiling, if a charged phase is omitted, or if the
cost model rejects the conversion, score 62 does not follow.

## 6. Preprocessing premise

The aggregate preprocessing field is 57. It covers starting-solution work, both
large-table constructions, tail construction, historical development work, and
the complete rerun allowance.

The sealed resource ledger has SHA-256
`fd2eac5d20fbe2cde77e0f7443ad25fb5263928104c78d976760886c30b69f4c`.
Its verifier receipt has SHA-256
`23e99f9ed7fcdddadace7c88ef0e33417273869881edf8a8d77f298d3ffe0622`.
Those artifacts bind source arithmetic and known local preprocessing below `2^51`.

They do not receipt all historical and development work. This exploratory claim
therefore states the additional premise that the unreceipted remainder is below
`2^56`. Since `2^51 + 2^56 < 2^57`, the aggregate field follows if that premise is
accepted. A reviewer may reject the premise or require a complete historical
receipt. The RFC 3161 seal is not represented as proof of the missing quantity.

## 7. Memory premise

The field `memory_log2_bytes: 39` is a whole-process peak ceiling. It covers mapped
tables, code, tuple buffers, worker state, allocator overhead, process trees,
verification, and every other simultaneously live object.

Constructive accounting for current reproducible phases remains below `2^34` bytes.
The source paper reports a 378 GB server for its tuple-generation experiment, but
server capacity is not a peak-memory measurement for this run. No complete peak-RSS
trace survives for historical starting-solution work. The historical portion is an
explicit exploratory premise under the `2^39` ceiling. Memory does not contribute
to the v5 scalar, but it remains required and reviewable.

## 8. Retained advice

The post-terminal inventory is a newline-terminated canonical TSV with one row per
resolved regular-file target inode. It records:

```text
external unique bytes             5,760,270,500
inventory bytes                     234,801
reserved downstream envelope     67,108,864
total with full envelope        5,827,614,165
exclusive advice cap            8,589,934,592
```

The inventory has SHA-256
`40ebe183ffe22346e10b285e11ad794276bf16afcecca8215d68354c4f6736cf`.
Its detached receipt has SHA-256
`84c56ccc0f92c7159efcaca9164cbc65338e768282c1277ea99c572cd5d008eb`.
The full `2^26` envelope is charged even when the final candidate and note are
smaller. Retaining generated tables as advice does not erase their preprocessing
or resident-memory cost.

## 9. Meaning of success probability 1

Discovery is already fully charged in time, preprocessing, failures, retry allowance,
memory, and retained advice. After the mechanically checked witness is fixed, the
submitted algorithm has one empty random tape: load the two certificate files and
run the organizer checker. That deterministic relation replay succeeds, so the
declared success probability is 1 for this retained construction.

This is not the probability that a fresh capped campaign finds another witness.
The single observed hit and stage histograms do not estimate that probability.
No Poisson independence claim or extrapolated fresh-search confidence is required
for the fixed-witness proposition submitted here.

## 10. Research attribution

The cryptanalytic framework is attributed to Yingxin Li, Fukang Liu, Gaoli Wang,
and Jiali Shi, *Improved Collision Attacks on SHA-256*, CRYPTO 2026 / IACR ePrint
2026/1080, with related framework context from Li, Liu, and Wang, ePrint 2024/349.

The published work supplies the two-block attack structure and differential route.
This package contributes the project-specific SHA-256/32 implementation, sealed
finite campaign, exact witness, paid-range reconstruction, and HashSmash cost
accounting. It does not claim authorship of the published cryptanalytic method.

## 11. Evidence boundary

Mechanically established here:

1. Candidate schema and package safety through organizer intake.
2. Two distinct complete messages and their exact C32 digest.
3. Target configuration and organizer implementation hashes.
4. Winner coordinates inside the paid tuple and tail ranges.
5. Terminal campaign counts, quiescence, and corrected auditor identity.
6. Exact v5 score arithmetic conditional on the declared inputs.
7. Advice arithmetic below `2^33` including the full downstream reserve.

Disclosed for exploratory review:

1. Unreceipted historical and development preprocessing is below `2^56`.
2. Historical whole-process peak memory is below `2^39` bytes.
3. The static per-item source ceilings cover every reachable paid path.

Not claimed:

1. A fresh-search success probability.
2. A 35-step complete-message collision from these two messages.
3. A full 64-step SHA-256 collision.
4. Production-Yukon acceptance or promotion before official readback.

## References

1. NIST, FIPS PUB 180-4, *Secure Hash Standard*.
2. Yingxin Li, Fukang Liu, Gaoli Wang, and Jiali Shi, IACR ePrint 2026/1080.
3. Yingxin Li, Fukang Liu, and Gaoli Wang, IACR ePrint 2024/349.
