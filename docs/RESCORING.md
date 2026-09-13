# Computation accounting and cost-only reorgs

## Prices

V5 scores log2(total computation in target-compression equivalents). One selected
compression/permutation costs 1; each other 256-bit RAM primitive costs 1/C.
Memory remains a required metric, with no scalar contribution or tie-break.

| Target | C |
| --- | ---: |
| MD5-s63 / s64 | 843 / 856 |
| SHA-1-r79 / r80 | 1957 / 1982 |
| SHA-256-r31 / r32 | 2140 / 2224 |
| SHA3-256-r5 / r6 | 1355 / 1626 |

`python3 scripts/reference_operation_costs.py` reproduces these estimates from the
trusted reference cores. It counts additions, logical operations, shifts and masks
on data words, including message expansion and feed-forward. Narrow rotations use
their explicit 256-bit-RAM implementation. Public loop/index arithmetic, Python
overhead, memory traffic and serialization are excluded from this reference
normalization. These are portable data-path estimates, not CPU timings or complete
instruction counts. All actual attack work, including memory accesses, remains
charged; a whole compression's internals must not also be charged individually.
Weights can alter rankings. Pending targets require their own reference costs
before activation; the shared model does not assign invented costs to them.

The definitions follow [MD5](https://www.rfc-editor.org/rfc/rfc1321),
[SHA-1/SHA-256](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), and
[Keccak](https://keccak.team/keccak_specs_summary.html).

## Resource ledgers

Add optional `resource_ledger` to `claim.json`, using
[resource-ledger-v1](../schemas/resource-ledger-v1.schema.json). Older packages
remain accepted. A ledger describes the entire algorithm at the claim's success
probability, including preprocessing, failures, recovery and verification.

Each component has an ID, phase, operation category, `count_log2`, bound kind,
review status, evidence and assumptions. Categories are `target_compression`,
`word_operation`, and `opaque`. Omit zero-work components: log2(0) is undefined,
while `count_log2: 0` means one operation. Use `source_weights: null` for raw counts;
opaque work records the prices in which its historical bound was stated.
Component bounds must cover all work without overlapping allowances. Use
`exact`, `upper_bound` or `estimate`, and `supported`, `conditional` or `unresolved`.
Only exact counts and upper bounds can set a migrated score; conditional bounds
retain their assumptions and are limited to the exploratory lane.

The normal cost judge reviews or reconstructs this ledger and retains it in
`cost_reconstruction.resource_ledger`. Normal reviews still score the submitted
`time_log2` bound. Their ledger prepares future migrations, without giving a model
an unchecked scalar override. Unknown work may remain an opaque total.

## Cost-only reorgs

Yukon still dispatches its ordinary intake, judge and score workflow. A protected
`reorg/plan.json` entry selects cost-only mode for an exact track and package.
Unlisted packages receive normal review. Entries pin both source and destination
configuration hashes: changing the algorithm, target, success rules or other work
semantics cannot silently inherit an old qualification. The initial v4-to-v5 entry
also explicitly authorizes the accounting-code migration; later v5 entries change
only prices. A code change needs a reviewed configuration pin, not just a prompt.

1. Download the trusted workflow's evidence and complete judge dossier before its
   30-day artifact expiry. Preserve them durably in the protected repository:

   ```sh
   python3 scripts/archive_review.py --evidence /path/judge-evidence.json \
     --dossier /path/judge-dossier.json
   ```

2. Review the emitted entry into `reorg/plan.json`'s `entries` array, along with the
   content-addressed archive it names. Include baseline packages when those should
   also be repriced. Keep every ancestor archive. Archive hashes authenticate
   content; the organizer-reviewed plan establishes its trusted provenance.
3. Merge the reviewed policy/plan and perform the usual managed Yukon reorg.
   Intake rechecks the package and certificates; original experiment evidence is
   inherited unchanged. Only the cost reviewer runs. It receives the original
   evidence and full qualification anchor plus the compact history of cost reviews.
4. The scorer verifies the chain, preserves qualification and success probability,
   and prices the new ledger deterministically. Memory, data and advice remain
   unchanged. Original time and preprocessing bounds appear as `declaredTimeLog2`
   and `declaredPreprocessingLog2`, with their original model and prices; the new
   score records its ledger, weights and source archive.
5. Before another reorg, archive the new evidence/dossier and point a new entry at
   it. Earlier scalar scores are never interpreted as raw operation counts.

Unknown work B at original weights w is repriced conservatively as
`B * max(new_weight / original_weight)`. Its original weights remain attached
through every reorg. Under the v4-to-v5 discounts an opaque v4 bound therefore
stays unchanged. Missing decomposition does not create a new validity failure.
Incomplete cost reviews emit no score and report that further evidence is needed.
The history is bounded to 32 records and 2 MiB of model input; exceeding either
limit stops explicitly rather than silently dropping provenance.

The checked-in plan starts empty. Prices apply to all active lanes, but this PR
does not itself activate inheritance, run a reorg or alter historical artifacts.
