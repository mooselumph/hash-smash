# BLAKE3 and Keccak[800] lane preparation — 2026-09-13

The organizer selected BLAKE3 rounds 1/2 and Keccak[800] rounds 5/6. The root
manifest now contains 12 exploratory tracks. All 24 defined lanes remain locally
runnable; the 12 rigorous lanes are excluded from new imports. Poseidon is deferred.

## Verification

- The standard-library offline suite passed: 214 tests, with 5 opt-in integration
  tests skipped. Every local lane exercised the bound pipeline with organizer
  fixtures; every imported lane exercised score artifact staging.
- 67 BLAKE3 vectors passed, including the official full-round corpus and independent
  Rust-reference prefix vectors across block/chunk/tree boundaries.
- Existing XKCP Keccak[800] 5/6/full-round vectors and sponge-boundary tests passed.
- Every selected target's v5 reference price was reproduced. New prices C are
  222/430 for BLAKE3 1/2 and 1355/1626 for Keccak[800] 5/6.
- All eight new candidate packages passed mechanical intake. Their complete
  fixed-function probability proof claims success >= 1/2. The conservative time
  bound is 149; memory log2 bytes is 137. These are proposed analytical bounds,
  not measured attack results or emitted scores.
- Live Bedrock review has not run: automatic approval review requires explicit
  approval to send the four exploratory packages to that provider. No local
  qualifying verdict or trusted score is claimed. No Yukon import was submitted.

## Exploratory package bindings

| Track | Package SHA-256 | Mechanical status | Live review / score |
| --- | --- | --- | --- |
| `blake3-r1-exploratory` | `f344e2274d19fa431d2105e7ae5e13583f3201a73dd007fade061838f157e40b` | ready / valid | pending / none |
| `blake3-r2-exploratory` | `bc5f741d43c675493fa11123375f7e8bc7552b326bcb59b4cb5a3389fec8b8d8` | ready / valid | pending / none |
| `keccak800-r5-exploratory` | `623a76c91903ac292574caeb65500cfad4b15f8fdcdc32f161130cbe89145d11` | ready / valid | pending / none |
| `keccak800-r6-exploratory` | `6369be3cfd4436ac4610cb1c52300439619d7882e1c2a3d88468c77eebfa9b14` | ready / valid | pending / none |

Intake snapshots live in each track's ignored
`lanes/exploratory/.yukon/reports/tracks/<track>/runs/` directory. The exact
candidate and configuration fingerprints are retained in those reports. After
approval, review each frozen package using the configured Bedrock Sol committee
with high reasoning effort, then run its deterministic score phase. Preserve
all attempts and address substantive findings before regenerating evidence.

## Import and existing-score implications

Use the [append-import runbook](YUKON_DEV_SETUP.md#append-newly-declared-tracks-to-an-existing-challenge)
after merging the human-reviewed PR into the existing challenge's saved source
branch. Appending these four tracks to an existing 16-record deployment produces
20 saved records; omitted rigorous records are preserved by Yukon. The current
manifest itself contains 12 entries. An append does not open submissions.

The shared trusted checker/schema additions change configuration fingerprints.
The old cost-only replay plan is archived verbatim in
[reorg/history/pre-blake3-keccak800-plan.json](../reorg/history/pre-blake3-keccak800-plan.json);
the active plan is empty so future evaluations take full review. Existing stored
Yukon scores are untouched. The PR requires `yukon-unsafe` because pending scores
must not be promoted across this harness change. Do not invoke a whole-challenge
reorg while saved rigorous records are absent from the manifest.
