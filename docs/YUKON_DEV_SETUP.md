# HashSmash Yukon dev setup

This operator runbook is reached through the [builder guide](./BUILDER_GUIDE.md).
It applies the reusable Yukon setup instructions to HashSmash's paired research
candidates. There is
one schema-v2 challenge imported from the repository root. Its manifest exposes twelve exploratory tracks. Rigorous packages remain
locally runnable, outside the import manifest; do not create a second import root.

## Contract and current scope

| Contract | Value |
| --- | --- |
| Challenge manifest name | `hashsmash` |
| Manifest / import root | Repository-root `benchmark.json`; omit `rootDir` |
| Schema / imported tracks | 2 / 12 exploratory (24 local lanes total) |
| Promotion mode | `manual` on every track; owner review before promotion |
| Yukon and organizer track ID | `<target>-<lane>`, such as `sha1-r80-rigorous` |
| Required exploratory / rigorous outcome | `plausible_not_refuted` / `ai_rigor_qualified` |
| Editable path, relative to repository root | `lanes/<lane>/candidates/<target>` |
| Score path, relative to repository root | `lanes/<lane>/.yukon/scores/<target>-<lane>.json` |

The protected registry records the lane, claim validation binds each package to
it, and successful scores include `metrics.lane`. Track names and descriptions
also identify the lane. Yukon's strict manifest schema does not accept an arbitrary
`metadata` field; do not add one. Lane directories remain isolated storage for
candidates and generated state, and no longer contain import manifests.

Each track has a literal `<target>-<lane>.yml` workflow. All workflows check out
the dispatched commit and run on GitHub-hosted `ubuntu-24.04`. The submission cap
is 4,194,304 expanded bytes per track. Lower `time_log2` wins.
The target, cost, and acceptance definitions remain in `docs/FRONTIER_LANES.md`,
`docs/JUDGE_LANES.md`, and their linked trusted profiles; this runbook does not change
them. MD5/SHA-1 endpoints are explicitly controls.

For the v3-to-v4 scoring migration, follow the
[total-computation reorg plan](./TIME_ONLY_REORG.md), including the UI compatibility
gate and candidate-only baseline restoration before replay.

BLAKE3 rounds1/2 and Keccak[800] rounds5/6 are now concrete organizer-selected
exploration targets. The four pending Poseidon slots remain excluded. Twelve
exploratory entries fit Yukon's 20-track manifest limit; including all 24 local
lanes would exceed it.
Do not manufacture boundaries or scores to make `--require-complete` pass.

HashSmash needs neither Willow's M3 Max runner group and JIT App nor its Rust
toolchain, Seatbelt bridge, private leaf tarball, or wall-time attack score.
`.yukon/setup.sh` and the Python pipeline are the operator entry points already
declared in the root manifest. Do not rename them to match another challenge.

## GitHub and provider access

The operator repository is the public `mooselumph/hash-smash` repository.
After its initial publication, use feature branches and human-reviewed harness
PRs; do not push harness changes directly to `main`.

Install or configure the [Yukon dev App](https://github.com/apps/yukon-eigen/installations/new)
for `mooselumph/hash-smash`. Its execution access includes contents write, Actions
read/write, and pull requests write. Verify the selected repository and any pending
permission approval in GitHub's repository/organization GitHub Apps settings.
`GET /repos/mooselumph/hash-smash/installation` requires an App JWT; an ordinary
`gh` login's JWT/401 error is not evidence that the App is absent. A successful
Yukon-driven baseline run verifies the service's actual access. A direct
`gh workflow run` only verifies that user's Actions access.

Configure this repository with Actions secret `AWS_BEARER_TOKEN_BEDROCK` and variables
`HASHSMASH_JUDGE_PROVIDER=bedrock`,
`HASHSMASH_BEDROCK_MODEL=us.openai.gpt-5.6-sol`, and
`HASHSMASH_BEDROCK_REGION=us-east-1`. The paired workflow selects committee mode
and high reasoning effort. Only the judge step receives the provider key;
experiments and final scoring run in separate jobs. Check these settings before
the official run; do not commit or print keys or `.env`.

Solvers can clone this public repository without a GitHub repository invitation.
They still authenticate to Yukon for submissions. For research threads, enable
Discussions and create an Announcement-format category named exactly
`Research Notes`; the dev App needs approved Discussions read/write access.

## Real baseline readiness

Follow [CANDIDATE_QUALIFICATION.md](./CANDIDATE_QUALIFICATION.md). Every imported
track needs a substantive `ready` package and a qualifying review/score under
that lane's policy. Complete the offline suite before live provider review.
Neither draft values, nominal reference scores, nor local calibration scores
are research baselines. An exploratory pass does not qualify a rigorous lane.

Before importing, merge the intended candidate and harness PRs, use a clean
checkout of that source branch, and obtain trusted workflow results on the exact
content. Changes to a package require fresh evidence/review. The importer helper's
local readiness check is not a remote-branch attestation or a proof of qualification;
Yukon dispatches baseline validation against the source it actually resolves.

The [local participant heuristic test](./PARTICIPANT_HEURISTIC_TEST.md) can help
diagnose the harness, but it is outside the production registry and cannot seed
this challenge. A draft rejection is an expected negative test, not a successful
end-to-end baseline.

## Import through Yukon dev

Confirm that the dev deployment supports schema v2 and that the importing account's
**email** is in `YUKON_BENCHMARK_IMPORTER_EMAILS`. Before replacing an existing
deployment, let active submissions finish and close/archive the prior challenge in
the setter UI. This new repository requires its own import; an import from another
repository URL does not move with a code copy. Yukon does not allow concurrent open
challenges for the same source repository. Record the new benchmark IDs and update
solver clone instructions after the fresh import.

Create the account's importer key in the dev setter UI's API keys view. Keep the key in a
private file outside this repository (`chmod 600`), or supply `YUKON_API_KEY` in
the calling process environment. Never paste it into notes or commit it.

Inspect the one import request without credentials or network access:

```sh
python3 scripts/import_yukon_dev.py --source-branch main
```

The request uses the fixed `https://api-dev.yukon.org` API, repository
`https://github.com/mooselumph/hash-smash`, and source branch `main`. It omits
`rootDir`, so Yukon reads the twelve-track exploratory schema-v2 manifest at the repository
root. The helper sends the supported `POST /api/benchmarks` JSON body directly.
If using the setter UI instead, choose the same repository and branch, leave its
root-directory field empty, and use the challenge name `hashsmash`.

Submitting a fresh import queues twelve exploratory baseline workflows against
the resolved source commit. Each imported baseline must qualify. For an existing
challenge, use the append operation below rather than recreating it.

After baseline readiness and credential setup, run the real import:

```sh
python3 scripts/import_yukon_dev.py --source-branch main --submit --wait
```

That command uses `YUKON_API_KEY`/`YUKON_API_TOKEN`; alternatively add
`--api-key-file /absolute/path/to/private-key-file`. The helper does not load
`.env`, print the key, follow redirects, or retry an uncertain import request.
It refuses imports while local candidates are drafts. `--source-branch` selects
an explicitly intended existing branch; do not create a parallel ranked branch
per track. If a setter slug has been agreed, `--name setter/challenge` can set it;
otherwise record the actual name returned by Yukon rather than guessing that
the GitHub organization equals the setter namespace.

There is deliberately no production or opening option. Successful baselines
remain `ready`, with submissions unopened. The helper reports track IDs and job
URLs; `--wait` reports transitions and returns nonzero on failed baselines or a
wait timeout. A timeout does not cancel or recreate the import. Inspect the saved
IDs in dev before retrying after a network error or interruption. To retry a failed
baseline, archive/delete that failed import in the setter UI, fix the actual
cause, and import again; never delete/recreate the GitHub repository.

## Append newly declared tracks to an existing challenge

Yukon's `POST /api/benchmarks/:id/import-tracks` reads the challenge's saved
repository, branch and root, and appends only newly declared schema-v2 tracks.
It preserves already imported records and queues independent baseline jobs for
the additions. It takes no per-track filter and does not delete tracks omitted
from the current manifest. Existing rigorous records therefore remain in Yukon;
this manifest change does not close or archive them.

After the human-reviewed source change is merged into the saved source branch,
inspect an offline plan using the actual existing challenge reference:

```sh
python3 scripts/import_yukon_dev.py --append-to SETTER/CHALLENGE
```

Replace the uppercase placeholder with the confirmed lowercase setter/challenge
name or an existing benchmark UUID. The helper checks only the twelve manifest
candidates; local-only rigorous packages do not block importing exploratory lanes.
The plan's workflow count is null because the server determines which tracks
are new. To send the reviewed request and wait for those jobs, add `--submit --wait`.
The append request uses the saved source; `--source-branch` and `--name` overrides
are not supported. It never opens submissions. An empty returned track list means
there were no additions; do not retry an uncertain mutation without inspecting Yukon.

The endpoint was verified against Yukon’s GitHub default branch on 2026-09-13. A fresh import
contains twelve tracks. Appending these four exploratory targets to an existing
sixteen-track deployment leaves twenty saved records, including its old rigorous
tracks. Avoid a whole-challenge reorg while saved records are absent from the
manifest; use the append operation for these additions.

## Yukon verification before opening

For each track, record the source commit, Yukon baseline job ID, GitHub workflow
run URL, App actor, exact score ZIP entry, review label and scalar. The score ZIP
must contain the repository-relative `scorePath`, not only its basename. The workflows
stage only the validated selected score under a fresh artifact root; hidden-file
upload preserves `.yukon`. Failure must leave no successful score artifact.

After every required baseline qualifies, the organizer can explicitly open the
dev challenge and direct solvers to [TASK.md](../TASK.md). Generic UI instructions
need only reference that file for all HashSmash-specific requirements and deviations.

Suggested UI wording:

> Before running evaluations or editing files, read the repository-root TASK.md.
> Follow its linked instructions and apply its challenge-specific exceptions to
> the generic Yukon workflow.

Test a legitimate improving candidate change and a non-editable-path rejection
through Yukon. The improving submission must enter `review` without merging or
changing the promoted best. After the owner inspects and accepts that exact
candidate SHA through the review API below, verify promotion. Confirm that it
preserves all sibling tracks, including the other lane's candidates, and the
harness. Save the before/after commit and path hashes; local surface-check tests
alone do not establish this platform result.

Humans review and merge harness PRs. Humans must **not** merge Yukon submission
PRs; Yukon promotes the content it scored. Use the `yukon-unsafe` label on harness
PRs that invalidate pending scores, so Yukon blocks promotion of stale scored
submissions after that PR merges. Avoid the label for unrelated safe documentation
changes. Changing the label, workflow, or score packaging does not authorize
changing scientific acceptance thresholds.

## Convert an existing registration to manual review

The root manifest sets `"promotionMode": "manual"` on all twelve imported track entries.
Yukon defaults omitted modes to `automatic`; editing this file alone does not
change existing registrations. Follow the released
[manual submission review contract](https://github.com/Layr-Labs/yukon/blob/v2026.09.10-1/docs/manual-submission-review.md).
Confirm the API, worker, and promotion workflow all support that release before
starting. The deployed `/doc.json` must expose `promotionMode` on benchmark PATCH
and `POST /api/submissions/{id}/review`.

Use the registered repository, source branch, challenge, and track IDs from the
owner API. Do not assume the GitHub namespace is the Yukon setter namespace. For
each existing track benchmark that needs the setting, authenticated as its owner:

1. Record its ID, source reference, baseline, promoted best, and submission history.
   Pause new submissions with `POST /api/benchmarks/:id/pause`.
2. Let queued/running validation and promotion jobs finish. Inspect submission
   status and promotion status as well as Actions; the public benchmark jobs
   endpoint lists baseline jobs only. Resolve any pending manual reviews before
   another configuration edit.
3. Land the manifest and its generator update through a human-reviewed harness PR.
4. Send `PATCH /api/benchmarks/:id` with JSON `{"promotionMode":"manual"}`.
   Read back every track and verify its mode, ID, baseline, and promoted best.
5. Resume the previously open tracks with `POST /api/benchmarks/:id/resume`.
6. Use a legitimate improvement to verify `review`, no queued promotion, an
   unmerged candidate PR, and an unchanged promoted best. Do not invent an improved
   resource claim merely to test the lifecycle.

Changing promotion mode preserves the registration and history. It needs no new
import, repository, App installation, or baseline rerun. If a mutation's response
is uncertain, read the current state before retrying. Record the actual conversion
and verification results separately; a manifest declaration is not evidence that
an existing deployment has been converted.

## Owner decisions

Inspect the submission's recorded candidate commit, lane review, evidence, and
numeric score. Send the decision as the benchmark owner to
`POST /api/submissions/:id/review` with `Content-Type: application/json` and a bearer
credential kept out of logs and notes:

```json
{
  "decision": "accept",
  "expectedCommitSha": "<full inspected candidate commit SHA>"
}
```

Use `"decision": "reject"` to reject, optionally adding a public `reason`.
Acceptance queues promotion only if the score still meets the improvement
threshold. Check `promotionStatus` afterward: acceptance alone does not establish
publication. A changed candidate SHA or a target branch that moved since validation
requires revalidation and a new review; manually approved candidates are not
rebased. GitHub merge/close actions alone do not update Yukon's review state.

Manual mode adds an owner decision after the existing lane qualification. It
does not admit every passing result, support scoreless acceptance, or replace
HashSmash's scientific policy. The existing score metrics describe the AI review;
do not rewrite historical `humanAccepted` or other score fields to represent a
later Yukon decision. Leaderboards and solver sync continue to use promoted results.
