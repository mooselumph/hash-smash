# HashSmash

HashSmash is a Yukon-compatible benchmark for AI-assisted review of cryptanalytic
collision claims. Each target has independent exploratory and rigorous lanes.
The roster has **28 planned slots: 24 locally runnable lanes and 4 reserved Poseidon
slots**. The Yukon manifest exposes **12 exploratory tracks**. Rigorous packages
and local review remain available, but are excluded from this import surface.
The organizer selected BLAKE3 rounds 1/2 and Keccak[800] rounds 5/6 on 2026-09-13.

Solvers start with [TASK.md](./TASK.md), the single entry point for assigned-track
instructions and HashSmash's differences from the generic Yukon CLI workflow.
Builders and deployment operators start with the
[builder guide](./docs/BUILDER_GUIDE.md); [AGENTS.md](./AGENTS.md) routes these roles.

The [paired-lane guide](./docs/FRONTIER_LANES.md) covers the roster, target
boundaries and deployment gates. The [review contract](./docs/JUDGE_LANES.md)
defines the two acceptance policies, and the
[experiment protocol](./docs/HEURISTIC_EXPERIMENTS.md) defines isolated executable
evidence. The [documentation index](./docs/README.md) covers operator guides,
research context and historical plans.

The exploratory outcome `plausible_not_refuted` means relevant support exists and
no fatal flaw survives adjudication. Rigorous qualification is `ai_rigor_qualified`.
Both are AI review outcomes, not mathematical proof or human acceptance. A score is
`log2(total charged computation)`, lower is better, under the
selected target and common cost model. Nominal references are neither established
attacks nor qualified baselines, and scalar improvement does not establish Pareto
dominance.

## Repository contract

A solver edits only its assigned `lanes/<lane>/candidates/<target>/` directory.
The package contains a strict JSON claim, a Markdown argument and declared
certificate or experiment files. Target profiles, cost models, schemas, judge
prompts, verifier code, workflows and outputs remain organizer-owned.

Drafts do not reach the judge or emit scores. A ready package must pass intake,
any declared experiments, and the selected lane's review policy before scoring.
Changed inputs require fresh evidence and review. Python experiments run only in
the organizer's bounded, networkless Docker executor; participant commands never
run on the host or in a credential-bearing job.

Scores are written to `lanes/<lane>/.yukon/scores/<target>-<lane>.json`, with
reports under `lanes/<lane>/.yukon/reports/tracks/<target>-<lane>/`. These generated
outputs are ignored by Git. Failed validation or qualification emits no score.

## Builder setup and local workflow

Run commands from the repository root. Deterministic tests use Python's standard
library and organizer fixtures, without contacting providers:

```sh
bash .yukon/setup.sh
python3 scripts/local_tracks.py list
python3 scripts/local_tracks.py catalog
python3 scripts/local_tracks.py check sha256-r31-exploratory
```

The pipeline requires an explicit organizer track ID, including the lane:

```sh
python3 scripts/hashsmash_pipeline.py intake --track sha256-r31-exploratory
```

After successful intake, a trusted operator can run `judge` and `score` with the
same `--track`. Follow the [candidate qualification guide](./docs/CANDIDATE_QUALIFICATION.md)
for the complete sequence and readiness requirements. Use
`bash scripts/run-local-track.sh sha256-r31-exploratory` for the local wrapper.

OpenRouter and Amazon Bedrock share the validated review interface. Provider,
model and committee configuration are documented in [judge/README.md](./judge/README.md).
Local wrappers load `OPENROUTER_API_KEY` or `AWS_BEARER_TOKEN_BEDROCK` from `.env`
without printing it; never commit or copy that file. The
[participant heuristic test](./docs/PARTICIPANT_HEURISTIC_TEST.md) exercises isolated
execution, numerical evidence, paired review and diagnostic scoring using
organizer fixtures outside the production registry.

## Yukon

The SHA-1 pilot and nine local tracks have been retired.

Follow [YUKON_DEV_SETUP.md](./docs/YUKON_DEV_SETUP.md) to import the repository root once
as `hashsmash`. The schema-v2 [`benchmark.json`](./benchmark.json) declares all
twelve exploratory tracks with unique names such as `sha256-r31-exploratory`
and `blake3-r1-exploratory`. There is no `rootDir` override or separate lane import.
Lane metadata remains in the protected registry, the validated claim binding,
and each generated score's `metrics.lane`. Yukon track names include the lane
suffix; its strict manifest schema has no arbitrary metadata field.

[CANDIDATE_QUALIFICATION.md](./docs/CANDIDATE_QUALIFICATION.md) describes organizer
baseline qualification. [TASK.md](./TASK.md) covers solver-specific rules and
delegates generic commands, notes and tracing to the Yukon CLI skill. Each
track keeps its own `lanes/<lane>/candidates/<target>` editable directory and
`lanes/<lane>/.yukon/scores/<target>-<lane>.json` score path. The literal per-track
workflow wrappers separate deterministic intake, secret-bearing review, and
final scoring. The score artifact contains that exact repository-relative path;
qualification failures withhold a score.

A fresh import queues twelve exploratory baseline workflows. To extend an existing
challenge, use Yukon’s import-new-tracks operation, documented in the
[operator runbook](./docs/YUKON_DEV_SETUP.md); it queues only newly declared tracks.
It does not delete existing rigorous records or open submissions. The manifest
stays below Yukon’s 20-track limit. The four undefined Poseidon slots remain deferred.

Before opening, test Yukon-driven validation, non-editable-path rejection, and
promotion while preserving sibling tracks in both lanes. Humans review harness
PRs; Yukon manages promotion of its own submission PRs. Public publication
additionally needs cryptanalytic calibration and human review decisions. Human
acceptance remains distinct from an AI review outcome.

See [`YUKON_CHALLENGE_PLAN.md`](./docs/archive/YUKON_CHALLENGE_PLAN.md) and
[`MVP_VALIDATION.md`](./docs/archive/MVP_VALIDATION.md) for the historical pilot design and
validation record. They do not define the current import contract.
