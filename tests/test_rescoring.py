"""Cost-only migration boundaries, using organizer fixtures and fake judges."""

from copy import deepcopy
import json
import math
import shutil
import unittest
from unittest.mock import patch

from judge import rescore
from judge.provider_adapter import ReviewResult
from scripts.archive_review import archive
from scripts.reference_operation_costs import reference_costs
from scripts import hashsmash_pipeline as pipeline
from scripts import rescore_artifacts
from tests import test_frontier_pipeline as fixtures
from tests.test_frontier_pipeline import fake_provider, read_json
from verifier.errors import VerificationError
from verifier.frontier_tracks import LaneTrack, ROOT, frontier_tracks
from verifier.io import atomic_write_json
from verifier.resources import UNIT_WEIGHTS, legacy_ledger, price_ledger
from verifier.schema_validation import validate_claim


def component(name, operation, count, *, basis=None, status="supported"):
    return {"id": name, "phase": "all trials", "operation": operation, "count_log2": count,
            "bound_kind": "upper_bound", "status": status, "source_weights": basis,
            "evidence": ["proof.md:L1-L2"], "assumptions": []}


def ledger(probability=0.39):
    return {"schema_version": "resource-ledger-v1", "success_probability": probability,
            "coverage": "Complete organizer fixture computation.",
            "components": [component("hashes", "target_compression", 20),
                           component("overhead", "word_operation", 30)]}


class CostClient:
    def __init__(self, resource_ledger=None, mutate=None):
        self.calls, self.ledger, self.mutate = [], resource_ledger, mutate

    def review(self, stage, evidence):
        self.calls.append((stage, deepcopy(evidence)))
        review = {"schema_version": "review-rescore-v1", "stage": stage,
                  "binding": evidence["review_context"]["binding"], "status": "complete",
                  "resource_ledger": self.ledger or evidence["review_context"]["fallback_ledger"],
                  "calculation_trace": ["Reprice the same organizer fixture bounds."]}
        if self.mutate:
            self.mutate(review)
        return ReviewResult(review, {"provider": "offline-organizer-fixture"})


class RescoringTests(unittest.TestCase):
    setUp = fixtures.FrontierPipelineTests.setUp
    paths = fixtures.FrontierPipelineTests.paths

    def source(self, *, rigorous=False):
        lane = "rigorous" if rigorous else "exploratory"
        paths = self.paths("sha256-r31-" + lane)
        old = paths.track.benchmark()
        old["cost_model"] = read_json(ROOT / "cost-models/collision-frontier-v4.json")
        with patch.object(LaneTrack, "benchmark", return_value=old), fake_provider():
            self.assertEqual(pipeline.run_all(paths), 0)
        self.archives = paths.rescore_archives
        self.plan = self.root / "plan.json"
        self.enterContext(patch.object(rescore, "ARCHIVES", self.archives))
        self.enterContext(patch.object(rescore, "PLAN", self.plan))
        entry = archive(paths.evidence, paths.dossier, self.archives)
        atomic_write_json(self.plan, {"entries": [entry]})
        return paths, entry

    def run_cost(self, paths, client):
        with fake_provider(factory=lambda _: client), \
                patch.object(pipeline, "execute_experiments", side_effect=AssertionError("must inherit experiments")):
            self.assertEqual(pipeline.run_all(paths), 0)

    def review_artifact(self, paths, name):
        downloaded = self.root / name
        evidence = downloaded / "runs/fixture/judge-evidence.json"
        evidence.parent.mkdir(parents=True)
        shutil.copyfile(paths.evidence, evidence)
        shutil.copyfile(paths.dossier, downloaded / "judge-dossier.json")
        if paths.rescore_history.exists():
            shutil.copyfile(paths.rescore_history, downloaded / "rescore-history.json")
        return downloaded

    def test_workflow_artifact_carries_history_after_original_expires(self):
        paths, entry = self.source()
        original = self.review_artifact(paths, "original")
        shutil.rmtree(self.archives)
        rescore_artifacts.restore(paths, original)
        self.run_cost(paths, CostClient(ledger()))
        self.assertEqual(set(read_json(paths.rescore_history)), {entry["source"]})
        second = archive(paths.evidence, paths.dossier, self.archives)
        latest = self.review_artifact(paths, "latest")
        shutil.rmtree(original)
        shutil.rmtree(self.archives)
        repinned = archive(latest / "runs/fixture/judge-evidence.json", latest / "judge-dossier.json",
                           self.root / "operator-cache")
        self.assertEqual(repinned, second)
        atomic_write_json(self.plan, {"entries": [second]})
        rescore_artifacts.restore(paths, latest)
        self.assertEqual({p.stem for p in self.archives.glob("*.json")}, {entry["source"], second["source"]})
        client = CostClient(ledger())
        self.run_cost(paths, client)
        self.assertEqual([stage for stage, _ in client.calls], ["lane_rescore"])
        self.assertEqual(len(client.calls[0][1]["review_context"]["cost_history"]), 1)
        self.assertEqual(set(read_json(paths.rescore_history)), {entry["source"], second["source"]})

    def test_missing_or_changed_workflow_artifact_fails_before_review(self):
        paths, entry = self.source()
        downloaded = self.review_artifact(paths, "downloaded")
        shutil.rmtree(self.archives)
        with self.assertRaisesRegex(VerificationError, "missing prior judgment"):
            pipeline.run_intake(paths)
        with self.assertRaisesRegex(VerificationError, "missing or oversized"):
            rescore_artifacts.restore(paths, self.root / "expired")
        evidence = downloaded / "runs/fixture/judge-evidence.json"
        changed = read_json(evidence)
        changed["submission"]["proof_markdown_line_numbered"] += "tampered"
        atomic_write_json(evidence, changed)
        with self.assertRaisesRegex(VerificationError, "pinned packet checksum"):
            rescore_artifacts.restore(paths, downloaded)
        self.assertFalse(self.archives.exists())

    def test_latest_artifact_requires_its_complete_untampered_history(self):
        paths, _ = self.source()
        self.run_cost(paths, CostClient(ledger()))
        second = archive(paths.evidence, paths.dossier, self.archives)
        downloaded = self.review_artifact(paths, "downloaded")
        atomic_write_json(self.plan, {"entries": [second]})
        shutil.rmtree(self.archives)
        history_file = downloaded / "rescore-history.json"
        history = read_json(history_file)
        history_file.unlink()
        with self.assertRaisesRegex(VerificationError, "missing prior judgment"):
            rescore_artifacts.restore(paths, downloaded)
        next(iter(history.values()))["evidence"]["schema_version"] = "tampered"
        atomic_write_json(history_file, history)
        with self.assertRaisesRegex(VerificationError, "history checksum"):
            rescore_artifacts.restore(paths, downloaded)
        self.assertFalse(self.archives.exists())

    def test_only_pinned_packages_select_positive_immutable_artifact_ids(self):
        paths, entry = self.source()
        references = self.root / "artifacts.json"
        with patch.object(rescore_artifacts, "ARTIFACTS", references):
            atomic_write_json(references, {entry["source"]: {"run_id": 42, "artifact_id": 73}})
            self.assertEqual(rescore_artifacts.selection(paths), entry)
            self.assertEqual(rescore_artifacts.artifact_reference(entry), {"run_id": 42, "artifact_id": 73})
            for bad in ({}, {entry["source"]: {"run_id": 42, "artifact_id": "73\n"}},
                        {entry["source"]: {"run_id": 42, "artifact_id": True}}):
                atomic_write_json(references, bad)
                with self.assertRaises(VerificationError):
                    rescore_artifacts.artifact_reference(entry)
            atomic_write_json(self.plan, {"entries": []})
            references.unlink()
            self.assertIsNone(rescore_artifacts.selection(paths))

    def test_migration_preserves_anchor_and_only_calls_cost_judge(self):
        paths, entry = self.source()
        anchor = rescore.load_archive(entry["source"])
        client = CostClient(ledger())
        self.run_cost(paths, client)
        self.assertEqual([stage for stage, _ in client.calls], ["lane_rescore"])
        supplied = client.calls[0][1]["review_context"]
        self.assertEqual(supplied["qualification_anchor"], anchor)
        self.assertEqual(supplied["cost_history"], [])
        result = read_json(paths.score)
        expected = math.log2(2**20 + 2**30 / 2140)
        self.assertAlmostEqual(result["score"], expected)
        self.assertEqual(result["metrics"]["declaredTimeLog2"], 128)
        self.assertEqual(result["metrics"]["declaredOperationWeights"], UNIT_WEIGHTS)
        self.assertNotIn("preprocessingLog2", result["metrics"])
        self.assertEqual(result["metrics"]["declaredPreprocessingLog2"], 0)
        self.assertEqual(result["metrics"]["rescoreSourceSha256"], entry["source"])
        self.assertEqual(read_json(paths.dossier)["lanes"], anchor["dossier"]["lanes"])
        self.assertEqual(result["metrics"]["resourceLedger"], ledger())

    def test_repeated_reorgs_reuse_counts_and_retain_history(self):
        paths, entry = self.source()
        self.run_cost(paths, CostClient(ledger()))
        entry2 = archive(paths.evidence, paths.dossier, self.archives)
        updated = paths.track.benchmark()
        updated["cost_model"]["reference_operation_costs"]["sha256-r31"] = 1070
        updated["cost_model"]["operation_weights"]["word_operation"] = 1 / 1070
        with patch.object(LaneTrack, "benchmark", return_value=updated):
            entry2["destination_config_sha256"] = paths.track.config_sha256()
            atomic_write_json(self.plan, {"entries": [entry2]})
            client = CostClient(ledger())
            self.run_cost(paths, client)
            supplied = client.calls[0][1]["review_context"]
            self.assertEqual(rescore.digest(supplied["qualification_anchor"]), entry["source"])
            self.assertEqual(len(supplied["cost_history"]), 1)
            self.assertEqual(supplied["cost_history"][0]["review"]["resource_ledger"], ledger())
            self.assertAlmostEqual(read_json(paths.score)["score"], math.log2(2**20 + 2**30 / 1070))
        updated["qualification_policy"]["sha256"] = "e" * 64
        with patch.object(LaneTrack, "benchmark", return_value=updated):
            entry2["destination_config_sha256"] = paths.track.config_sha256()
            atomic_write_json(self.plan, {"entries": [entry2]})
            with self.assertRaisesRegex(VerificationError, "cannot change qualification"):
                pipeline.run_intake(paths)

    def test_opaque_legacy_bound_survives_discount_without_fabricated_counts(self):
        paths, _ = self.source()
        self.run_cost(paths, CostClient())
        result = read_json(paths.score)
        self.assertEqual(result["score"], 128)
        self.assertEqual(result["metrics"]["resourceLedger"]["components"][0]["source_weights"], UNIT_WEIGHTS)
        opaque = legacy_ledger(read_json(paths.candidate / "claim.json"),
                               {"target_compression": 1, "word_operation": 1 / 512}, rigorous=False)
        self.assertEqual(price_ledger(opaque, {"target_compression": 1, "word_operation": 1 / 256}), 129)

    def test_stale_pin_and_nonpricing_semantic_change_fail_before_model_call(self):
        paths, entry = self.source()
        changed = paths.track.benchmark()
        changed["cost_model"]["minimum_success_probability"] = 0.2
        with patch.object(LaneTrack, "benchmark", return_value=changed):
            with self.assertRaisesRegex(VerificationError, "current configuration"):
                pipeline.run_intake(paths)
            entry["destination_config_sha256"] = paths.track.config_sha256()
            atomic_write_json(self.plan, {"entries": [entry]})
            with self.assertRaisesRegex(VerificationError, "more than operation weights"):
                pipeline.run_intake(paths)

    def test_archive_tampering_and_duplicate_pins_are_rejected(self):
        paths, entry = self.source()
        archive_path = self.archives / (entry["source"] + ".json")
        packet = read_json(archive_path)
        packet["dossier"]["claim"]["claim"]["success_probability"] = 1
        atomic_write_json(archive_path, packet)
        with self.assertRaisesRegex(VerificationError, "checksum mismatch"):
            pipeline.run_intake(paths)
        atomic_write_json(self.plan, {"entries": [entry, entry]})
        with self.assertRaisesRegex(VerificationError, "duplicate"):
            pipeline.run_intake(paths)

    def test_failed_anchor_cannot_be_used_for_inheritance(self):
        paths, entry = self.source()
        packet = rescore.load_archive(entry["source"])
        packet["dossier"]["lanes"]["exploratory"]["eligible"] = False
        # Even resealing an inconsistent decision cannot pass deterministic checks.
        with self.assertRaises(VerificationError):
            rescore.verify_packet(packet)

    def test_incomplete_cost_review_retains_qualification_and_emits_no_score(self):
        paths, entry = self.source()
        anchor = rescore.load_archive(entry["source"])
        client = CostClient(mutate=lambda review: review.update(status="needs_evidence", resource_ledger=None))
        with fake_provider(factory=lambda _: client):
            self.assertEqual(pipeline.run_all(paths), 2)
        self.assertFalse(paths.score.exists())
        self.assertEqual(read_json(paths.aggregate)["status"], "rescore_needs_evidence")
        self.assertEqual(read_json(paths.dossier)["review"]["status"], "needs_evidence")
        self.assertEqual(rescore.load_archive(entry["source"]), anchor)

    def test_new_success_probability_and_uncertain_rigorous_costs_fail_closed(self):
        paths, _ = self.source(rigorous=True)
        self.assertEqual(pipeline.run_intake(paths), 0)
        evidence = read_json(paths.evidence)
        for mutation in (lambda r: r["resource_ledger"].update(success_probability=1),
                         lambda r: r["resource_ledger"]["components"][0].update(status="conditional")):
            client = CostClient(ledger(), mutation)
            with self.assertRaises(VerificationError):
                rescore.run_review(evidence, rescore.find_source(paths.track, evidence["submission"]["intake_report"]["package_sha256"]), client)

    def test_solver_ledger_is_optional_but_validated_and_never_a_score_override(self):
        paths = self.paths()
        claim = read_json(paths.candidate / "claim.json")
        validate_claim(claim, track=paths.track)
        claim["resource_ledger"] = ledger()
        atomic_write_json(paths.candidate / "claim.json", claim)
        with fake_provider():
            self.assertEqual(pipeline.run_all(paths), 0)
        self.assertEqual(read_json(paths.score)["score"], 128)
        claim["resource_ledger"]["components"][0]["count_log2"] = float("inf")
        with self.assertRaises(VerificationError):
            validate_claim(claim, track=paths.track)

    def test_projection_rejects_estimates_duplicates_and_bad_bases(self):
        for mutate in (
            lambda x: x["components"][0].update(bound_kind="estimate"),
            lambda x: x["components"][0].update(status="unresolved"),
            lambda x: x["components"][1].update(id="hashes"),
            lambda x: x["components"][0].update(source_weights=UNIT_WEIGHTS),
            lambda x: x["components"][0].update(operation="opaque", source_weights=None),
        ):
            value = ledger()
            mutate(value)
            with self.assertRaises(VerificationError):
                price_ledger(value, UNIT_WEIGHTS)

    def test_every_active_target_has_a_reproducible_price(self):
        estimates = reference_costs()
        self.assertEqual(estimates, read_json(ROOT / "cost-models/collision-frontier-v5.json")["reference_operation_costs"])
        for track in frontier_tracks():
            weights = track.benchmark()["cost_model"]["operation_weights"]
            self.assertEqual(weights["target_compression"], 1)
            self.assertEqual(weights["word_operation"], 1 / estimates[track.target_id])

    def test_provider_boundaries_support_cost_only_reviews_and_reject_bad_ledgers(self):
        from judge.tests import test_provider_adapter as openrouter, test_bedrock_adapter as bedrock
        from judge.tests.helpers import provider_response
        from judge.provider_adapter import JudgeInfraError, _schema_for_stage
        from judge.tests.helpers import fixture_evidence
        evidence = {"review_context": {"binding": rescore.evidence_binding(fixture_evidence())}}
        record = CostClient(ledger()).review("lane_rescore", evidence).review
        schema = _schema_for_stage("lane_rescore")
        self.assertNotIn("$ref", json.dumps(schema))
        for make_client, response in ((openrouter.client, provider_response),
                                      (bedrock.client, bedrock.bedrock_response),
                                      (bedrock.sol_client, bedrock.sol_response)):
            transport = openrouter.FakeTransport([response(record)])
            result = make_client(transport).review("lane_rescore", evidence)
            self.assertEqual(result.review, record)
            body = json.loads(transport.calls[0]["body"])
            self.assertNotIn("tools", body)
            self.assertIn("qualification_anchor", json.dumps(body))
            bad = deepcopy(record)
            bad["resource_ledger"]["components"][0]["count_log2"] = -1
            with self.assertRaises(JudgeInfraError):
                make_client(openrouter.FakeTransport([response(bad)] * 3)).review("lane_rescore", evidence)
