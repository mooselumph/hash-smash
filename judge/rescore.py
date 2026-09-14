"""Organizer-pinned, cost-only reviews with immutable qualification ancestry."""

from copy import deepcopy
import json
from pathlib import Path

from verifier.errors import VerificationError
from verifier.io import canonical_json_bytes, load_json_bytes, sha256_bytes
from verifier.resources import UNIT_WEIGHTS, ledger_schema, price_ledger, validate_ledger, validate_weights
from verifier.schema_validation import require_sha256
from .paired_review import aggregate_paired_reviews, evidence_binding, select_lane_aggregate
from .schema_validation import _validate

ROOT = Path(__file__).resolve().parents[1]
ARCHIVES = ROOT / ".yukon/work/rescore-archives"
PLAN = ROOT / "reorg/plan.json"


class RescoreNeedsEvidence(VerificationError):
    def __init__(self, result):
        super().__init__("cost-only review needs further evidence")
        self.result = result


def digest(value):
    return sha256_bytes(canonical_json_bytes(value))


def review_schema(*, legacy=False):
    version = "v1" if legacy else "v2"
    schema = json.loads((ROOT / f"schemas/review-rescore-{version}.schema.json").read_text())
    paired = json.loads((ROOT / "schemas/review-lanes-v1.schema.json").read_text())
    schema["properties"]["binding"] = paired["properties"]["binding"]
    if legacy:
        schema["properties"]["resource_ledger"] = {**ledger_schema(), "type": ["object", "null"]}
    return schema


def validate_review(review):
    legacy = isinstance(review, dict) and review.get("schema_version") == "review-rescore-v1"
    _validate(review, review_schema(legacy=legacy), "$")
    for key, value in review["binding"].items():
        require_sha256(value, "binding." + key)
    if legacy and review["status"] == "complete":
        validate_ledger(review["resource_ledger"])
    value = review["resource_ledger"] if legacy else review["time_log2"]
    if review["status"] == "complete" and value is None:
        raise VerificationError("a complete rescore needs a computation bound")
    if review["status"] != "complete" and value is not None:
        raise VerificationError("an incomplete rescore cannot supply a score")
    return review


def weights(evidence):
    return validate_weights(evidence["benchmark"]["cost_model"].get("operation_weights", dict(UNIT_WEIGHTS)))


def scoring_policy(evidence):
    """Accounting version and effective prices, independent of judge/checker hashes.

    Organizers must change the public model ID for a change in accounting rules.
    Prices may change within that version. Other targets' reference costs and
    explanatory edits do not change this submission's scoring policy.
    """
    model = evidence["benchmark"]["cost_model"]
    return {"id": model["id"], "operation_weights": weights(evidence)}


def accepted_score(packet):
    """Read the latest accepted bound; ledgers are only a legacy archive format."""
    review = packet["dossier"].get("rescore", {}).get("review")
    if review is None:
        return float(packet["dossier"]["claim"]["claim"]["time_log2"])
    return check_cost_review(review, packet["evidence"])


def find_source(track, package_sha256):
    """Only protected organizer configuration can select an inherited review."""
    if not PLAN.exists():
        return None
    plan = load_json_bytes(PLAN.read_bytes(), str(PLAN))
    if not isinstance(plan, dict) or set(plan) != {"entries"} or not isinstance(plan["entries"], list):
        raise VerificationError("rescore plan must contain entries")
    selected, seen = None, set()
    for entry in plan["entries"]:
        if not isinstance(entry, dict) or set(entry) != {
            "track_id", "package_sha256", "source", "source_config_sha256", "destination_config_sha256",
        }:
            raise VerificationError("invalid rescore plan entry")
        for key in ("package_sha256", "source", "source_config_sha256", "destination_config_sha256"):
            require_sha256(entry[key], "rescore." + key)
        key = (entry["track_id"], entry["package_sha256"])
        if key in seen:
            raise VerificationError("duplicate rescore plan entry")
        seen.add(key)
        if key == (track.id, package_sha256):
            if entry["destination_config_sha256"] != track.config_sha256():
                raise VerificationError("rescore plan does not authorize the current configuration")
            selected = entry
    return selected


def load_archive(source, archive_root=None):
    require_sha256(source, "rescore.source")
    root = ARCHIVES if archive_root is None else archive_root
    path = root / (source + ".json")
    if not path.exists():
        raise VerificationError("missing prior judgment; restore its pinned workflow artifact before rescoring")
    if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise VerificationError("invalid rescore archive file")
    packet = load_json_bytes(path.read_bytes(), str(path))
    if not isinstance(packet, dict) or set(packet) != {"evidence", "dossier"} or digest(packet) != source:
        raise VerificationError("rescore archive checksum mismatch")
    return packet


def history_packets(source, archive_root=None):
    """Retain exactly the verified ancestry needed by the next workflow run."""
    packet = load_archive(source, archive_root)
    verify_packet(packet, archive_root)
    packets = {}
    while True:
        packets[source] = packet
        if "rescore" not in packet["dossier"]:
            return packets
        source = packet["evidence"]["rescore_source"]
        packet = load_archive(source, archive_root)


def _transition(current, previous, authorization, *, legacy=False):
    a, b = current["submission"]["intake_report"], previous["submission"]["intake_report"]
    expected = {
        "track_id": current["benchmark"]["track_id"], "package_sha256": a["package_sha256"],
        "source": current["rescore_source"], "source_config_sha256": b["target_config_sha256"],
        "destination_config_sha256": a["target_config_sha256"],
    }
    if authorization != expected or a["claim"] != b["claim"] or a["package_sha256"] != b["package_sha256"]:
        raise VerificationError("cost-only transition is not authorized for this exact submission")
    # Configuration pins explicitly authorize the initial accounting-code migration.
    # Independently reject changes to the mathematical target and work semantics.
    for key in ("track_id", "lane", "target_id", "target_profile", "selection", "frontier"):
        if current["benchmark"][key] != previous["benchmark"][key]:
            raise VerificationError("cost-only transition changed the target or lane")
    for key in ("id", "lane", "pass_status"):
        if current["benchmark"]["qualification_policy"][key] != previous["benchmark"]["qualification_policy"][key]:
            raise VerificationError("cost-only transition changed qualification policy")
    if not legacy:
        # Exact organizer pins authorize the reorg. The judge receives both
        # configurations and reuses prior reasoning only where still applicable.
        weights(current)
        weights(previous)
        # The ID is the public accounting version. Editing substantive rules
        # without changing that version must not silently look like no change.
        old_model = previous["benchmark"]["cost_model"]
        new_model = current["benchmark"]["cost_model"]
        if old_model["id"] == new_model["id"]:
            for field in ("score", "time_unit", "minimum_success_probability", "primitive_operations",
                          "total_time_includes", "probability_space", "memory_scoring", "parallel_computation"):
                if old_model.get(field) != new_model.get(field):
                    raise VerificationError("changed accounting rules require a new public cost-model ID")
        return
    # v4 -> v5 introduces prices; later v5 reorgs may change those prices only.
    old_cost, new_cost = deepcopy(previous["benchmark"]["cost_model"]), deepcopy(current["benchmark"]["cost_model"])
    if old_cost.get("id") not in {"collision-frontier-v4", "collision-frontier-v5"} or new_cost.get("id") != "collision-frontier-v5":
        raise VerificationError("unsupported cost-only model transition")
    if old_cost["id"] == new_cost["id"]:
        if ({k: v for k, v in current["benchmark"].items() if k != "cost_model"}
                != {k: v for k, v in previous["benchmark"].items() if k != "cost_model"}):
            raise VerificationError("a v5 cost-only transition cannot change qualification or checker code")
    if old_cost["id"] != new_cost["id"]:
        legacy = json.loads((ROOT / "cost-models/collision-frontier-v4.json").read_text())
        if old_cost != legacy:
            raise VerificationError("v4 migration requires the exact historical work model")
        for field in ("id", "version", "computation_model", "nominal_reference"):
            old_cost.pop(field, None)
            new_cost.pop(field, None)
    for field in ("operation_weights", "reference_operation_costs"):
        old_cost.pop(field, None)
        new_cost.pop(field, None)
    if old_cost != new_cost:
        raise VerificationError("cost-only transition changed more than operation weights")
    weights(current)
    weights(previous)


def _check_integrity(packet):
    evidence, dossier = packet["evidence"], packet["dossier"]
    binding = evidence_binding(evidence)
    if (dossier["binding"] != binding or dossier["claim"] != evidence["submission"]["intake_report"]["claim"]
            or digest(evidence["benchmark"]) != binding["target_config_sha256"]):
        raise VerificationError("archived review does not bind its evidence")
    aggregate = dossier["aggregate"]
    config_hash = digest(dossier["judge_configuration"])
    core = {k: v for k, v in dossier.items() if k not in {"aggregate", "judge_configuration"}}
    core["judge_configuration_sha256"] = config_hash
    if (aggregate.get("judge_config_sha256") != config_hash or aggregate.get("dossier_sha256") != digest(core)
            or aggregate.get("judge_evidence_sha256") != digest(evidence)):
        raise VerificationError("archived dossier/configuration integrity mismatch")
    selected = select_lane_aggregate(dossier, evidence["benchmark"]["lane"])
    if any(aggregate.get(k) != v for k, v in selected.items()):
        raise VerificationError("archived aggregate differs from its dossier")


def verify_packet(packet, archive_root=None, *, depth=0):
    """Recheck the entire retained chain, without asking a model to rejudge it."""
    if depth >= 32:
        raise VerificationError("rescore history exceeds 32 records")
    _check_integrity(packet)
    evidence, dossier = packet["evidence"], packet["dossier"]
    if "rescore" not in dossier:
        decisions = aggregate_paired_reviews(dossier["reviews"], binding=dossier["binding"], claim=dossier["claim"],
                                             infrastructure_failures=dossier.get("infrastructure_failures"))
        if decisions != dossier["lanes"]:
            raise VerificationError("stored decisions differ from deterministic aggregation")
        if dossier["schema_version"] != "judge-paired-dossier-v1":
            raise VerificationError("qualification anchor must be a full paired review")
        return packet, []
    record = dossier["rescore"]
    if record["operation_weights"] != weights(evidence):
        raise VerificationError("rescore history contains inconsistent operation weights")
    source = load_archive(evidence["rescore_source"], archive_root)
    anchor, history = verify_packet(source, archive_root, depth=depth + 1)
    legacy = record["review"]["schema_version"] == "review-rescore-v1"
    _transition(evidence, source["evidence"], record["authorization"], legacy=legacy)
    if dossier["lanes"] != anchor["dossier"]["lanes"] or dossier["heuristic_assessments"] != anchor["dossier"]["heuristic_assessments"]:
        raise VerificationError("rescore changed inherited qualification")
    check_cost_review(record["review"], evidence)
    if not legacy and scoring_policy(evidence) == scoring_policy(source["evidence"]):
        if record["review"]["time_log2"] != accepted_score(source):
            raise VerificationError("unchanged scoring policy must preserve the previous score")
    return anchor, history + [record]


def context(evidence, authorization, archive_root=None):
    previous = load_archive(evidence["rescore_source"], archive_root)
    anchor, history = verify_packet(previous, archive_root)
    _transition(evidence, previous["evidence"], authorization)
    lane = evidence["benchmark"]["lane"]
    if not anchor["dossier"]["lanes"][lane]["eligible"]:
        raise VerificationError("cost-only rescoring requires a qualified anchor")
    return {
        "binding": evidence_binding(evidence), "qualification_anchor": anchor,
        "cost_history": history, "previous_judgment": previous,
        "previous_score": accepted_score(previous),
        "score_policy_changed": scoring_policy(evidence) != scoring_policy(previous["evidence"]),
        "previous_weights": weights(previous["evidence"]), "new_weights": weights(evidence),
    }


def check_cost_review(review, evidence):
    validate_review(review)
    if review["binding"] != evidence_binding(evidence) or review["status"] != "complete":
        raise VerificationError("cost-only review needs evidence or has a mismatched binding")
    if review["schema_version"] == "review-rescore-v2":
        return review["time_log2"]
    ledger = review["resource_ledger"]
    if ledger["success_probability"] != evidence["submission"]["intake_report"]["claim"]["claim"]["success_probability"]:
        raise VerificationError("cost-only review changed success probability")
    return price_ledger(ledger, weights(evidence), rigorous=evidence["benchmark"]["lane"] == "rigorous")


def run_review(evidence, authorization, client, archive_root=None):
    supplied = context(evidence, authorization, archive_root)
    payload = {**deepcopy(evidence), "review_context": supplied}
    if len(canonical_json_bytes(payload)) > 2 * 1024 * 1024:
        raise VerificationError("cost-only review history exceeds the 2 MiB evidence budget")
    result = client.review("lane_rescore", payload)
    if not isinstance(result.review, dict) or result.review.get("schema_version") != "review-rescore-v2":
        raise VerificationError("new reorgs require a final review-rescore-v2 judgment")
    if result.review.get("status") == "complete" and not supplied["score_policy_changed"]:
        # A non-accounting reorg cannot tighten or reset an accepted score.
        result.review["time_log2"] = supplied["previous_score"]
    validate_review(result.review)
    if result.review["binding"] != evidence_binding(evidence):
        raise VerificationError("cost-only review has a mismatched binding")
    if result.review["status"] == "needs_evidence":
        raise RescoreNeedsEvidence(result)
    check_cost_review(result.review, evidence)
    anchor = supplied["qualification_anchor"]["dossier"]
    return {
        "schema_version": "judge-rescore-dossier-v1", "policy_id": anchor["policy_id"],
        "binding": evidence_binding(evidence), "claim": deepcopy(anchor["claim"]),
        "lanes": deepcopy(anchor["lanes"]), "heuristic_assessments": deepcopy(anchor["heuristic_assessments"]),
        "rescore": {"authorization": authorization, "operation_weights": weights(evidence),
                    "score_policy_changed": supplied["score_policy_changed"],
                    "previous_score": supplied["previous_score"],
                    "review": result.review, "provenance": result.provenance},
    }
