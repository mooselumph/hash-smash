"""Reusable resource bounds and deterministic pricing in compression equivalents."""

from __future__ import annotations

import json
import math
from pathlib import Path

from .errors import VerificationError

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas/resource-ledger-v1.schema.json"
UNIT_WEIGHTS = {"target_compression": 1, "word_operation": 1}


def ledger_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def validate_weights(weights: dict) -> dict:
    if not isinstance(weights, dict) or set(weights) != set(UNIT_WEIGHTS):
        raise VerificationError("operation weights must price target_compression and word_operation")
    for value in weights.values():
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value > 0
        except OverflowError:
            valid = False
        if not valid:
            raise VerificationError("operation weights must be finite and positive")
    if weights["target_compression"] != 1:
        raise VerificationError("one target compression must remain one score unit")
    return weights


def validate_ledger(ledger: dict) -> dict:
    from judge.schema_validation import _validate, ReviewValidationError

    try:
        _validate(ledger, ledger_schema(), "$.resource_ledger")
    except (ReviewValidationError, OverflowError) as error:
        raise VerificationError(f"invalid resource ledger: {error}") from error
    ids = [item["id"] for item in ledger["components"]]
    if len(ids) != len(set(ids)):
        raise VerificationError("resource component IDs must be unique")
    for item in ledger["components"]:
        basis = item["source_weights"]
        if item["operation"] == "opaque":
            validate_weights(basis)
        elif basis is not None:
            raise VerificationError("raw operation counts cannot have source weights")
    return ledger


def price_ledger(ledger: dict, weights: dict, *, rigorous: bool = False) -> float:
    """Sum upper bounds in log space; opaque work uses the worst price ratio.

    An opaque bound B measured at old prices a,b implies a new bound
    B * max(new_a/a, new_b/b). Its original prices never change on replay.
    """
    validate_ledger(ledger)
    validate_weights(weights)
    terms = []
    for item in ledger["components"]:
        if item["bound_kind"] == "estimate" or item["status"] == "unresolved":
            raise VerificationError("estimates and unresolved components cannot set a score")
        if rigorous and item["status"] != "supported":
            raise VerificationError("rigorous rescoring requires supported resource bounds")
        if item["operation"] == "opaque":
            basis = item["source_weights"]
            adjustment = max(math.log2(weights[k]) - math.log2(basis[k]) for k in weights)
        else:
            adjustment = math.log2(weights[item["operation"]])
        terms.append(item["count_log2"] + adjustment)
    largest = max(terms)
    score = largest + math.log2(math.fsum(2 ** (term - largest) for term in terms))
    if not math.isfinite(score):
        raise VerificationError("resource projection must be finite")
    return max(0.0, score)


def legacy_ledger(claim: dict, weights: dict, *, rigorous: bool) -> dict:
    """Retain an accepted aggregate bound without inventing an operation mix."""
    return {
        "schema_version": "resource-ledger-v1",
        "success_probability": claim["claim"]["success_probability"],
        "coverage": "Entire submitted computation, including preprocessing and failed trials.",
        "components": [{
            "id": "legacy-total", "phase": "entire algorithm", "operation": "opaque",
            "count_log2": claim["claim"]["time_log2"], "bound_kind": "upper_bound",
            "status": "supported" if rigorous else "conditional",
            "source_weights": dict(weights), "evidence": ["claim.json:/claim/time_log2"],
            "assumptions": ["Inherited qualification and all its recorded limitations."],
        }],
    }
