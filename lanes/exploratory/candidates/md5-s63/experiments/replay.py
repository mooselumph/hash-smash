"""Replay a published single-block collision against the selected MD5-s63 target.

The organizer owns the request, target callback, digest checks, trial count,
container image, and resource limits. This untrusted program validates the
closed request shape and returns the same retained pair for every trial. It
does not report attack cost or pretend that duplicate rows are fresh samples.
"""

import json
import re
import sys


EXPERIMENT_ID = "published-single-block-s63-replay"
TARGET_PROFILE = "md5-s63-prefix-v1"
EVENT = {"kind": "full-collision"}
REQUEST_KEYS = {
    "schema_version",
    "experiment_id",
    "target_profile",
    "event",
    "max_message_bytes",
    "trials",
}
SEED_RE = re.compile(r"[0-9a-f]{64}\Z")

MESSAGE_A_HEX = (
    "4dc968ff0ee35c209572d4777b721587"
    "d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa200a8284bf36e8e4b55b35f4275"
    "93d849676da0d1555d8360fb5f07fea2"
)
MESSAGE_B_HEX = (
    "4dc968ff0ee35c209572d4777b721587"
    "d36fa7b21bdc56b74a3dc0783e7b9518"
    "afbfa202a8284bf36e8e4b55b35f4275"
    "93d849676da0d1d55d8360fb5f07fea2"
)


def fail(message):
    raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key")
        result[key] = value
    return result


def validate_request(request):
    if type(request) is not dict or set(request) != REQUEST_KEYS:
        fail("unexpected request shape")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        fail("unexpected schema version")
    if request["experiment_id"] != EXPERIMENT_ID:
        fail("unexpected experiment id")
    if request["target_profile"] != TARGET_PROFILE:
        fail("unexpected target profile")
    if type(request["event"]) is not dict or request["event"] != EVENT:
        fail("unexpected event")
    if type(request["max_message_bytes"]) is not int or request["max_message_bytes"] < 64:
        fail("message budget is too small")
    trials = request["trials"]
    if type(trials) is not list or not trials:
        fail("trials must be a nonempty list")
    for index, trial in enumerate(trials):
        if type(trial) is not dict or set(trial) != {"trial", "seed"}:
            fail("unexpected trial shape")
        if type(trial["trial"]) is not int or trial["trial"] != index:
            fail("trials are not in organizer order")
        if type(trial["seed"]) is not str or SEED_RE.fullmatch(trial["seed"]) is None:
            fail("invalid organizer seed")
    return trials


def main():
    request = json.load(
        sys.stdin,
        object_pairs_hook=unique_object,
        parse_constant=lambda value: fail("nonfinite JSON number"),
    )
    trials = validate_request(request)
    json.dump(
        {
            "schema_version": 1,
            "trials": [
                {
                    "trial": trial["trial"],
                    "message_a_hex": MESSAGE_A_HEX,
                    "message_b_hex": MESSAGE_B_HEX,
                }
                for trial in trials
            ],
        },
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
