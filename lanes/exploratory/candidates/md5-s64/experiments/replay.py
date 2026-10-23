"""Replay one published full-MD5 collision inside the organizer sandbox.

The organizer owns the request, target callback, digest checks, trial count,
container image, and resource limits. This untrusted program only validates the
closed request shape and returns the same retained message pair for each trial.
It makes no observation or claim about attack cost or independent success.
"""

import json
import re
import sys


EXPERIMENT_ID = "published-single-block-cpc-replay"
TARGET_PROFILE = "md5-s64-prefix-v1"
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
    "4f64656420476f6c6472656963680a4f"
    "64656420476f6c6472656963680a4f64"
    "656420476f6c6472656963680a4f6465"
    "6420476fd8050d0019bb9318924caa96"
    "dce35cb835b349e144e98c50c22cf461"
    "244a4064bf1afaecc5820d428ad38d6b"
    "ec89a5ad51e29063dd79b16cf67c1297"
    "8647f5af123de3acf844085cd025b956"
)
MESSAGE_B_HEX = (
    "4e65616c204b6f626c69747a0a4e6561"
    "6c204b6f626c69747a0a4e65616c204b"
    "6f626c69747a0a4e65616c204b6f626c"
    "69747a0a75b80e0035f3d2c909af1bad"
    "dce35cb835b349e144e88c50c22cf461"
    "244a40e4bf1afaecc5820d428ad38d6b"
    "ec89a5ad51e29063dd79b16cf6fc1197"
    "8647f5af123de3acf84408dcd025b956"
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
    if type(request["max_message_bytes"]) is not int or request["max_message_bytes"] < 128:
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
    output = {
        "schema_version": 1,
        "trials": [
            {
                "trial": trial["trial"],
                "message_a_hex": MESSAGE_A_HEX,
                "message_b_hex": MESSAGE_B_HEX,
            }
            for trial in trials
        ],
    }
    json.dump(output, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
