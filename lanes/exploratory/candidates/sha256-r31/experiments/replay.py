"""Fixed witness transport; execute ONLY in the organizer Docker sandbox.

This source intentionally replays one public pair for every requested trial.
It is evidence for the selected-target collision relation only. It does not
reproduce the historical search or provide attack-cost or probability evidence.
"""

import json
import sys


MESSAGE_A_HEX = (
    "8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082"
    "dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249"
    "9abdeb1b1f195f415a7210c155614f13a2269dd1be888a61359257d4adf3737b"
    "9f0484a6eb830a5866add94a9669232d45271fa5b8f69585428bbce30703b904"
)
MESSAGE_B_HEX = (
    "8ce3f8055c401aed579e5f7fbc3116cbca189b3ceb75f04c958f0a0e7760b082"
    "dcd5027d32260ad67b12b659eee66518ad7f88ddf8ad20bb7ae40ffd21609249"
    "9abdeb1b1f195f415a7210c155614f13a2269dd1be887a6735b2dfc5fde32975"
    "c70595a6eb838a5c66add94a9669232d45271fa5b8f69585428bbce30703b904"
)


def validate_request(request):
    if type(request) is not dict:
        raise ValueError("organizer request must be an object")
    required = {
        "schema_version",
        "experiment_id",
        "target_profile",
        "event",
        "max_message_bytes",
        "trials",
    }
    if set(request) != required:
        raise ValueError("unexpected organizer request fields")
    if request["schema_version"] != 1:
        raise ValueError("unexpected organizer schema")
    if request["experiment_id"] != "published-r31-witness-replay":
        raise ValueError("unexpected experiment id")
    if request["target_profile"] != "sha256-r31-prefix-v1":
        raise ValueError("unexpected organizer target")
    if request["event"] != {"kind": "full-collision"}:
        raise ValueError("unexpected organizer event")
    if type(request["max_message_bytes"]) is not int or request["max_message_bytes"] < 128:
        raise ValueError("organizer message budget is too small")
    if type(request["trials"]) is not list:
        raise ValueError("organizer trials must be a list")
    for index, trial in enumerate(request["trials"]):
        if type(trial) is not dict or set(trial) != {"trial", "seed"}:
            raise ValueError("unexpected organizer trial")
        if type(trial["trial"]) is not int or trial["trial"] != index:
            raise ValueError("organizer trials must be ordered")
        seed = trial["seed"]
        if type(seed) is not str or len(seed) != 64:
            raise ValueError("organizer seed must be 32-byte hex")
        try:
            decoded = bytes.fromhex(seed)
        except ValueError as error:
            raise ValueError("organizer seed must be valid hex") from error
        if len(decoded) != 32 or seed != seed.lower():
            raise ValueError("organizer seed must be lowercase 32-byte hex")


def main():
    request = json.load(sys.stdin)
    validate_request(request)
    rows = [
        {
            "trial": trial["trial"],
            "message_a_hex": MESSAGE_A_HEX,
            "message_b_hex": MESSAGE_B_HEX,
        }
        for trial in request["trials"]
    ]
    json.dump(
        {"schema_version": 1, "trials": rows},
        sys.stdout,
        separators=(",", ":"),
        sort_keys=True,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
