"""Validate CWS-001 structural review fixtures; not a wallet or protocol validator."""
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON property in structural fixture")
        result[name] = value
    return result


def read_json(path):
    # The case collection repeats examples; this is a QA-file bound, not the
    # normative 1 MiB bound on individual wallet descriptor input.
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Structural QA file exceeds 4 MiB")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)


base = Path(__file__).resolve().parent
schema = read_json(base / "connected-accounts.v1-draft.schema.json")
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
example = read_json(base / "examples/matrix-and-nostr.json")
cases = read_json(base / "structural-cases.json")["cases"]
for case in cases:
    document = copy.deepcopy(example)
    for patch in case["patches"]:
        if patch["op"] == "repeatFirstAccount":
            document["accounts"] = [copy.deepcopy(example["accounts"][0]) for _ in range(patch["count"])]
            continue
        target = document
        for key in patch["path"][:-1]:
            target = target[key]
        key = patch["path"][-1]
        if patch["op"] == "delete":
            del target[key]
        elif patch["op"] == "set":
            target[key] = patch["value"]
        else:
            raise ValueError("Unknown structural-fixture operation")
    if validator.is_valid(document) != case["valid"]:
        raise SystemExit("Unexpected structural result: " + case["name"])
validator.validate(example)
print(f"Schema and example valid; {len(cases)} structural cases passed.")
print("Protocol semantics, cryptography, custody and device behavior are not tested.")
