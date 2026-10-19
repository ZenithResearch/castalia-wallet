"""Offline structural QA for the file/schema proposal, not a wallet SDK/codec."""
import base64
import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import urljoin, urldefrag

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

BASE = Path(__file__).resolve().parent
BUNDLE = BASE / "examples/example-connection"
PREFIX = "https://raw.githubusercontent.com/ZenithResearch/castalia-wallet/main/docs/standards/cws-001/schemas/"
COUNT = 0


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate property")
        result[name] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def no_remote(uri):
    raise NoSuchResource(ref=uri)


def references(value):
    if isinstance(value, dict):
        for name, item in value.items():
            if name in ("$ref", "$dynamicRef"):
                yield item
            else:
                yield from references(item)
    elif isinstance(value, list):
        for item in value:
            yield from references(item)


resources = {}
for path in BASE.rglob("*.schema.json"):
    if path.stat().st_size > 65536:
        raise ValueError("Schema file exceeds bound")
    document = read(path)
    if document["$id"] in resources:
        raise ValueError("Duplicate schema ID")
    Draft202012Validator.check_schema(document)
    resources[document["$id"]] = document
for schema_id, document in resources.items():
    for target in references(document):
        if urldefrag(urljoin(schema_id, target))[0] not in resources:
            raise ValueError("Unpinned external schema reference")
registry = Registry(retrieve=no_remote).with_resources(
    (key, Resource.from_contents(value)) for key, value in resources.items()
)


def validator(name):
    return Draft202012Validator(resources[PREFIX + name], registry=registry)


def expect(name, action, accepted=True):
    global COUNT
    try:
        action()
        actual = True
    except (ValueError, KeyError, OSError):
        actual = False
    except Exception as error:
        # jsonschema's ValidationError is distinct from malformed QA setup.
        from jsonschema.exceptions import ValidationError
        if not isinstance(error, ValidationError):
            raise
        actual = False
    if actual != accepted:
        raise AssertionError("Unexpected result: " + name)
    COUNT += 1


publication = read(BUNDLE / "publication.json")
publication_digest = hashlib.sha256((BUNDLE / "publication.json").read_bytes()).hexdigest()


def validate_package(package):
    validator("schema-publication-v1-draft.schema.json").validate(package)
    parts = package["parts"]
    if len({part["partId"] for part in parts}) != len(parts):
        raise ValueError("Duplicate part ID")
    if len({op["operationId"] for op in package["operations"]}) != len(package["operations"]):
        raise ValueError("Duplicate operation ID")
    refs = [part["valueSchema"] for part in parts]
    for operation in package["operations"]:
        refs.extend([operation["requestSchema"], operation["resultSchema"]])
    for reference in refs:
        path = (BUNDLE / reference["path"]).resolve()
        if BUNDLE.resolve() not in path.parents or path.stat().st_size > 65536:
            raise ValueError("Schema path/bound violation")
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference["sha256"]:
            raise ValueError("Schema digest mismatch")
        if read(path)["$id"] != reference["id"]:
            raise ValueError("Schema ID mismatch")


def validate_entry(entry, destination):
    Draft202012Validator(resources[PREFIX + "common.schema.json"]["$defs"]["entry"], registry=registry).validate(entry)
    ref = entry["publication"]
    if (ref["id"], ref["version"], ref["sha256"]) != (
        publication["profileId"], publication["profileVersion"], publication_digest
    ):
        raise ValueError("Publication pin mismatch")
    part = next((part for part in publication["parts"] if part["partId"] == entry["partId"]), None)
    if part is None or part["storage"] != destination or destination == "device-local":
        raise ValueError("Part cannot enter this portable artifact")
    Draft202012Validator(resources[part["valueSchema"]["id"]], registry=registry).validate(entry["value"])


expect("complete synthetic publisher package", lambda: validate_package(publication))
data = read(BASE / "examples/castaway-v2-draft.contents.json")
expect("typed data payload", lambda: validator("castaway-contents-v2-draft.schema.json").validate(data))
entry = data["entries"][0]
expect("public connection part/value", lambda: validate_entry(entry, "castaway"))
private_entry = copy.deepcopy(entry)
private_entry["entryId"] = "example-private-recovery"
private_entry["partId"] = "recovery"
private_entry["value"] = {
    "schema": "org.example.connection-recovery.v1", "accountId": "example-account",
    "recoveryMaterial": "NONSECRET-STRUCTURAL-SENTINEL",
}
expect("private part in recovery", lambda: validate_entry(private_entry, "recovery"))
expect("private part rejected in Castaway", lambda: validate_entry(private_entry, "castaway"), False)
session_entry = copy.deepcopy(entry)
session_entry["partId"] = "session"
session_entry["value"] = {
    "schema": "org.example.connection-session.v1", "accountId": "example-account",
    "accessToken": "NONSECRET-STRUCTURAL-SENTINEL",
}
for destination in ("castaway", "recovery"):
    expect("device state rejected in " + destination, lambda dest=destination: validate_entry(session_entry, dest), False)
for key, replacement in (("version", "2.0.0"), ("sha256", "0" * 64), ("id", "https://other.example.org/profile")):
    bad = copy.deepcopy(entry); bad["publication"][key] = replacement
    expect("publication pin " + key, lambda value=bad: validate_entry(value, "castaway"), False)
bad = copy.deepcopy(entry); bad["partId"] = "unknown"
expect("unknown part", lambda: validate_entry(bad, "castaway"), False)
bad = copy.deepcopy(entry); bad["value"]["accessToken"] = "NONSECRET-STRUCTURAL-SENTINEL"
expect("secret field rejected by public value schema", lambda: validate_entry(bad, "castaway"), False)
for modification in ("traversal", "digest", "id", "classification", "grant", "duplicate-part", "duplicate-operation"):
    bad = copy.deepcopy(publication)
    if modification == "traversal": bad["parts"][0]["valueSchema"]["path"] = "../account-v1.schema.json"
    elif modification == "digest": bad["parts"][0]["valueSchema"]["sha256"] = "0" * 64
    elif modification == "id": bad["parts"][0]["valueSchema"]["id"] = "https://other.example.org/schema"
    elif modification == "classification": bad["parts"][1]["storage"] = "castaway"
    elif modification == "grant": bad["operations"][0]["requiresApproval"] = False
    elif modification == "duplicate-part": bad["parts"].append(copy.deepcopy(bad["parts"][0]))
    else: bad["operations"].append(copy.deepcopy(bad["operations"][0]))
    expect("invalid publication " + modification, lambda value=bad: validate_package(value), False)

# Existing public vector is only checked structurally here. Do not print or
# duplicate its separately published disposable cryptographic fixture material.
vector = read(BASE / "../../contracts/castalia-wallet-custody-v1.vector.json")
recovery = vector["container"]
expect("existing frozen custody-v1 envelope", lambda: validator("wallet-custody-v1.schema.json").validate(recovery))
portable = {"schema":"castalia.castaway.v1", "contentsSchema":"castalia.castaway-contents.v1",
    "ownerPublicKey":data["ownerMemberKey"], "exportedAt":0, "kdf":recovery["kdf"],
    "aead":recovery["aead"], "ciphertext":base64.urlsafe_b64encode(bytes(16)).decode().rstrip("=")}
expect("synthetic current data envelope", lambda: validator("castaway-envelope-v1.schema.json").validate(portable))
for original, filename in ((recovery,"wallet-custody-v1.schema.json"), (portable,"castaway-envelope-v1.schema.json")):
    for field in ("entries", "schemaPublications", "accessToken"):
        bad = copy.deepcopy(original); bad[field] = []
        expect("v1 rejects added field " + field, lambda value=bad, schema=filename: validator(schema).validate(value), False)
expanded = copy.deepcopy(recovery)
expanded["schema"] = "castalia.wallet-custody.v2-draft"
expanded["contentsSchema"] = "castalia.wallet-secrets.v2-draft"
expect("candidate recovery envelope", lambda: validator("wallet-custody-v2-draft.schema.json").validate(expanded))
expect("candidate rejected by old envelope", lambda: validator("wallet-custody-v1.schema.json").validate(expanded), False)
portable2 = copy.deepcopy(portable)
portable2["schema"] = "castalia.castaway.v2-draft"
portable2["contentsSchema"] = "castalia.castaway-contents.v2-draft"
expect("candidate data envelope", lambda: validator("castaway-envelope-v2-draft.schema.json").validate(portable2))
private_payload = {"schema":"castalia.wallet-secrets.v2-draft", "version":2,
    "ownerMemberKey":data["ownerMemberKey"], "custodyRevision":1,
    "root":{"schema":"castalia.wallet-secret.v1", "keyId":"0"*64,
        "privateKeyPkcs8":base64.urlsafe_b64encode(bytes(48)).decode().rstrip("="), "createdAt":0},
    "entries":[private_entry], "coverage":[{"accountId":"example-account", "source":"included",
        "entryIds":[private_entry["entryId"]], "dependencies":[]}]}
# Zero bytes are an intentionally invalid DER sentinel, never a usable key.
expect("candidate private payload shape only", lambda: validator("wallet-secrets-v2-draft.schema.json").validate(private_payload))
for source in ("included", "root-derived", "external", "excluded"):
    bad = copy.deepcopy(private_payload)
    bad["coverage"][0] = {"accountId":"example-account", "source":source, "entryIds":[], "dependencies":[]}
    expect("incomplete coverage " + source, lambda value=bad: validator("wallet-secrets-v2-draft.schema.json").validate(value), False)
expect("duplicate JSON properties rejected", lambda: json.loads('{"a":1,"a":2}', object_pairs_hook=unique), False)
print(f"{len(resources)} schema meta-checks and {COUNT} file/publication structural cases passed; resolution stayed offline.")
print("No SDK, cryptographic recovery, current nested-v1 payload replacement or device conformance is claimed.")
