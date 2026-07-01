import base64
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from nacl.signing import SigningKey

from attest_ref_impl import (
    AcceptAllSignatureVerifier,
    AttestMessage,
    AttestVerifier,
    DeploymentProfile,
    Ed25519SignatureVerifier,
    StaticAuthorityResolver,
    StaticGroundsResolver,
    load_profile,
)

EXAMPLE_EXPECTATIONS: List[Tuple[str, str]] = [
    ("Positive baseline: valid ASSERT", "pass"),
    ("Case 1. Fabricated OBSERVED with non-resolving grounds", "hard_fail"),
    ("Case 2. Confidence interval with named-but-nonresolving method", "hard_fail"),
    ("Case 3. ENDORSE strength upgrade with no new grounds", "hard_fail"),
    ("Case 4. ENDORSE with new-but-correlated grounds", "soft_flag"),
    ("Case 5. RELAY consumed without explicit uptake", "hard_fail"),
    ("Case 6. Unsigned reliance-bearing ASSERT", "hard_fail"),
    ("Case 7. Dissent ID preserved but meaning laundered", "pass"),
    ("Case 8. Aggregate relies on already retracted message (ancestry-reachable)", "hard_fail"),
    ("Case 9. Relay-chain lineage vs mutable handler trail", "pass_scope_limit"),
    ("Case 10. Opaque payload with strong-looking warrant envelope", "pass_scope_limit"),
    ("Case 11. External telemetry injected into local COMMIT", "hard_fail"),
    ("Case 12. External remediation text upgraded into ENDORSE authority", "hard_fail"),
    ("Case 13. External telemetry with explicit local approval receipt", "soft_flag"),
    ("Case 14. Misbound authority receipt on COMMIT", "hard_fail"),
    ("Case 15. Circular grounds chain returns to originating claim", "hard_fail"),
]

SIGNING_KEY = SigningKey.generate()
VERIFY_KEY_B64 = base64.b64encode(bytes(SIGNING_KEY.verify_key)).decode("ascii")


def harness_profile(signature_required_frames=None) -> DeploymentProfile:
    profile = load_profile()
    profile.name = "attest-harness-v02-noncrypto"
    profile.signature_required_frames = signature_required_frames or set()
    profile.signature_required_retract_when_warranted = False
    profile.signature_recommended_frames = set()
    profile.authority_required_frames = {"COMMIT", "DELEGATE", "ENDORSE"}
    return profile


def crypto_profile() -> DeploymentProfile:
    profile = load_profile()
    profile.name = "attest-harness-v02-crypto"
    profile.signature_required_frames = {"ASSERT", "ENDORSE", "DISSENT"}
    profile.signature_required_retract_when_warranted = True
    profile.signature_recommended_frames = {"COMMIT"}
    profile.signer_public_keys = {"agent:crypto-tester": VERIFY_KEY_B64}
    return profile


def load_examples() -> Dict[str, dict]:
    path = Path("attest-serialized-examples.md")
    content = path.read_text(encoding="utf-8")
    examples: Dict[str, dict] = {}

    pattern = re.compile(r"^##\s+(.*?)\n.*?```json\n(.*?)\n```", re.MULTILINE | re.DOTALL)
    for match in pattern.finditer(content):
        name = match.group(1).strip()
        raw = match.group(2).strip()
        examples[name] = json.loads(raw)

    return examples


def make_message(data: dict, keep_id: bool = False) -> AttestMessage:
    payload = json.loads(json.dumps(data))
    if not keep_id:
        payload.pop("id", None)
    return AttestMessage.model_validate(payload)


def infer_adopted_chain(name: str) -> List[AttestMessage]:
    if name == "Case 3. ENDORSE strength upgrade with no new grounds":
        return [
            make_message(
                {
                    "frame": "ASSERT",
                    "mode": "legible",
                    "from": "agent:source",
                    "to": "agent:planner-0",
                    "parents": [],
                    "ordering_anchor": ["2026-06-29T20:24:00Z", 104],
                    "warrant": {"type": "REPORTED", "grounds": ["src:upstream-report"]},
                    "content": "Weak reported claim",
                }
            )
        ]

    if name == "Case 4. ENDORSE with new-but-correlated grounds":
        return [
            make_message(
                {
                    "frame": "ASSERT",
                    "mode": "legible",
                    "from": "agent:source",
                    "to": "agent:planner-0",
                    "parents": [],
                    "ordering_anchor": ["2026-06-29T20:26:00Z", 106],
                    "warrant": {"type": "REPORTED", "grounds": ["src:shared-upstream"]},
                    "content": "Weak reported claim",
                }
            )
        ]

    if name == "Case 8. Aggregate relies on already retracted message (ancestry-reachable)":
        intermediate = make_message(
            {
                "id": "msg:intermediate-b",
                "frame": "ASSERT",
                "mode": "legible",
                "from": "agent:planner-0",
                "to": "agent:planner-1",
                "parents": ["h:message-a"],
                "ordering_anchor": ["2026-06-29T20:34:00Z", 120],
                "warrant": {"type": "DERIVED", "grounds": ["msg:h:message-a"]},
                "content": "Intermediate aggregate over A.",
            },
            keep_id=False,
        )
        return [intermediate]

    if name == "Case 15. Circular grounds chain returns to originating claim":
        b = make_message(
            {
                "id": "msg:cycle-b",
                "frame": "ASSERT",
                "mode": "legible",
                "from": "agent:cycle-b",
                "to": "agent:cycle-a",
                "parents": [],
                "ordering_anchor": ["2026-06-30T22:10:00Z", 300],
                "warrant": {"type": "DERIVED", "grounds": ["msg:cycle-a"]},
                "content": "B depends on A.",
            },
            keep_id=False,
        )
        return [b]

    return []


def infer_known_messages(name: str) -> List[AttestMessage]:
    if name == "Case 8. Aggregate relies on already retracted message (ancestry-reachable)":
        retract = make_message(
            {
                "frame": "RETRACT",
                "mode": "legible",
                "from": "agent:critic-1",
                "to": "agent:planner-0",
                "parents": ["h:earlier-parent"],
                "targets": ["h:message-a"],
                "ordering_anchor": ["2026-06-29T20:35:00Z", 121],
                "warrant": {"type": "REPORTED", "grounds": ["src:retraction-log"]},
                "content": "Withdraw premise A due to upstream correction.",
            }
        )
        intermediate = infer_adopted_chain(name)[0]
        return [retract, intermediate]

    if name == "Case 15. Circular grounds chain returns to originating claim":
        return []

    return []


def unresolved_grounds_for_case(name: str) -> Set[str]:
    if name == "Case 1. Fabricated OBSERVED with non-resolving grounds":
        return {"missing-call-id"}
    if name == "Case 2. Confidence interval with named-but-nonresolving method":
        return {"note:ensemble disagreement"}
    return set()


def collect_resolver_known_refs(examples: Dict[str, dict], known_messages: List[AttestMessage], case_name: str) -> Set[str]:
    refs: Set[str] = set()
    unresolved = unresolved_grounds_for_case(case_name)

    for message in known_messages:
        refs.add(message.compute_id())
        refs.add(message.compute_core_id())
        refs.update(message.targets)
        if message.warrant:
            refs.update(message.warrant.grounds)

    for _, data in examples.items():
        warrant = data.get("warrant") or {}
        for ground in warrant.get("grounds") or []:
            if ground not in unresolved:
                refs.add(ground)

    refs.update(
        {
            "src:doi:10.1234/example/p7",
            "tool:websearch#a6bf",
            "src:upstream-report",
            "src:shared-upstream",
            "tool:second-retrieval#same-upstream",
            "src:aggregate-notes",
            "src:relay-audit",
            "tool:sensor-log#alpha",
            "src:sentry-event:resolution-text",
            "src:report:alpha",
            "src:retraction-log",
            "msg:h:dissent-msg-1",
            "msg:h:message-a",
            "h:message-a",
            "receipt:approval-001",
            "approval:ops-001",
            "policy:local-ops-v1",
        }
    )
    return refs


def collect_known_authorities(case_name: str) -> Set[str]:
    refs = set()
    if case_name == "Case 4. ENDORSE with new-but-correlated grounds":
        refs.add("policy:review-only-endorse")
    if case_name == "Case 13. External telemetry with explicit local approval receipt":
        refs.add("approval:ops-001")
    if case_name == "Case 14. Misbound authority receipt on COMMIT":
        refs.add("approval:ops-001")
    return refs


def materialize_special_references(name: str, data: dict) -> dict:
    data = json.loads(json.dumps(data))

    if name == "Case 8. Aggregate relies on already retracted message (ancestry-reachable)":
        data["parents"] = ["msg:intermediate-b"]
        data["warrant"]["grounds"] = ["msg:h:message-a"]

    if name == "Case 6. Unsigned reliance-bearing ASSERT":
        data["sig"] = None

    return data


def classify_result(result: Dict[str, List[str]]) -> str:
    if result["hard_fail"]:
        return "hard_fail"
    if result["soft_flag"]:
        return "soft_flag"
    if result["pass_scope_limit"]:
        return "pass_scope_limit"
    return "pass"


def sign_ed25519_message(msg: AttestMessage) -> str:
    signature = SIGNING_KEY.sign(msg.canonical_bytes()).signature
    return "ed25519:" + base64.b64encode(signature).decode("ascii")


def build_crypto_vector() -> AttestMessage:
    msg = make_message(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:crypto-tester",
            "to": "agent:planner-0",
            "parents": [],
            "ordering_anchor": ["2026-06-30T15:00:00Z", 1],
            "warrant": {"type": "RETRIEVED", "grounds": ["src:doi:10.1234/example/p7"]},
            "content": "Canonical signing vector.",
        }
    )
    payload = msg.model_dump(by_alias=True)
    payload["sig"] = sign_ed25519_message(msg)
    return AttestMessage.model_validate(payload)


def run_tests() -> int:
    base_profile = harness_profile()
    examples = load_examples()
    failures = 0

    print(f"profile={base_profile.name} independence_policy={base_profile.independence_policy_name}\n")

    synthetic_examples = dict(examples)
    synthetic_examples["Case 14. Misbound authority receipt on COMMIT"] = {
        "frame": "COMMIT",
        "mode": "legible",
        "from": "agent:operator-1",
        "to": "agent:executor-0",
        "parents": ["relay:hop:1"],
        "ordering_anchor": ["2026-06-30T14:59:00Z", 200],
        "action_scope": "state_change",
        "warrant": {"type": "REPORTED", "grounds": ["src:sentry-event:resolution-text"]},
        "deontic": {
            "type": "HUMAN_APPROVAL",
            "authority": ["approval:ops-001"],
            "scope": "state_change",
            "binds": {"message": "deadbeef", "parents": ["relay:hop:1"]},
            "nonce": "nonce-invalid"
        },
        "content": "Apply remediation from external issue.",
        "sig": None
    }
    cycle_seed = make_message(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:cycle-a",
            "to": "agent:cycle-b",
            "parents": [],
            "ordering_anchor": ["2026-06-30T22:11:00Z", 301],
            "warrant": {"type": "DERIVED", "grounds": []},
            "content": "Self-grounded cycle seed.",
            "sig": None,
        }
    )
    synthetic_examples["Case 15. Circular grounds chain returns to originating claim"] = {
        "frame": "ASSERT",
        "mode": "legible",
        "from": "agent:cycle-a",
        "to": "agent:cycle-b",
        "parents": [],
        "ordering_anchor": ["2026-06-30T22:11:00Z", 301],
        "warrant": {"type": "DERIVED", "grounds": [cycle_seed.compute_id()]},
        "content": "Self-grounded cycle seed.",
        "sig": None
    }

    for name, expected in EXAMPLE_EXPECTATIONS:
        known_messages = infer_known_messages(name)
        adopted_chain = infer_adopted_chain(name)
        known_refs = collect_resolver_known_refs(synthetic_examples, known_messages + adopted_chain, name)
        authority_refs = collect_known_authorities(name)
        profile = harness_profile({"ASSERT"} if name == "Case 6. Unsigned reliance-bearing ASSERT" else set())
        verifier = AttestVerifier(
            profile=profile,
            grounds_resolver=StaticGroundsResolver(known_refs),
            authority_resolver=StaticAuthorityResolver(authority_refs),
            signature_verifier=AcceptAllSignatureVerifier(),
        )

        data = materialize_special_references(name, synthetic_examples[name])
        msg = make_message(data)
        result = verifier.verify(msg, adopted_chain=adopted_chain, known_messages=known_messages + adopted_chain)
        actual = classify_result(result)
        ok = actual == expected
        if not ok:
            failures += 1
        print(f"{name}\n  expected={expected}\n  actual={actual}\n  ok={ok}\n  detail={result}\n")

    crypto_msg = build_crypto_vector()
    crypto_verifier = AttestVerifier(
        profile=crypto_profile(),
        grounds_resolver=StaticGroundsResolver({"src:doi:10.1234/example/p7"}),
        authority_resolver=StaticAuthorityResolver(set()),
        signature_verifier=Ed25519SignatureVerifier({"agent:crypto-tester": VERIFY_KEY_B64}),
    )
    crypto_result = crypto_verifier.verify(crypto_msg)
    crypto_ok = classify_result(crypto_result) == "pass"
    if not crypto_ok:
        failures += 1
    print(f"Crypto vector\n  expected=pass\n  actual={classify_result(crypto_result)}\n  ok={crypto_ok}\n  detail={crypto_result}\n")

    if failures:
        print(f"FAILURES={failures}")
        return 1

    print("ALL_EXPECTATIONS_MET")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_tests())
