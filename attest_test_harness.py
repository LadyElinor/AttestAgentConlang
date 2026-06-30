import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from attest_ref_impl import (
    AcceptAllSignatureVerifier,
    AttestMessage,
    AttestVerifier,
    DeploymentProfile,
    DeterministicSignatureVerifier,
    StaticGroundsResolver,
    canonicalize_json_bytes,
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
    ("Case 7. Dissent ID preserved but meaning laundered", "soft_flag"),
    ("Case 8. Aggregate relies on already retracted message (ancestry-reachable)", "hard_fail"),
    ("Case 9. Relay-chain lineage vs mutable handler trail", "pass_scope_limit"),
    ("Case 10. Opaque payload with strong-looking warrant envelope", "pass_scope_limit"),
    ("Case 11. External telemetry injected into local COMMIT", "hard_fail"),
    ("Case 12. External remediation text upgraded into ENDORSE authority", "hard_fail"),
    ("Case 13. External telemetry with explicit local approval receipt", "soft_flag"),
    ("Case 14. Misbound authority receipt on COMMIT", "hard_fail"),
]


def harness_profile(signature_required_frames=None) -> DeploymentProfile:
    profile = load_profile()
    profile.name = "attest-harness-v02-noncrypto"
    profile.signature_required_frames = signature_required_frames or set()
    profile.signature_required_retract_when_warranted = False
    profile.signature_recommended_frames = set()
    return profile


def crypto_profile() -> DeploymentProfile:
    profile = load_profile()
    profile.name = "attest-harness-v02-crypto"
    profile.signature_required_frames = {"ASSERT", "ENDORSE", "DISSENT"}
    profile.signature_required_retract_when_warranted = True
    profile.signature_recommended_frames = {"COMMIT"}
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
        return [retract]

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
            "policy:local-ops-v1",
        }
    )
    return refs


def materialize_special_references(name: str, data: dict) -> dict:
    data = json.loads(json.dumps(data))

    if name == "Case 8. Aggregate relies on already retracted message (ancestry-reachable)":
        data["parents"] = ["h:message-a"]
        data["warrant"]["grounds"] = ["msg:h:message-a"]

    if name == "Case 6. Unsigned reliance-bearing ASSERT":
        data["sig"] = None

    if name == "Case 13. External telemetry with explicit local approval receipt":
        data["authority_receipts"] = [
            {
                "kind": "human_approval",
                "receipt_ref": "approval:ops-001",
                "scope": "state_change",
                "issuer": "human:operator",
            }
        ]

    return data


def classify_result(result: Dict[str, List[str]]) -> str:
    if result["hard_fail"]:
        return "hard_fail"
    if result["soft_flag"]:
        return "soft_flag"
    if result["pass_scope_limit"]:
        return "pass_scope_limit"
    return "pass"


def deterministic_test_sig(msg: AttestMessage) -> str:
    digest = canonicalize_json_bytes(msg.canonical_dict())
    return f"testsig:{__import__('hashlib').sha256((msg.from_ + ':').encode('utf-8') + digest).hexdigest()}"


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
    payload["sig"] = deterministic_test_sig(msg)
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
        "warrant": {"type": "REPORTED", "grounds": ["src:sentry-event:resolution-text"]},
        "authority_receipts": [
            {
                "kind": "human_approval",
                "receipt_ref": "approval:ops-001",
                "scope": "state_change",
                "issuer": "human:operator",
                "bound_message_id": "deadbeef",
                "bound_parent_ids": ["relay:hop:other"]
            }
        ],
        "content": "Apply remediation from external issue.",
        "sig": None
    }

    for name, expected in EXAMPLE_EXPECTATIONS:
        known_messages = infer_known_messages(name)
        adopted_chain = infer_adopted_chain(name)
        known_refs = collect_resolver_known_refs(synthetic_examples, known_messages + adopted_chain, name)
        profile = harness_profile({"ASSERT"} if name == "Case 6. Unsigned reliance-bearing ASSERT" else set())
        verifier = AttestVerifier(
            profile=profile,
            grounds_resolver=StaticGroundsResolver(known_refs),
            signature_verifier=AcceptAllSignatureVerifier(),
        )

        data = materialize_special_references(name, synthetic_examples[name])
        msg = make_message(data)
        result = verifier.verify(msg, adopted_chain=adopted_chain, known_messages=known_messages)
        actual = classify_result(result)
        ok = actual == expected
        if not ok:
            failures += 1
        print(f"{name}\n  expected={expected}\n  actual={actual}\n  ok={ok}\n  detail={result}\n")

    crypto_msg = build_crypto_vector()
    crypto_verifier = AttestVerifier(
        profile=crypto_profile(),
        grounds_resolver=StaticGroundsResolver({"src:doi:10.1234/example/p7"}),
        signature_verifier=DeterministicSignatureVerifier(),
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
