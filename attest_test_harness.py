import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

from attest_ref_impl import AcceptAllSignatureVerifier, AttestMessage, AttestVerifier, DeploymentProfile, StaticGroundsResolver

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
]


def harness_profile(signature_required_frames=None) -> DeploymentProfile:
    return DeploymentProfile(
        name="attest-harness-v02-noncrypto",
        signature_required_frames=signature_required_frames or set(),
        signature_required_retract_when_warranted=False,
        signature_recommended_frames=set(),
        state_changing_frames={"COMMIT"},
        authority_required_frames={"COMMIT", "ENDORSE"},
        accepted_authority_kinds={"human_approval", "local_policy", "sandbox_policy"},
        require_local_authority_chain_for_state_change=True,
        external_authority_prefixes=["src:sentry-event", "src:external-issue", "src:ticket", "src:web", "src:github-issue"],
        local_authority_prefixes=["approval:", "policy:", "sandbox:"],
        warrant_strength_order={
            "OBSERVED": 5,
            "DERIVED": 4,
            "RETRIEVED": 3,
            "REPORTED": 2,
            "ASSUMED": 1,
        },
        relay_parent_prefixes=["h:upstream-relay", "relay:hop:"],
        independence_policy_name="declared-lineage-default",
    )


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

    for name, data in examples.items():
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
            "h:dissent-msg-1",
            "h:message-a",
            "h:upstream-relay-msg...",
            "h:weak-reported-msg...",
            "h:external-telemetry-msg...",
            "h:external-issue-msg...",
        }
    )
    return refs


def materialize_special_references(name: str, data: dict) -> dict:
    data = json.loads(json.dumps(data))

    if name == "Case 8. Aggregate relies on already retracted message (ancestry-reachable)":
        data["parents"] = ["h:message-a"]
        data["warrant"]["grounds"] = ["h:message-a"]

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


def run_tests() -> int:
    base_profile = harness_profile()
    examples = load_examples()
    failures = 0

    print(f"profile={base_profile.name} independence_policy={base_profile.independence_policy_name}\n")

    for name, expected in EXAMPLE_EXPECTATIONS:
        known_messages = infer_known_messages(name)
        adopted_chain = infer_adopted_chain(name)
        known_refs = collect_resolver_known_refs(examples, known_messages + adopted_chain, name)
        profile = harness_profile({"ASSERT"} if name == "Case 6. Unsigned reliance-bearing ASSERT" else set())
        verifier = AttestVerifier(
            profile=profile,
            grounds_resolver=StaticGroundsResolver(known_refs),
            signature_verifier=AcceptAllSignatureVerifier(),
        )

        data = materialize_special_references(name, examples[name])
        msg = make_message(data)
        result = verifier.verify(msg, adopted_chain=adopted_chain, known_messages=known_messages)
        actual = classify_result(result)
        ok = actual == expected
        if not ok:
            failures += 1
        print(f"{name}\n  expected={expected}\n  actual={actual}\n  ok={ok}\n  detail={result}\n")

    if failures:
        print(f"FAILURES={failures}")
        return 1

    print("ALL_EXPECTATIONS_MET")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_tests())
