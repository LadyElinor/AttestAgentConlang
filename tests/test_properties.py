from attest_ref_impl import (
    AttestMessage,
    AttestVerifier,
    DeploymentProfile,
    DeterministicSignatureVerifier,
    StaticGroundsResolver,
    canonicalize_json_bytes,
    load_profile,
)
from hypothesis import given, strategies as st
import hashlib


NONCRYPTO_PROFILE = load_profile()
NONCRYPTO_PROFILE.name = "attest-test-noncrypto"
NONCRYPTO_PROFILE.signature_required_frames = set()
NONCRYPTO_PROFILE.signature_required_retract_when_warranted = False
NONCRYPTO_PROFILE.signature_recommended_frames = set()


def deterministic_sig(msg: AttestMessage) -> str:
    digest = canonicalize_json_bytes(msg.canonical_dict())
    return f"testsig:{hashlib.sha256((msg.from_ + ':').encode('utf-8') + digest).hexdigest()}"


@given(st.text(min_size=1, max_size=40).map(lambda s: "tool:" + s))
def test_prefixed_fabricated_observed_fails_closed(ref: str):
    verifier = AttestVerifier(profile=NONCRYPTO_PROFILE, grounds_resolver=StaticGroundsResolver(set()))
    msg = AttestMessage.model_validate(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:tester",
            "to": "agent:planner",
            "parents": [],
            "ordering_anchor": ["2026-06-29T20:00:00Z", 1],
            "warrant": {"type": "OBSERVED", "confidence": [0.9, 0.99], "grounds": [ref]},
            "content": "fabricated observed claim",
        }
    )
    result = verifier.verify(msg)
    assert "OBSERVED_GROUNDS_NOT_ARTIFACT_BACKED" in result["hard_fail"]


@given(st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=20))
def test_nfc_nfd_normalize_to_same_id(prefix: str, stem: str):
    a = AttestMessage.model_validate(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:tester",
            "to": "agent:planner",
            "parents": [],
            "ordering_anchor": ["2026-06-29T20:00:00Z", 2],
            "warrant": {"type": "ASSUMED", "grounds": []},
            "content": prefix + "é" + stem,
        }
    )
    b = AttestMessage.model_validate(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:tester",
            "to": "agent:planner",
            "parents": [],
            "ordering_anchor": ["2026-06-29T20:00:00Z", 2],
            "warrant": {"type": "ASSUMED", "grounds": []},
            "content": prefix + "e\u0301" + stem,
        }
    )
    assert a.compute_id() == b.compute_id()


def test_authority_receipt_must_bind_message_and_parents():
    verifier = AttestVerifier(
        profile=load_profile(),
        grounds_resolver=StaticGroundsResolver({"src:sentry-event:resolution-text", "approval:ops-001"}),
    )
    msg = AttestMessage.model_validate(
        {
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
                    "bound_parent_ids": ["relay:hop:other"],
                }
            ],
            "content": "Apply remediation from external issue.",
        }
    )
    result = verifier.verify(msg)
    assert "AUTHORITY_RECEIPT_BINDING_INVALID" in result["hard_fail"]


def test_deterministic_signature_vector_verifies():
    profile = load_profile()
    verifier = AttestVerifier(
        profile=profile,
        grounds_resolver=StaticGroundsResolver({"src:doi:10.1234/example/p7"}),
        signature_verifier=DeterministicSignatureVerifier(),
    )
    msg = AttestMessage.model_validate(
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
    payload["sig"] = deterministic_sig(msg)
    signed = AttestMessage.model_validate(payload)
    result = verifier.verify(signed)
    assert result == {"hard_fail": [], "soft_flag": [], "pass_scope_limit": []}
