from attest_ref_impl import AttestMessage, AttestVerifier, DeploymentProfile, StaticGroundsResolver
from hypothesis import given, strategies as st


NONCRYPTO_PROFILE = DeploymentProfile(
    name="attest-test-noncrypto",
    signature_required_frames=set(),
    signature_required_retract_when_warranted=False,
    signature_recommended_frames=set(),
    state_changing_frames={"COMMIT"},
    authority_required_frames={"COMMIT", "ENDORSE"},
    accepted_authority_kinds={"human_approval", "local_policy", "sandbox_policy"},
    require_local_authority_chain_for_state_change=True,
)


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
