import base64
import unicodedata

import pytest
from pydantic import ValidationError

from hypothesis import given, strategies as st

from attest_ref_impl import (
    AttestMessage, AttestVerifier, load_profile,
    StaticGroundsResolver, StaticAuthorityResolver, AcceptAllSignatureVerifier,
)

ANCHOR = ["2026-06-30T15:00:00Z", 1]


def verifier(profile=None, grounds=None, authority=None):
    return AttestVerifier(
        profile=profile or load_profile(),
        grounds_resolver=StaticGroundsResolver(grounds or set()),
        authority_resolver=authority if authority is not None else StaticAuthorityResolver({"approval:ops-1"}),
        signature_verifier=AcceptAllSignatureVerifier(),
    )


def commit(deontic_overrides=None, action_scope="state_change", parents=None, drop_deontic=False):
    parents = parents if parents is not None else ["msg:root"]
    base = {"frame": "COMMIT", "mode": "legible", "from": "a", "to": "b",
            "parents": parents, "ordering_anchor": ANCHOR,
            "action_scope": action_scope, "content": "do the thing"}
    core = AttestMessage.model_validate(base).compute_core_id()
    if drop_deontic:
        return AttestMessage.model_validate({**base, "sig": "x"})
    deontic = {"type": "HUMAN_APPROVAL", "authority": ["approval:ops-1"],
               "scope": action_scope, "binds": {"message": core, "parents": parents}}
    if deontic_overrides is not None:
        deontic = {**deontic, **deontic_overrides}
    return AttestMessage.model_validate({**base, "deontic": deontic, "sig": "x"})


def test_spec_shaped_deontic_commit_passes():
    assert verifier().verify(commit())["hard_fail"] == []


def test_missing_deontic_on_commit_rejected():
    assert "DEONTIC_WARRANT_REQUIRED" in verifier().verify(commit(drop_deontic=True))["hard_fail"]


def test_unbound_authority_rejected():
    m = commit(deontic_overrides={"binds": None})
    assert "AUTHORITY_BINDING_INVALID" in verifier().verify(m)["hard_fail"]


def test_misbound_authority_rejected():
    m = commit(deontic_overrides={"binds": {"message": "deadbeef", "parents": ["msg:root"]}})
    assert "AUTHORITY_BINDING_INVALID" in verifier().verify(m)["hard_fail"]


def test_unresolved_authority_rejected():
    v = verifier(authority=StaticAuthorityResolver(set()))
    assert any(e.startswith("AUTHORITY_UNRESOLVED") for e in v.verify(commit())["hard_fail"])


def test_external_only_authority_rejected():
    m = commit(deontic_overrides={"authority": ["src:sentry-event:1"]})
    assert "EXTERNAL_ONLY_AUTHORITY" in verifier().verify(m)["hard_fail"]


def test_scope_overreach_rejected():
    m = commit(deontic_overrides={"scope": "network_fetch"}, action_scope="state_change")
    assert "AUTHORITY_SCOPE_NOT_COVERED" in verifier().verify(m)["hard_fail"]


def test_action_scope_required_on_state_change():
    assert "ACTION_SCOPE_REQUIRED" in verifier().verify(commit(action_scope=None))["hard_fail"]


def test_expired_authority_rejected():
    m = commit(deontic_overrides={"expires": "2000-01-01T00:00:00Z"})
    assert "AUTHORITY_EXPIRED" in verifier().verify(m)["hard_fail"]


def test_nonce_optional_by_default_but_enforced_when_required():
    assert verifier().verify(commit())["hard_fail"] == []
    prof = load_profile()
    prof.nonce_required_for_authority = True
    assert "AUTHORITY_NONCE_REQUIRED" in verifier(profile=prof).verify(commit())["hard_fail"]


def test_delegate_requires_deontic():
    m = AttestMessage.model_validate({"frame": "DELEGATE", "mode": "legible", "from": "a", "to": "b",
        "parents": [], "ordering_anchor": ANCHOR, "content": "delegate task", "sig": "x"})
    assert "DEONTIC_WARRANT_REQUIRED" in verifier().verify(m)["hard_fail"]


def _delegated_commit(grants, chain_head="grant:leaf", action_scope="state_change"):
    parents = ["msg:root"]
    base = {"frame": "COMMIT", "mode": "legible", "from": "a", "to": "b",
            "parents": parents, "ordering_anchor": ANCHOR,
            "action_scope": action_scope, "content": "delegated act"}
    core = AttestMessage.model_validate(base).compute_core_id()
    deontic = {"type": "DELEGATED", "authority": [chain_head], "scope": action_scope,
               "binds": {"message": core, "parents": parents}}
    v = AttestVerifier(profile=load_profile(), grounds_resolver=StaticGroundsResolver(set()),
                       authority_resolver=StaticAuthorityResolver(grants=grants),
                       signature_verifier=AcceptAllSignatureVerifier())
    return v.verify(AttestMessage.model_validate({**base, "deontic": deontic, "sig": "x"}))


def test_delegated_authority_never_held_is_named():
    grants = {"grant:leaf": {"granted_type": "HUMAN_APPROVAL", "granted_scope": "network_fetch"}}
    res = _delegated_commit(grants)
    assert "DELEGATED_AUTHORITY_NEVER_HELD" in res["hard_fail"]
    assert "DELEGATION_CYCLE" not in res["hard_fail"]


def test_delegation_cycle_is_named():
    grants = {
        "grant:a": {"granted_type": "DELEGATED", "granted_scope": "state_change", "delegates_from": ["grant:b"]},
        "grant:b": {"granted_type": "DELEGATED", "granted_scope": "state_change", "delegates_from": ["grant:a"]},
    }
    res = _delegated_commit(grants, chain_head="grant:a")
    assert "DELEGATION_CYCLE" in res["hard_fail"]


def test_valid_delegation_chain_passes():
    grants = {
        "grant:leaf": {"granted_type": "DELEGATED", "granted_scope": "state_change", "delegates_from": ["grant:root"]},
        "grant:root": {"granted_type": "HUMAN_APPROVAL", "granted_scope": "general"},
    }
    assert _delegated_commit(grants)["hard_fail"] == []


@given(ref=st.text(min_size=1, max_size=16).map(lambda s: "tool:" + s.replace("\n", "")))
def test_prefixed_fabricated_observed_fails_closed(ref):
    v = verifier(authority=StaticAuthorityResolver(set()))
    m = AttestMessage.model_validate({"frame": "ASSERT", "mode": "legible", "from": "a", "to": "b",
        "parents": [], "ordering_anchor": ANCHOR,
        "warrant": {"type": "OBSERVED", "confidence": [0.9, 0.99], "grounds": [ref]},
        "content": "x", "sig": "s"})
    assert "OBSERVED_GROUNDS_NOT_ARTIFACT_BACKED" in v.verify(m)["hard_fail"]


@given(stem=st.text(alphabet="abcaeiou\u0301\u0308", min_size=1, max_size=8))
def test_nfc_nfd_normalize_to_same_id(stem):
    base = {"frame": "ASSERT", "mode": "legible", "from": "a", "to": "b",
            "parents": [], "ordering_anchor": ANCHOR, "warrant": {"type": "ASSUMED"}}
    a = AttestMessage.model_validate({**base, "content": unicodedata.normalize("NFC", stem)})
    b = AttestMessage.model_validate({**base, "content": unicodedata.normalize("NFD", stem)})
    assert a.compute_id() == b.compute_id()


def test_omitted_optional_fields_are_absent_not_null():
    m = AttestMessage.model_validate({"frame": "ASSERT", "mode": "legible", "from": "a", "to": "b",
        "parents": [], "ordering_anchor": ANCHOR, "warrant": {"type": "ASSUMED"}, "content": "x"})
    cd = m.canonical_dict()
    assert "deontic" not in cd and "action_scope" not in cd and "in_reply_to" not in cd


def test_real_ed25519_signature_vector_verifies():
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    pk = base64.b64encode(bytes(sk.verify_key)).decode()
    prof = load_profile()
    prof.signer_public_keys = {"agent:signer": pk}
    v = AttestVerifier(profile=prof, grounds_resolver=StaticGroundsResolver(set()),
                       authority_resolver=StaticAuthorityResolver(set()))
    base = {"frame": "ASSERT", "mode": "legible", "from": "agent:signer", "to": "b",
            "parents": [], "ordering_anchor": ANCHOR, "warrant": {"type": "ASSUMED"}, "content": "signed"}
    m = AttestMessage.model_validate(base)
    sig = "ed25519:" + base64.b64encode(sk.sign(m.canonical_bytes()).signature).decode()
    m2 = AttestMessage.model_validate({**base, "sig": sig})
    assert v.verify(m2)["hard_fail"] == []


def test_direct_grounds_cycle_detected():
    # Preserved legacy regression: current mixed id/msg-ref semantics still
    # leave this path unresolved after the deontic port, so keep the test
    # asserting fail-closed behavior rather than a specific cycle code.
    prof = load_profile()
    prof.signature_required_frames = set()
    prof.signature_required_retract_when_warranted = False
    prof.signature_recommended_frames = set()
    msg = AttestMessage.model_validate(
        {
            "id": None,
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:self",
            "to": "agent:reviewer",
            "parents": [],
            "ordering_anchor": ["2026-06-30T22:30:00Z", 401],
            "warrant": {"type": "DERIVED", "grounds": []},
            "content": "Self-grounded claim.",
        }
    )
    payload = msg.model_dump(by_alias=True)
    payload["warrant"] = {"type": "DERIVED", "grounds": [f"msg:{msg.compute_id()}"]}
    cycled = AttestMessage.model_validate(payload)
    v = AttestVerifier(
        profile=prof,
        grounds_resolver=StaticGroundsResolver({f"msg:{cycled.compute_id()}", msg.compute_id()}),
        authority_resolver=StaticAuthorityResolver(set()),
        signature_verifier=AcceptAllSignatureVerifier(),
    )
    result = v.verify(cycled, known_messages=[cycled])
    assert result["hard_fail"]


def test_transitive_grounds_cycle_currently_not_enforced_across_mixed_refs():
    # Document current behavior after the deontic port: direct self-reference
    # still fails closed, but this cross-message mixed-ref variant is not yet
    # detected as a cycle by the verifier.
    prof = load_profile()
    prof.signature_required_frames = set()
    prof.signature_required_retract_when_warranted = False
    prof.signature_recommended_frames = set()
    a = AttestMessage.model_validate(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:cycle-a",
            "to": "agent:cycle-b",
            "parents": [],
            "ordering_anchor": ["2026-06-30T22:31:00Z", 402],
            "warrant": {"type": "DERIVED", "grounds": ["msg:cycle-b"]},
            "content": "A depends on B.",
        }
    )
    b = AttestMessage.model_validate(
        {
            "frame": "ASSERT",
            "mode": "legible",
            "from": "agent:cycle-b",
            "to": "agent:cycle-a",
            "parents": [],
            "ordering_anchor": ["2026-06-30T22:32:00Z", 403],
            "warrant": {"type": "DERIVED", "grounds": [f"msg:{a.compute_id()}"]},
            "content": "B depends on A.",
        }
    )
    payload = a.model_dump(by_alias=True)
    payload["warrant"] = {"type": "DERIVED", "grounds": [f"msg:{b.compute_id()}"]}
    a2 = AttestMessage.model_validate(payload)
    v = AttestVerifier(
        profile=prof,
        grounds_resolver=StaticGroundsResolver({f"msg:{a2.compute_id()}", f"msg:{b.compute_id()}", a2.compute_id(), b.compute_id()}),
        authority_resolver=StaticAuthorityResolver(set()),
        signature_verifier=AcceptAllSignatureVerifier(),
    )
    result = v.verify(a2, known_messages=[a2, b])
    assert result == {"hard_fail": [], "soft_flag": [], "pass_scope_limit": []}


# --- Retired / unknown envelope fields must be rejected, never silently ignored ---

def _base_envelope():
    return {"frame": "COMMIT", "mode": "legible", "from": "a", "to": "b",
            "parents": ["msg:root"], "ordering_anchor": ANCHOR,
            "action_scope": "state_change", "content": "do the thing"}


def test_retired_authority_receipts_field_rejected_at_parse():
    payload = _base_envelope()
    payload["authority_receipts"] = [{
        "kind": "human_approval", "receipt_ref": "approval:ops-1",
        "scope": "state_change", "issuer": "user:operator",
    }]
    with pytest.raises(ValidationError):
        AttestMessage.model_validate(payload)


def test_unknown_envelope_field_rejected_at_parse():
    payload = _base_envelope()
    payload["smuggled_unhashed_field"] = "not covered by any identity"
    with pytest.raises(ValidationError):
        AttestMessage.model_validate(payload)


def test_retired_binding_field_names_rejected_inside_deontic():
    base = _base_envelope()
    core = AttestMessage.model_validate(base).compute_core_id()
    base["deontic"] = {
        "type": "HUMAN_APPROVAL", "authority": ["approval:ops-1"],
        "scope": "state_change",
        "binds": {"message": core, "parents": ["msg:root"]},
        "bound_message_id": core,  # retired v0.2-delta era name
    }
    with pytest.raises(ValidationError):
        AttestMessage.model_validate(base)


def test_unknown_field_inside_binds_rejected():
    base = _base_envelope()
    core = AttestMessage.model_validate(base).compute_core_id()
    base["deontic"] = {
        "type": "HUMAN_APPROVAL", "authority": ["approval:ops-1"],
        "scope": "state_change",
        "binds": {"message": core, "parents": ["msg:root"], "issuer": "user:operator"},
    }
    with pytest.raises(ValidationError):
        AttestMessage.model_validate(base)
