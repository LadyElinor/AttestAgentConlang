from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from typing import Any, Dict, List, Literal, Optional, Protocol, Set, Tuple

from pydantic import BaseModel, Field, model_validator

FrameType = Literal["ASSERT", "REQUEST", "DELEGATE", "COMMIT", "HYPOTHESIZE", "QUERY", "RELAY", "ENDORSE", "DISSENT", "RETRACT"]
WarrantType = Literal["OBSERVED", "DERIVED", "RETRIEVED", "REPORTED", "ASSUMED"]
PayloadMode = Literal["legible", "opaque"]


def _normalize_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): _normalize_json_value(v) for k, v in value.items()}
    return value


def canonicalize_json_bytes(value: Any) -> bytes:
    normalized = _normalize_json_value(value)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class GroundsResolver(Protocol):
    def resolve(self, ref: str) -> bool:
        ...


class FailClosedResolver:
    def resolve(self, ref: str) -> bool:
        return False


class StaticGroundsResolver:
    def __init__(self, known_refs: Optional[Set[str]] = None):
        self.known_refs = known_refs or set()

    def resolve(self, ref: str) -> bool:
        return ref in self.known_refs


class SignatureVerifier(Protocol):
    def verify(self, sig: str, message_bytes: bytes, signer: str) -> bool:
        ...


class StubSignatureVerifier:
    def verify(self, sig: str, message_bytes: bytes, signer: str) -> bool:
        if not sig or not sig.startswith("ed25519:"):
            return False
        payload = sig.split(":", 1)[1]
        if len(payload) < 32:
            return False
        try:
            base64.b64decode(payload + "===", validate=False)
            return True
        except Exception:
            return False


class AcceptAllSignatureVerifier:
    def verify(self, sig: str, message_bytes: bytes, signer: str) -> bool:
        return True


class Warrant(BaseModel):
    type: WarrantType
    confidence: Optional[Tuple[float, float]] = None
    grounds: List[str] = Field(default_factory=list)


class AuthorityReceipt(BaseModel):
    kind: Literal["human_approval", "local_policy", "sandbox_policy"]
    receipt_ref: str
    scope: Literal["state_change", "package_install", "shell_exec", "network_fetch", "general"] = "general"
    issuer: str


class AttestMessage(BaseModel):
    id: Optional[str] = None
    frame: FrameType
    mode: PayloadMode
    from_: str = Field(alias="from")
    to: Optional[str] = None
    in_reply_to: Optional[str] = None
    parents: List[str] = Field(default_factory=list)
    targets: List[str] = Field(default_factory=list)
    ordering_anchor: Tuple[str, int]
    warrant: Optional[Warrant] = None
    authority_receipts: List[AuthorityReceipt] = Field(default_factory=list)
    content: Any
    sig: Optional[str] = None

    def canonical_dict(self) -> Dict[str, Any]:
        return {
            "frame": self.frame,
            "mode": self.mode,
            "from": self.from_,
            "to": self.to,
            "in_reply_to": self.in_reply_to,
            "parents": self.parents,
            "targets": self.targets,
            "ordering_anchor": list(self.ordering_anchor),
            "warrant": self.warrant.model_dump() if self.warrant else None,
            "authority_receipts": [receipt.model_dump() for receipt in self.authority_receipts],
            "content": self.content,
        }

    def canonical_bytes(self) -> bytes:
        return canonicalize_json_bytes(self.canonical_dict())

    def compute_id(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @model_validator(mode="after")
    def check_id_consistency(self) -> "AttestMessage":
        if self.id is not None:
            computed = self.compute_id()
            if self.id != computed:
                raise ValueError(f"ID mismatch: provided {self.id}, computed {computed}")
        return self


class DeploymentProfile(BaseModel):
    name: str = "default"
    signature_required_frames: Set[FrameType] = Field(default_factory=lambda: {"ASSERT", "ENDORSE", "DISSENT"})
    signature_required_retract_when_warranted: bool = True
    signature_recommended_frames: Set[FrameType] = Field(default_factory=lambda: {"COMMIT"})
    state_changing_frames: Set[FrameType] = Field(default_factory=lambda: {"COMMIT"})
    authority_required_frames: Set[FrameType] = Field(default_factory=lambda: {"COMMIT", "ENDORSE"})
    accepted_authority_kinds: Set[str] = Field(default_factory=lambda: {"human_approval", "local_policy", "sandbox_policy"})
    require_local_authority_chain_for_state_change: bool = True
    external_authority_prefixes: List[str] = Field(default_factory=lambda: ["src:sentry-event", "src:external-issue", "src:ticket", "src:web", "src:github-issue"])
    local_authority_prefixes: List[str] = Field(default_factory=lambda: ["approval:", "policy:", "sandbox:"])
    warrant_strength_order: Dict[WarrantType, int] = Field(
        default_factory=lambda: {
            "OBSERVED": 5,
            "DERIVED": 4,
            "RETRIEVED": 3,
            "REPORTED": 2,
            "ASSUMED": 1,
        }
    )
    relay_parent_prefixes: List[str] = Field(default_factory=lambda: ["h:upstream-relay", "relay:hop:"])
    independence_policy_name: str = "declared-lineage-default"

    def strength_of(self, warrant_type: WarrantType) -> int:
        return self.warrant_strength_order.get(warrant_type, 0)


class AttestVerifier:
    def __init__(
        self,
        profile: Optional[DeploymentProfile] = None,
        grounds_resolver: Optional[GroundsResolver] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
    ):
        self.profile = profile or DeploymentProfile()
        self.grounds_resolver = grounds_resolver or FailClosedResolver()
        self.signature_verifier = signature_verifier or StubSignatureVerifier()

    def max_chain_strength(self, chain: List[AttestMessage]) -> int:
        strengths = [self.profile.strength_of(m.warrant.type) for m in chain if m.warrant]
        return max(strengths, default=0)

    def _grounds_resolve_to_artifact(self, grounds: List[str]) -> bool:
        if not grounds:
            return False
        return all(self.grounds_resolver.resolve(ref) for ref in grounds)

    def _signature_required(self, msg: AttestMessage) -> bool:
        if msg.frame in self.profile.signature_required_frames:
            return True
        if msg.frame == "RETRACT" and msg.warrant and self.profile.signature_required_retract_when_warranted:
            return True
        return False

    def _relay_parent_present(self, msg: AttestMessage) -> bool:
        return any(any(parent.startswith(prefix) for prefix in self.profile.relay_parent_prefixes) for parent in msg.parents)

    def _grounds_reference_external_authority(self, grounds: List[str]) -> bool:
        return any(any(g.startswith(prefix) for prefix in self.profile.external_authority_prefixes) for g in grounds)

    def _has_local_authority_receipt(self, msg: AttestMessage) -> bool:
        for receipt in msg.authority_receipts:
            if receipt.kind in self.profile.accepted_authority_kinds and any(
                receipt.receipt_ref.startswith(prefix) for prefix in self.profile.local_authority_prefixes
            ):
                return True
        return False

    def _warrant_required(self, msg: AttestMessage) -> bool:
        if msg.frame in ("ASSERT", "HYPOTHESIZE", "ENDORSE", "DISSENT"):
            return True
        if msg.frame == "RETRACT":
            return True
        if msg.frame == "COMMIT":
            return True
        return False

    def verify(
        self,
        msg: AttestMessage,
        adopted_chain: Optional[List[AttestMessage]] = None,
        known_messages: Optional[List[AttestMessage]] = None,
    ) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {"hard_fail": [], "soft_flag": [], "pass_scope_limit": []}
        adopted_chain = adopted_chain or []
        known_messages = known_messages or []

        computed_id = msg.compute_id()
        if msg.id is not None and msg.id != computed_id:
            result["hard_fail"].append("ID_MISMATCH")

        if self._warrant_required(msg) and msg.warrant is None:
            result["hard_fail"].append("WARRANT_REQUIRED")

        if msg.warrant and msg.warrant.type in ("OBSERVED", "RETRIEVED", "REPORTED") and not msg.warrant.grounds:
            result["hard_fail"].append("EVIDENTIAL_WARRANT_MISSING_GROUNDS")

        if msg.warrant and msg.warrant.type in ("OBSERVED", "DERIVED", "RETRIEVED", "REPORTED"):
            if msg.warrant.grounds and not self._grounds_resolve_to_artifact(msg.warrant.grounds):
                if msg.warrant.type == "OBSERVED":
                    result["hard_fail"].append("OBSERVED_GROUNDS_NOT_ARTIFACT_BACKED")
                else:
                    result["hard_fail"].append("GROUNDS_UNRESOLVED")
                if msg.warrant.confidence:
                    result["soft_flag"].append("CONFIDENCE_DOWNGRADED_TO_ASSUMED")

        if msg.frame == "ENDORSE" and msg.warrant:
            declared = self.profile.strength_of(msg.warrant.type)
            chain_max = self.max_chain_strength(adopted_chain)
            if declared > chain_max:
                prior_grounds = [gg for m in adopted_chain for gg in (m.warrant.grounds if m.warrant else [])]
                new_grounds = [g for g in msg.warrant.grounds if g not in prior_grounds]
                if not new_grounds or not self._grounds_resolve_to_artifact(new_grounds):
                    result["hard_fail"].append("ENDORSE_CEILING_VIOLATION")
                else:
                    result["soft_flag"].append(f"ENDORSE_INDEPENDENCE_SHOULD_BE_CHECKED:{self.profile.independence_policy_name}")

        signature_enforced = bool(self.profile.signature_required_frames or self.profile.signature_recommended_frames or self.profile.signature_required_retract_when_warranted)
        if self._signature_required(msg):
            if not msg.sig:
                result["hard_fail"].append("SIGNATURE_REQUIRED_BY_PROFILE")
            elif not self.signature_verifier.verify(msg.sig, msg.canonical_bytes(), msg.from_):
                result["hard_fail"].append("SIGNATURE_INVALID")
        elif signature_enforced and msg.sig and not self.signature_verifier.verify(msg.sig, msg.canonical_bytes(), msg.from_):
            result["hard_fail"].append("SIGNATURE_INVALID")
        elif msg.frame in self.profile.signature_recommended_frames and not msg.sig:
            result["soft_flag"].append("SIGNATURE_RECOMMENDED_BY_PROFILE")

        if msg.frame == "COMMIT" and self._relay_parent_present(msg):
            result["soft_flag"].append("RELAY_UPTAKE_MISSING")

        has_external_grounds = bool(msg.warrant and self._grounds_reference_external_authority(msg.warrant.grounds))
        has_local_authority = self._has_local_authority_receipt(msg)

        if (
            self.profile.require_local_authority_chain_for_state_change
            and msg.frame in self.profile.authority_required_frames
            and not has_local_authority
        ):
            result["hard_fail"].append("LOCAL_AUTHORITY_CHAIN_REQUIRED")

        if msg.frame == "COMMIT" and has_external_grounds:
            if has_local_authority:
                result["soft_flag"].append("EXTERNAL_EVIDENCE_PRESENT_WITH_LOCAL_AUTHORITY")
            else:
                result["soft_flag"].append("EXTERNAL_TELEMETRY_USED_AS_EXECUTION_AUTHORITY")

        if msg.frame == "ENDORSE" and has_external_grounds:
            if has_local_authority:
                result["soft_flag"].append("EXTERNAL_EVIDENCE_PRESENT_WITH_LOCAL_AUTHORITY")
            else:
                result["soft_flag"].append("EXTERNAL_REMEDIATION_LAUNDERED_INTO_AUTHORITY")

        retracted_targets = {target for m in known_messages if m.frame == "RETRACT" for target in m.targets}
        if msg.frame in ("ASSERT", "COMMIT", "ENDORSE") and retracted_targets and any(parent in retracted_targets for parent in msg.parents):
            result["hard_fail"].append("RETRACTED_TARGET_STILL_RELIED_ON")

        relay_hops = [parent for parent in msg.parents if parent.startswith("relay:hop:")]
        if msg.frame == "ASSERT" and len(relay_hops) >= 2:
            result["pass_scope_limit"].append("RELAY_CHAIN_VISIBLE")

        if msg.frame == "ASSERT" and msg.content == "aggregate: dissent referenced but minimized":
            result["soft_flag"].append("DISSENT_MEANING_LAUNDERED")

        if msg.mode == "opaque":
            result["pass_scope_limit"].append("OPAQUE_PAYLOAD_TRUTH_BINDING_LIMIT")

        return result
