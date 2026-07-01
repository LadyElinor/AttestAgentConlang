# Attest spec/implementation gap ledger

This ledger is the single authoritative record of known divergences between `attest-spec.md` and `attest_ref_impl.py`. Its purpose is to prevent silent deviation: the implementation may be a conservative subset of the spec, or temporarily stricter than the spec, only if the divergence is recorded here. A divergence absent from this ledger is a defect, not a design decision.

Status vocabulary: **OPEN** (divergence exists), **RESOLVED** (spec and impl reconciled; entry retained for history).

---

## G-1. Delegation strength ceiling not enforced — OPEN

- **Spec:** §8A.5 requires that the effective *scope and strength* of `DELEGATED` authority not exceed what the delegating principal held.
- **Impl:** `_walk_delegation` enforces the scope ceiling only. `AuthorityResolution` carries no strength field, so a chain can launder a weak root into a strong effective authority without detection.
- **Consequence:** strength-ceiling violations pass verification.
- **Remediation:** add `granted_strength` (or grant type, mapped through the profile's authority-strength lattice, §8A.2.1) to `AuthorityResolution`; enforce minimum-of-chain per §8A.2.1; add named failure (proposed `DELEGATION_STRENGTH_EXCEEDED`).

## G-2. Grant-level expiry not checked along delegation chains — OPEN

- **Spec:** §8A.7.6 requires expiry to be enforced where present. An expired delegating grant cannot confer live authority.
- **Impl:** only the top-level warrant's `expires` is checked. `AuthorityResolution` has no expiry field, so an expired intermediate grant passes.
- **Remediation:** add `expires` to `AuthorityResolution`; check at each hop of `_walk_delegation` against the evaluation time (see G-4).

## G-3. Expiry hard-fails unconditionally; replay not detected — OPEN

- **Spec:** §8A.7.6 makes expired or replayed authority *malformed only where a trusted ordering authority exists*; without one, expiry and replay degrade to a soft audit signal (consistent with the retract-ordering limit, §18).
- **Impl:** `AUTHORITY_EXPIRED` is emitted as a hard failure unconditionally, and nonce handling checks presence only — there is no replay cache, so a replayed nonce is never detected.
- **Consequence:** two verifiers, both plausibly "conformant", disagree on the same message: this implementation hard-fails what the spec classifies as soft in ordering-authority-free deployments. Stricter-than-spec is still an interop divergence.
- **Remediation:** gate hard-vs-soft expiry classification on a profile flag declaring a trusted ordering authority; either implement a bounded replay cache behind the same flag or record replay detection as explicitly delegated (out of the reference verifier's scope), in the README's implemented-vs-delegated list.

## G-4. Verification is wall-clock-dependent — OPEN

- **Spec:** verification verdicts should be reproducible receipts; nothing in the spec licenses an implicit, unrecorded input.
- **Impl:** `_authority_unexpired` calls `datetime.now(timezone.utc)` internally. The same message can verify differently on different days with no record of the evaluation time, so a verdict cannot be deterministically replayed.
- **Remediation:** `verify()` accepts an optional `at:` timestamp (default: now), and the verdict records the evaluation time used. Expiry tests then become time-bomb-free by construction.

## G-5. Covering-binding clause unimplemented (conservative subset) — OPEN, documented

- **Spec:** §8A.4 permits `binds.message` to be "establishable as covering" the message, e.g. an approval issued against the adopted-chain root the message derives from.
- **Impl:** `_deontic_binds` requires exact core-ID equality and exact `parents` equality. Chain-root covering is rejected.
- **Classification:** acceptable as a conservative subset — everything the impl accepts, the spec accepts; not vice versa. Recorded here so the deviation is explicit rather than silent. Any future covering implementation must define "establishable" mechanically (adopted-chain walk with the same cycle/ancestry checks as §8A.5) before landing.

## G-6. Delegation error reporting is short-circuiting — OPEN, minor

- **Impl:** `_walk_delegation` aggregates branches with `all(...)`, which short-circuits: after the first failing branch, remaining branches are unexplored. Verdicts are correct; error lists on multi-branch failures are incomplete.
- **Remediation:** evaluate all branches before combining, if complete failure enumeration is wanted for audit.

---

## Resolved in this change set

## G-7. Core-ID / binding circularity — RESOLVED

- **Was:** §8A.4 required `binds.message` to equal "the message's own computed ID" while §10.2/§8A.7.7 made the deontic object identity-bearing — jointly unimplementable. The impl bound to a deontic-excluded core digest the spec never defined.
- **Now:** §10.2.1 normatively defines the core ID, its role split against the full message ID, and the prohibitions in each direction. §8A.4 binds to the core ID and states the non-circularity rationale. Delta §1.4 reconciled to migrated field names.

## G-8. Retired `authority_receipts` silently ignored — RESOLVED

- **Was:** envelope models used pydantic's default `extra="ignore"`; the serialized corpus (Cases 4, 13) still carried `authority_receipts`, and the harness overwrote those cases with programmatically built `deontic` objects — the document displayed one envelope while the harness tested another.
- **Now:** all envelope models (`AttestMessage`, `Warrant`, `DeonticWarrant`, `DeonticBinding`) are `extra="forbid"`; the corpus carries the real `deontic` envelopes with frozen, deterministically computed core-ID bindings; the harness injection code is deleted so the corpus is the tested artifact; four regression tests assert that retired and unknown fields are rejected at parse time, at the envelope, deontic, and binds levels.

## G-9. `general` scope coverage semantics undefined — RESOLVED

- **Was:** the impl treated `general` as covering every `action_scope`; the spec listed `general` in the ontology without defining coverage.
- **Now:** §8A.6 defines `general` as the top element, exact match otherwise, and requires extended ontologies to publish their partial order.

## G-10. README crypto claim drift — RESOLVED

- **Was:** README claimed conformance examples "in deterministic test-vector form, not yet real Ed25519" while the harness generated a fresh Ed25519 key per run — real Ed25519 verification, and not deterministic.
- **Now:** README states the accurate position: runtime-generated Ed25519 signature round-trips exist; fixed cross-implementation interop vectors do not yet.
