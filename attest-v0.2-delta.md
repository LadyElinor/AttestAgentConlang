# Attest v0.2 Delta Plan

This document separates three layers of change so Attest can evolve without mixing wire-format semantics, deployment policy, and local verifier behavior.

## 1. Protocol changes

### 1.1 Normative canonicalization
Attest v0.2 should replace draft-level canonicalization guidance with a precise interoperable rule set.

Implemented in the reference model now:
- explicit canonical field ordering
- NFC normalization
- deterministic JSON encoding with `allow_nan=False`

Still needed for a stronger v0.2 claim:
- numeric cross-language golden vectors
- explicit omitted-versus-null compatibility rules in the normative spec text

### 1.2 First-class deployment profile artifact
Profiles are now represented as first-class artifacts in draft form.

A profile artifact should declare at minimum:
- `profile_id`
- `profile_version`
- warrant-strength lattice
- signature requirements by frame class
- authority requirements by frame class
- resolver policy and supported grounds namespaces
- ordering-anchor comparison semantics
- independence policy label
- signer public keys or key-discovery indirection where deployments allow it

### 1.3 Grounds namespace and resolver contract
Attest now defines reference classes and minimum verifier behavior in the reference implementation.

Current namespaces:
- `msg:` message IDs
- `tool:` tool-call receipts
- `src:` external source citations
- `doc:` document anchors
- `receipt:` authority or execution receipts
- `policy:` local policy artifacts
- `h:` legacy content-addressed message identifiers

Current resolution outcomes:
- resolved
- unresolved
- stale
- malformed
- inaccessible-under-profile

### 1.4 Deontic warrant binding (formerly "authority receipts")
The `authority_receipts` array is retired. Authorization is carried by the `deontic` object (spec §8A), which binds not just to a generic approval class but to the concrete state-changing reliance context.

Current binding fields, under migrated names:
- `binds.message` (bound to the deontic-excluded core ID, spec §10.2.1, to avoid self-reference loops)
- `binds.parents`
- `scope` (must cover the message's `action_scope`, spec §8A.6)
- `expires`, optional
- `nonce`, required under current reference behavior for authority-required frames

Issuer identity now lives in the resolved authority artifact rather than the envelope. Envelopes carrying the retired `authority_receipts` field are rejected at parse time; retired fields are never silently ignored.

### 1.5 Dissent-layer split
Attest v0.2 distinguishes:
- dissent-presence preservation, artifact-local and sometimes hard-checkable
- dissent-faithfulness preservation, semantic and soft

The generic verifier no longer contains the old example-specific dissent oracle.

## 2. Default-profile changes

### 2.1 Signature policy
The default profile continues to require signatures for reliance-bearing `ASSERT`, `ENDORSE`, `DISSENT`, and evidential `RETRACT`, while keeping evidence-bearing `COMMIT` at recommended status in the draft default profile.

### 2.2 Authority policy
The default profile explicitly declares which frame classes require local authority receipts and how authority can be proven without laundering external evidence into local authorization.

### 2.3 Resolver policy
The default profile now carries a `grounds_resolution_policy` block that is consumed by the reference verifier instead of ignored.

## 3. Reference implementation changes

### 3.1 Canonicalization implementation
The reference implementation moved closer to a real canonicalization target with explicit tests and cross-case reproducibility checks.

### 3.2 Signed conformance vectors
The reference repo now includes real Ed25519 signing and verification tests using PyNaCl-backed vectors in the harness and pytest suite.

Still recommended next additions:
- wrong-key verification failure vector
- same-logical-message / alternate-source-serialization vector
- invalid-signature corruption vector

### 3.3 Harness split
Two harness classes remain useful:
- semantic/non-crypto fixture harness for protocol logic
- crypto conformance harness for real signing/verification vectors

### 3.4 Output taxonomy
Verifier outputs should distinguish:
- hard structural failure
- hard integrity/authentication failure
- soft dissent-faithfulness concern
- soft independence concern
- scope-limit / visibility-limit note

## 4. Documentation changes

### 4.1 Pitch reconciliation
Narrative artifacts such as `attest.txt` have been rewritten to match the narrower, more honest scope already present in the spec and review notes.

### 4.2 Layer separation
Repository docs should distinguish clearly between:
- protocol semantics
- default profile semantics
- reference implementation behavior
- research notes and design rationale

## 5. Suggested execution order
1. normative canonicalization
2. deployment profile artifact
3. grounds namespace and resolver contract
4. tighter authority receipt binding
5. real signed test vectors
6. dissent-layer split in examples and verifier outputs
7. pitch/document reconciliation

## 6. Newly verified hardening pass
The current reference implementation now additionally enforces:
- real authority resolution instead of prefix-only authorization
- mandatory authority binding for authority-required frames
- expiry and nonce checks for local authority receipts
- ordering-aware, ancestry-walking retract checks
- consumed grounds-resolution policy instead of decorative profile drift
- removal of the generic example-specific dissent oracle from verifier logic
