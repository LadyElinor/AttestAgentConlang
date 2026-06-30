# Attest v0.2 Delta Plan

This document separates three layers of change so Attest can evolve without mixing wire-format semantics, deployment policy, and local verifier behavior.

## 1. Protocol changes

### 1.1 Normative canonicalization
Attest v0.2 should replace draft-level canonicalization guidance with a precise interoperable rule set.

Required clarifications:
- omitted fields versus explicit `null`
- Unicode normalization form
- scalar and numeric encoding rules
- list-order preservation rules
- canonical field ordering
- canonical byte examples with golden test vectors

### 1.2 First-class deployment profile artifact
Profiles should become first-class protocol artifacts rather than remaining mostly implementation-side objects.

A profile artifact should declare at minimum:
- `profile_id`
- `profile_version`
- warrant-strength lattice
- signature requirements by frame class
- authority requirements by frame class
- resolver policy and supported grounds namespaces
- ordering-anchor comparison semantics
- independence policy label

### 1.3 Grounds namespace and resolver contract
Attest v0.2 should define reference classes and minimum verifier behavior.

Suggested namespaces:
- `msg:` message IDs
- `tool:` tool-call receipts
- `src:` external source citations
- `doc:` document anchors
- `receipt:` authority or execution receipts
- `policy:` local policy artifacts

Suggested verifier outcomes:
- resolved
- unresolved
- stale
- syntactically malformed
- inaccessible-under-profile

### 1.4 Authority receipt binding
Authority receipts should bind not just to generic approval class, but to the concrete state-changing reliance context.

Suggested binding fields:
- `bound_message_id`
- `bound_parent_ids` or adopted-chain root
- `scope`
- `issuer`
- optional `expires_at`
- optional nonce or approval token

### 1.5 Dissent-layer split
Attest v0.2 should explicitly distinguish:
- dissent-presence preservation, artifact-local and sometimes hard-checkable
- dissent-faithfulness preservation, semantic and soft

## 2. Default-profile changes

### 2.1 Signature policy
The default profile should continue to require signatures for reliance-bearing `ASSERT`, `ENDORSE`, `DISSENT`, and evidential `RETRACT`, while keeping evidence-bearing `COMMIT` at recommended or required depending on deployment risk.

### 2.2 Authority policy
The default profile should explicitly declare which frame classes require local authority receipts and how authority can be proven without laundering external evidence into local authorization.

### 2.3 Resolver policy
The default profile should declare which grounds namespaces are accepted and whether unresolved grounds hard-fail, soft-flag, or remain profile-unsupported.

## 3. Reference implementation changes

### 3.1 Canonicalization implementation
Move the reference implementation closer to a real canonicalization target with explicit tests and cross-language reproducibility fixtures.

### 3.2 Signed conformance vectors
Add real Ed25519 test vectors:
- valid signature over canonical bytes
- invalid signature with unchanged bytes
- valid signature over differently serialized but canonically equivalent payload
- wrong-key verification failure

### 3.3 Harness split
Keep two harness classes:
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
Narrative artifacts such as `attest.txt` should be rewritten to match the narrower, more honest scope already present in the spec and review notes.

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
