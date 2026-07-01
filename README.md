# AttestAgentConlang

Attest is a draft typed, auditable inter-agent message protocol focused on preserving warrant, lineage, and trust-boundary semantics.

## Current direction

Attest is being tightened toward a more portable and verifiable v0.2 shape.
The main priorities are:
- normative canonicalization
- first-class deployment profile artifacts
- first-class grounds namespace and resolver contracts
- tighter authority receipt binding
- signed conformance vectors
- clearer dissent-layer split between presence and faithfulness
- pitch and documentation reconciliation

## Repository contents

- `attest-spec.md` - current protocol draft
- `attest-v0.2-delta.md` - protocol/profile/implementation split for the next revision
- `attest-profile-default-v02.json` - draft default deployment profile artifact
- `attest-adversarial-corpus.md` - adversarial and boundary-case corpus
- `attest_ref_impl.py` - Python reference verifier skeleton
- `attest_test_harness.py` - example-driven regression harness
- `attest-serialized-examples.md` - serialized example cases used by the harness
- `tests/test_properties.py` - property and regression tests
- `attest.txt` - concise high-level project description aligned to current scope
- `attest-gap-ledger.md` - authoritative record of known spec/implementation divergences

## Status

This is a draft research/prototyping repo, not a production security library.

The reference implementation is explicit about what is implemented versus delegated:
- canonical bytes are computed locally and deterministically
- grounds resolution is supplied by a resolver interface
- signature verification is supplied by a verifier interface
- deployment policy is profile-driven and now has a draft artifact form
- signature verification uses real Ed25519 (PyNaCl) with a per-run generated key in the harness; fixed cross-implementation interop vectors do not yet exist

## Quick start

```bash
python -m pip install -e .
python attest_test_harness.py
python -m pytest -q
```

## License

MIT
