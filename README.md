# AttestAgentConlang

Attest is a draft typed, auditable inter-agent message protocol focused on preserving warrant, lineage, and trust-boundary semantics.

This repository contains:
- `attest-spec.md` - current protocol draft
- `attest-adversarial-corpus.md` - adversarial and boundary-case corpus
- `attest_ref_impl.py` - Python reference verifier skeleton
- `attest_test_harness.py` - example-driven regression harness
- `attest-serialized-examples.md` - serialized example cases used by the harness

## Status

This is a draft research/prototyping repo, not a production security library.

The current verifier is intentionally explicit about what is implemented vs delegated:
- grounds resolution is supplied by a resolver interface
- signature verification is supplied by a verifier interface
- deployment policy is profile-driven

## Quick start

```bash
python -m pip install -e .
python attest_test_harness.py
```

## License

MIT
