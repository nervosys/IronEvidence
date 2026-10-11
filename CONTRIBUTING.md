# Contributing to IronEvidence

## Before anything else

- **Licensing.** Contributions are accepted under the
  [Contributor License Agreement](CLA.md), so they can be distributed under
  both the AGPL v3 and the commercial licence
  ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). Opening a pull request
  indicates agreement; your commit name and email serve as the signature.
- **Security issues** are reported privately: see [SECURITY.md](SECURITY.md).

## Rules

- IronCrypto is the only dependency. `scripts/check-first-party-only.py`
  fails on anything else.
- No `unsafe` code, and nothing panics on input. Return an error.
- Nothing is fetched. Mappings and schemas come from the caller.
- Output says only what its source says. A control a component bears on is
  not a control it satisfies; a gap stays a gap. An input that claims FIPS
  validation is refused.
- Output validates against NIST's published OSCAL schema; see the README for
  the check.
- Break the thing and confirm the test fails. A test that passes on broken
  code verified nothing.

## Before you open a pull request

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-features
$ python scripts/check-first-party-only.py --all-features
```

Never claim FIPS 140-3 validation or an independent review, in code,
documentation or commit messages. Neither exists.
