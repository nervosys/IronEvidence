# Changelog

## Unreleased

- Output now validates against NIST's OSCAL 1.1.2 component-definition JSON
  schema; `scripts/check-oscal-schema.py` and CI check it. UUIDs must be
  version 4 or 5, as OSCAL requires.
- Added `Status::Unmet`, written as `not-implemented`, so an unmet control is
  never rendered as planned.
- Scaffolded IronEvidence: workspace, licence, CI, dependency policy, the initial
  types and the design notes in `docs/`. Not published.
