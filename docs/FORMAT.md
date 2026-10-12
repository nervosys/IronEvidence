# The control-mappings file: `ironsecurity-controls/1`

A project in the IronSecurity stack states how it stands against controls in
one JSON file in its own repository. IronEvidence reads the file with
`ironevidence::controls::Mappings` and writes it as an OSCAL component.

IronCrypto is the exception: it publishes its mappings through
`ic ontology controls --json`, in its own schema (`ironcrypto-controls/1`),
which `ironevidence::ironcrypto` reads.

No project ships a file in this form yet. `tests/data/example-controls.json`
is a fictional example used by the tests.

## Who writes it

The project's maintainers. Every entry is the project's claim about itself,
and IronEvidence passes it on without raising it. Keep the file beside the
code, review changes to it as code is reviewed, and keep `version` in step
with the release it describes.

## Shape

```json
{
  "schema": "ironsecurity-controls/1",
  "project": "Example Project",
  "description": "What the project is, in a sentence or two.",
  "version": "1.2.3",
  "fipsValidated": false,
  "controls": [
    {
      "framework": "sp800-53",
      "id": "SC-12(2)",
      "title": "Cryptographic Key Establishment and Management | Symmetric Keys",
      "bearing": "Keys are generated and wrapped by the project.",
      "compliance": {
        "state": "partial",
        "evidence": ["src/keys.rs"],
        "gap": "Key generation does not use a validated module."
      }
    }
  ]
}
```

| Member | Meaning |
| --- | --- |
| `schema` | Exactly `ironsecurity-controls/1` |
| `project` | The project's name. One file per project: two files with one name cannot go in one document |
| `description` | What the project is |
| `version` | The project version the statements are true of |
| `fipsValidated` | Must be `false`. No project in the stack is FIPS 140 validated; a file that says otherwise, or omits the member, is refused |
| `controls` | The statements, in the order they should appear |

Each control:

| Member | Meaning |
| --- | --- |
| `framework` | `sp800-53` (NIST SP 800-53 Rev. 5) or `cmmc` (CMMC 2.0, NIST SP 800-171 Rev. 2). Weakness and technique lists such as CWE and ATT&CK are not controls and are refused |
| `id` | The control as the framework writes it. SP 800-53: `SC-13`, `SC-12(2)`. CMMC: the practice identifier, `SC.L2-3.13.11`. It must start with a letter and hold only letters, digits, `.`, `-` and `_`, because OSCAL carries it as a token; a bare `3.13.11` is refused |
| `title` | The control's title |
| `bearing` | How the control bears on this project at all. It opens the statement, so write it to stand alone |
| `compliance` | Where the project stands; see below |

A control may appear once per framework.

## States

| `state` | Also required | Written as |
| --- | --- | --- |
| `met` | `evidence` | `implemented` |
| `partial` | `evidence`, `gap` | `partial`, with the gap in the statement |
| `unmet` | `reason` | `not-implemented`, with the reason |
| `not-applicable` | `reason` | `not-applicable`, with the reason |

`evidence` is a non-empty list of repository paths or URLs that show the part
that is met. `gap` says what is not met; a partial without one is refused,
because it would read as something stronger. There is no `planned` state: a
control the project does not meet is `unmet` until it does.

## Rules the reader enforces

- "Met" is about the project's part of a control, never about a system. The
  component's description says so, and says the project is not FIPS 140
  validated.
- A control that needs a FIPS 140 validated module (SP 800-53 SC-13, CMMC
  SC.L2-3.13.11) is `unmet` for every project in the stack. The reader cannot
  check that an entry is honest; it refuses only a file that claims
  validation outright.
- Unknown members are ignored. Missing or empty required members are refused.

## Writing the document

```text
ironevidence component --ironcrypto controls.json --source ipg-controls.json \
    --last-modified 2026-10-10T00:00:00Z --output stack.json
```

Each source becomes one component, IronCrypto's first and the rest in the
order given. Identifiers are derived from the project name, framework and
control, so they are the same on every run.
