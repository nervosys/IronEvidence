"""Validate an OSCAL component definition against NIST's JSON schema.

Usage: check-oscal-schema.py <oscal_component_schema.json> <document.json>

The schema is NIST's `oscal_component_schema.json` for the OSCAL version in
`ironevidence::OSCAL_VERSION`, from https://github.com/usnistgov/OSCAL/releases.
It is not bundled; download it and pass its path. Needs the `jsonschema`
package (test tooling only).

The schema's patterns use Unicode classes that Python's `re` lacks. They are
narrowed to ASCII letters and digits, which is stricter: a document that passes
here passes the real pattern.
"""
import json
import sys

import jsonschema

BACKSLASH = chr(92)


def narrow(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                value = value.replace(BACKSLASH + "p{L}", "[A-Za-z]")
                value = value.replace(BACKSLASH + "p{N}", "[0-9]")
                if BACKSLASH + "p{" in value:
                    raise SystemExit(f"unhandled Unicode class in pattern: {value}")
                node[key] = value
            else:
                narrow(value)
    elif isinstance(node, list):
        for item in node:
            narrow(item)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as handle:
        schema = json.load(handle)
    with open(sys.argv[2], encoding="utf-8") as handle:
        document = json.load(handle)
    narrow(schema)
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    for error in errors:
        print("/".join(str(p) for p in error.path), "-", error.message[:300])
    print(json.dumps({"ok": not errors, "errors": len(errors),
                      "schema": schema.get("$id")}))
    raise SystemExit(bool(errors))


if __name__ == "__main__":
    main()
