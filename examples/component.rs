//! Print a small OSCAL component definition.
use ironevidence::{Component, ComponentDefinition, ControlImplementation, Requirement, Status};

fn main() {
    let definition = ComponentDefinition {
        uuid: "6f1f0c0e-2f0b-4d5e-9a57-0b6d1b5f3c01".into(),
        title: "IronSecurity component definitions".into(),
        version: "0.0.0".into(),
        last_modified: "2026-10-09T00:00:00Z".into(),
        components: vec![Component {
            uuid: "6f1f0c0e-2f0b-4d5e-9a57-0b6d1b5f3c02".into(),
            title: "IronCrypto".into(),
            description: "Cryptographic primitives for the IronSecurity stack".into(),
            version: "0.2.20".into(),
            implementations: vec![ControlImplementation {
                uuid: "6f1f0c0e-2f0b-4d5e-9a57-0b6d1b5f3c03".into(),
                source: "https://doi.org/10.6028/NIST.SP.800-53r5".into(),
                description: "NIST SP 800-53 r5 controls".into(),
                requirements: vec![Requirement {
                    uuid: "6f1f0c0e-2f0b-4d5e-9a57-0b6d1b5f3c04".into(),
                    control_id: "sc-13".into(),
                    status: Status::Unmet,
                    description: "Implements FIPS-approved algorithms. Not CMVP validated, so this control is unmet; \
                                  a validation is planned, with no date."
                        .into(),
                    evidence: vec!["https://github.com/nervosys/IronCrypto".into()],
                }],
            }],
        }],
    };
    match definition.to_oscal_json() {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
