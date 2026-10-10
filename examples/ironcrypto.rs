//! Write IronCrypto's control mappings as an OSCAL component definition.
//!
//! Usage: ironcrypto <controls.json> <last-modified RFC 3339 timestamp>
//! where controls.json is the output of `ic ontology controls --json`.
use ironevidence::{ComponentDefinition, ironcrypto::Controls, uuid5};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(path), Some(last_modified)) = (args.next(), args.next()) else {
        eprintln!("usage: ironcrypto <controls.json> <last-modified>");
        std::process::exit(2);
    };
    let run = || -> Result<String, Box<dyn std::error::Error>> {
        let controls = Controls::from_json(&std::fs::read_to_string(&path)?)?;
        let component = controls
            .component(&["sp800-53", "cmmc"])
            .ok_or("no control framework selected")?;
        let definition = ComponentDefinition {
            uuid: uuid5::id("ironsecurity/component-definition/ironcrypto"),
            title: "IronCrypto component definition".into(),
            version: controls.version.clone(),
            last_modified,
            components: vec![component],
        };
        Ok(definition.to_oscal_json()?)
    };
    match run() {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
