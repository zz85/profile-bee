//! Convert a stackcollapse file to CodeGuru JSON format.
//!
//! Usage: cargo run --example collapse_to_codeguru -- <input.txt> <output.json>

use std::env;
use std::fs;

use profile_bee::codeguru::{collapse_to_codeguru, CodeGuruOptions};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <collapse-input> <codeguru-output.json>", args[0]);
        std::process::exit(1);
    }

    let input = fs::read_to_string(&args[1]).expect("Failed to read input file");
    let stacks: Vec<String> = input.lines().map(|s| s.to_owned()).collect();

    eprintln!("Read {} stack lines from {}", stacks.len(), args[1]);

    let opts = CodeGuruOptions {
        frequency_hz: 99,
        duration_ms: 10000,
        ..Default::default()
    };

    let json = collapse_to_codeguru(&stacks, &opts);

    fs::write(&args[2], &json).expect("Failed to write output file");
    eprintln!("Wrote {} bytes to {}", json.len(), args[2]);
}
