//! Convert a stackcollapse file to pprof protobuf format.
//!
//! Usage: cargo run --example collapse_to_pprof -- <input.txt> <output.pb.gz>

use std::env;
use std::fs;

use profile_bee::pprof::{collapse_to_pprof, PprofOptions};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <collapse-input> <pprof-output.pb.gz>", args[0]);
        std::process::exit(1);
    }

    let input = fs::read_to_string(&args[1]).expect("Failed to read input file");
    let stacks: Vec<String> = input.lines().map(|s| s.to_owned()).collect();

    eprintln!("Read {} stack lines from {}", stacks.len(), args[1]);

    let opts = PprofOptions {
        frequency_hz: 99,
        duration_ms: 10000,
        off_cpu: false,
    };

    let pprof_bytes = collapse_to_pprof(&stacks, &opts).expect("Failed to generate pprof");

    fs::write(&args[2], &pprof_bytes).expect("Failed to write output file");
    eprintln!(
        "Wrote {} bytes to {} (gzip-compressed pprof protobuf)",
        pprof_bytes.len(),
        args[2]
    );
}
