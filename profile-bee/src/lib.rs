use legacy::symbols::StackFrameInfo;
use profile_bee_common::StackInfo;

mod cache;
pub mod ebpf;
pub mod html;
pub mod spawn;

mod legacy;
pub mod types;

pub mod dwarf_unwind;

pub mod probe_spec;
pub mod probe_resolver;

mod trace_handler;
pub use trace_handler::*;


