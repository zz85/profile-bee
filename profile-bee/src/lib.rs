use legacy::symbols::StackFrameInfo;
use profile_bee_common::StackInfo;

mod cache;
pub mod codeguru;
#[cfg(feature = "aws")]
pub mod codeguru_upload;
pub mod ebpf;
pub mod event_loop;
pub mod html;
pub mod process_metadata;
pub mod session;
pub mod spawn;
pub mod symbolize;

mod legacy;
pub mod types;

pub mod dwarf_unwind;

pub mod output;
pub mod pipeline;
pub mod pprof;

pub mod probe_resolver;
pub mod probe_spec;

pub mod jitdump;
pub mod v8;

mod trace_handler;
pub use trace_handler::*;
