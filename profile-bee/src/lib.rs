use legacy::symbols::StackFrameInfo;
use profile_bee_common::StackInfo;

mod cache;
pub mod ebpf;
pub mod html;
pub mod spawn;

pub mod legacy;

mod trace_handler;
pub use trace_handler::*;
