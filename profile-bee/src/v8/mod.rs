//! V8 / Node.js profiling support.
//!
//! This module provides zero-configuration JavaScript symbol resolution for
//! Node.js processes by reading V8's internal data structures directly.
//! The approach is inspired by the OpenTelemetry eBPF profiler's V8 tracer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  1. V8 Detection (introspection.rs)                            │
//! │     Read /proc/<pid>/exe → is it Node.js?                      │
//! │     Read v8dbg_* symbols from ELF → V8IntrospectionData        │
//! │     Build V8ProcInfo for eBPF unwinder                         │
//! │                                                                │
//! │  2. Frame Classification (eBPF, future)                        │
//! │     Read FP context → extract JSFunction pointer               │
//! │     Classify frame: interpreted / JIT / builtin                │
//! │     Pass heap pointer to userspace alongside IP                │
//! │                                                                │
//! │  3. Symbol Resolution (heap.rs)                                │
//! │     process_vm_readv → read JSFunction from live heap          │
//! │     Chase: JSFunction → SharedFunctionInfo → name              │
//! │                       → Script → source file + line            │
//! │     Handle V8 string types: Seq, Cons, Thin                    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Current Status
//!
//! - Phase 1 (introspection): Complete — reads v8dbg_* symbols, builds V8ProcInfo
//! - Phase 2 (heap reader): Complete — reads V8 objects via process_vm_readv
//! - Phase 3 (integration): Pending — wire into symbolization pipeline
//! - Phase 4 (eBPF): Pending — custom V8 frame extraction in eBPF

pub mod heap;
pub mod introspection;
pub mod types;

pub use heap::{V8HeapReader, V8Symbol};
pub use introspection::{is_nodejs_binary, read_introspection_data, read_v8_version};
pub use profile_bee_common::V8ProcInfo;
pub use types::V8IntrospectionData;
