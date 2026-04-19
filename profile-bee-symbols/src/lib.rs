//! Shared symbol extraction and FileId computation for profile-bee ecosystem.
//!
//! This crate is used by both `profile-bee` (the profiler) and `symbol-server`
//! (the devfiler-compatible symbol serving daemon).
//!
//! - `fileid`: htlhash FileId computation compatible with devfiler/Elastic
//! - `extract`: ELF symbol extraction from .symtab/.dynsym with demangling

pub mod extract;
pub mod fileid;
