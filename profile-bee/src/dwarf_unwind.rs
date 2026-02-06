/// DWARF-based stack unwinding for processes without frame pointers
///
/// # Architecture: Hybrid Unwinding (eBPF + Userland)
///
/// Profile-bee uses a two-stage unwinding approach:
///
/// ## 1. eBPF (Kernel Space) - Frame Pointer Unwinding
/// - **Location**: `profile-bee-ebpf/src/lib.rs` (functions: `copy_stack`, `get_frame`)
/// - **What**: Walks frame pointer chain in kernel context
/// - **Advantage**: Fast, low overhead, runs at high frequency (99-9999 Hz)
/// - **Limitation**: Only works for binaries compiled with `-fno-omit-frame-pointer`
///
/// ## 2. Userland (This Module) - DWARF Unwinding  
/// - **Location**: This file (`dwarf_unwind.rs`)
/// - **What**: Uses DWARF CFI to unwind optimized code without frame pointers
/// - **When**: Activates as fallback when eBPF FP unwinding produces <10 frames
/// - **Status**: **Infrastructure complete, algorithm NOT yet implemented**
///
/// # Current Implementation Status
///
/// ✅ **COMPLETE**: Infrastructure
/// - Process memory map reading (`/proc/[pid]/maps`)
/// - ELF binary parsing (`object` crate)
/// - `.eh_frame`/`.debug_frame` section extraction
/// - Per-binary caching of unwind information
/// - Integration with TraceHandler
///
/// ❌ **TODO**: DWARF Unwinding Algorithm (see line 163)
/// - Parse `.eh_frame` with gimli
/// - Evaluate DWARF CFI instructions
/// - Compute Canonical Frame Address (CFA)
/// - Walk stack using DWARF unwind rules
///
/// # Why Userland for DWARF?
///
/// DWARF unwinding cannot be done in eBPF because:
/// - `.eh_frame` sections can be megabytes (exceeds eBPF program size limits)
/// - Complex parsing and expression evaluation (stack-based DWARF VM)
/// - Need to read process maps and binary files from filesystem
/// - Gimli library is userspace-only
///
/// # References
/// - https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers
/// - https://github.com/gimli-rs/gimli for DWARF parsing
/// - See `docs/dwarf_unwinding_design.md` for complete architecture
use anyhow::{Context, Result};
use blazesym::Addr;
use object::{Object, ObjectSection};
use proc_maps::get_process_maps;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Minimum number of frames from frame pointer unwinding before DWARF is skipped
/// If FP unwinding produces this many or more frames, we assume it's sufficient
const MIN_FRAMES_FOR_FP_UNWINDING: usize = 10;

/// DWARF-based stack unwinder
///
/// Manages DWARF unwind information and performs stack unwinding
/// for processes that don't have frame pointers enabled.
pub struct DwarfUnwinder {
    /// Cache of parsed DWARF information per binary
    unwind_info_cache: HashMap<PathBuf, UnwindInfo>,
    /// Whether DWARF unwinding is enabled
    enabled: bool,
}

/// Unwind information for a single binary
struct UnwindInfo {
    /// .eh_frame section data for unwinding
    eh_frame_data: Vec<u8>,
    /// Base address of the binary in memory
    base_addr: u64,
    /// Path to the binary file
    path: PathBuf,
}

impl DwarfUnwinder {
    /// Create a new DWARF unwinder
    ///
    /// # Arguments
    /// * `enabled` - Whether DWARF unwinding should be used
    pub fn new(enabled: bool) -> Self {
        DwarfUnwinder {
            unwind_info_cache: HashMap::new(),
            enabled,
        }
    }

    /// Check if DWARF unwinding is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Load unwind info for a binary if not already cached
    fn load_unwind_info(&mut self, path: &Path, base_addr: u64) -> Result<()> {
        if self.unwind_info_cache.contains_key(path) {
            return Ok(());
        }

        tracing::debug!("Loading DWARF unwind info for {:?}", path);

        let binary_data = fs::read(path)
            .with_context(|| format!("Failed to read binary {:?}", path))?;

        let object = object::File::parse(&*binary_data)
            .with_context(|| format!("Failed to parse binary {:?}", path))?;

        // Try to find .eh_frame section
        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .or_else(|| object.section_by_name(".debug_frame"));

        if let Some(section) = eh_frame_section {
            let eh_frame_data = section.data()
                .with_context(|| "Failed to read .eh_frame section")?
                .to_vec();

            tracing::debug!(
                "Loaded {} bytes of unwind info from {:?}",
                eh_frame_data.len(),
                path
            );

            let info = UnwindInfo {
                eh_frame_data,
                base_addr,
                path: path.to_path_buf(),
            };

            self.unwind_info_cache.insert(path.to_path_buf(), info);
            Ok(())
        } else {
            tracing::debug!("No .eh_frame or .debug_frame section found in {:?}", path);
            Err(anyhow::anyhow!("No unwind section found"))
        }
    }

    /// Attempt to unwind the stack using DWARF information
    ///
    /// This is called when frame pointer unwinding fails or produces
    /// incomplete results. It uses DWARF CFI to reconstruct the call stack.
    ///
    /// # Arguments
    /// * `pid` - Process ID to unwind
    /// * `initial_addresses` - Initial addresses from frame pointer unwinding
    ///
    /// # Returns
    /// Additional addresses discovered through DWARF unwinding, or None if
    /// DWARF unwinding is disabled or fails.
    pub fn unwind_stack(&mut self, pid: u32, initial_addresses: &[Addr]) -> Result<Option<Vec<Addr>>> {
        if !self.enabled {
            return Ok(None);
        }

        // If we already have a good stack from frame pointers, just return it
        if initial_addresses.len() >= MIN_FRAMES_FOR_FP_UNWINDING {
            tracing::trace!("Frame pointer unwinding produced sufficient frames, skipping DWARF");
            return Ok(None);
        }

        // Try to enhance the stack using DWARF unwinding
        match self.try_dwarf_unwind(pid, initial_addresses) {
            Ok(addrs) => {
                if addrs.len() > initial_addresses.len() {
                    tracing::debug!(
                        "DWARF unwinding enhanced stack from {} to {} frames",
                        initial_addresses.len(),
                        addrs.len()
                    );
                    Ok(Some(addrs))
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                tracing::trace!("DWARF unwinding failed: {:?}", e);
                Ok(None)
            }
        }
    }

    /// Attempt DWARF-based unwinding
    ///
    /// # Current Implementation Status: INCOMPLETE
    ///
    /// This method currently only:
    /// ✅ Reads process memory maps
    /// ✅ Parses ELF binaries and extracts `.eh_frame` sections
    /// ✅ Caches unwind information
    ///
    /// ❌ Does NOT actually unwind the stack (see TODO below)
    ///
    /// # What's Needed for Full Implementation
    ///
    /// To complete DWARF unwinding, this method needs to:
    /// 1. Use gimli to parse `.eh_frame` and find FDE (Frame Description Entry) for each IP
    /// 2. Evaluate DWARF CFI instructions (DW_CFA_def_cfa, DW_CFA_offset, etc.)
    /// 3. Compute Canonical Frame Address (CFA) for each frame
    /// 4. Extract return address from saved registers
    /// 5. Repeat for each frame until reaching stack bottom
    ///
    /// # Why It's Not Implemented Yet
    ///
    /// DWARF unwinding requires:
    /// - Complex gimli API usage (UnwindContext, RegisterRule evaluation)
    /// - Architecture-specific register handling (x86_64, ARM, etc.)
    /// - Process memory reading (may require ptrace or process_vm_readv)
    /// - Robust error handling for malformed unwind info
    ///
    /// The infrastructure is complete and ready for the algorithm implementation.
    fn try_dwarf_unwind(&mut self, pid: u32, _initial_addresses: &[Addr]) -> Result<Vec<Addr>> {
        // Read process memory maps to find loaded binaries
        let maps = get_process_maps(pid as i32)
            .with_context(|| format!("Failed to read process maps for pid {}", pid))?;

        // Load unwind info for all executable mappings
        for map in &maps {
            if let Some(ref pathname) = map.filename() {
                let path = Path::new(pathname);
                if path.exists() && map.is_exec() {
                    let _ = self.load_unwind_info(path, map.start() as u64);
                }
            }
        }

        // ==================================================================================
        // TODO: ACTUAL DWARF UNWINDING ALGORITHM (NOT YET IMPLEMENTED)
        // ==================================================================================
        //
        // The code above successfully loads .eh_frame sections from all binaries.
        // Now we need to use them to actually unwind the stack.
        //
        // ALGORITHM OUTLINE:
        // ==================================================================================
        //
        // 1. START WITH INITIAL INSTRUCTION POINTERS from eBPF frame pointer unwinding
        //
        // 2. FOR EACH IP in initial_addresses:
        //    a. Find which binary contains this IP (use process maps)
        //    b. Get cached UnwindInfo for that binary
        //    c. Parse .eh_frame with gimli to find FDE for this IP
        //    d. Evaluate DWARF expressions to get CFA (Canonical Frame Address)
        //    e. Read return address from computed location
        //    f. Add return address to unwound stack
        //    g. Repeat with return address as new IP
        //
        // 3. RETURN all discovered instruction pointers
        //
        // ==================================================================================
        // IMPLEMENTATION NOTES:
        // ==================================================================================
        //
        // Use gimli's UnwindContext:
        //   let eh_frame = EhFrame::new(&eh_frame_data, NativeEndian);
        //   let mut ctx = UnwindContext::new();
        //   let row = eh_frame.unwind_info_for_address(bases, &mut ctx, ip)?;
        //
        // Evaluate CFA rule:
        //   match row.cfa() {
        //       CfaRule::RegisterAndOffset { register, offset } => {
        //           // CFA = register_value + offset
        //       }
        //       CfaRule::Expression(expr) => {
        //           // Evaluate DWARF expression (complex)
        //       }
        //   }
        //
        // Get return address:
        //   let ra_rule = row.register(RETURN_ADDRESS_REGISTER);
        //   match ra_rule {
        //       RegisterRule::Offset(offset) => {
        //           // Return address is at CFA + offset
        //       }
        //       // ... handle other register rules
        //   }
        //
        // CHALLENGES:
        // - Need to read process memory (may require ptrace permissions)
        // - Register state tracking across frames
        // - Architecture-specific register definitions
        // - Error handling for corrupt/missing unwind info
        //
        // REFERENCES:
        // - https://github.com/nbdd0121/unwinding/blob/master/src/unwinder/frame.rs
        // - https://github.com/gimli-rs/gimli/tree/master/examples
        // - https://github.com/parca-dev/parca-agent/blob/main/pkg/stack/unwind/
        //
        // ==================================================================================

        tracing::trace!(
            "DWARF infrastructure ready with {} cached binaries",
            self.unwind_info_cache.len()
        );
        Ok(vec![])
    }
}

impl Default for DwarfUnwinder {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwarf_unwinder_creation() {
        let unwinder = DwarfUnwinder::new(true);
        assert!(unwinder.is_enabled());

        let unwinder = DwarfUnwinder::new(false);
        assert!(!unwinder.is_enabled());
    }

    #[test]
    fn test_dwarf_unwinder_disabled() {
        let mut unwinder = DwarfUnwinder::new(false);
        let result = unwinder.unwind_stack(1234, &[0x1000, 0x2000]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_dwarf_unwinder_with_sufficient_frames() {
        let mut unwinder = DwarfUnwinder::new(true);
        // Create a stack with many frames - should skip DWARF
        let addrs: Vec<Addr> = (0..15).map(|i| 0x1000 + i * 0x100).collect();
        let result = unwinder.unwind_stack(1234, &addrs);
        assert!(result.is_ok());
        // Should return None because frame pointer unwinding was sufficient
        assert_eq!(result.unwrap(), None);
    }
}
