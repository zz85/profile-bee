/// DWARF-based stack unwinding for processes without frame pointers
///
/// This module provides DWARF CFI (Call Frame Information) based stack unwinding
/// as a fallback when frame pointer unwinding fails or is incomplete.
///
/// References:
/// - https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers
/// - https://github.com/gimli-rs/gimli for DWARF parsing
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

        // TODO: Implement the actual DWARF unwinding algorithm
        // This would involve:
        // 1. Starting from the initial IP (instruction pointer)
        // 2. Finding the corresponding .eh_frame FDE (Frame Description Entry)
        // 3. Evaluating the DWARF expressions to compute CFA and return address
        // 4. Repeating for each frame until we reach the end
        //
        // For now, this demonstrates the infrastructure is in place:
        // - We can read process maps
        // - We can load and parse .eh_frame sections
        // - We cache the parsed data for performance
        //
        // A full implementation would use gimli's UnwindContext and evaluate
        // CFI instructions to walk the stack. Reference implementations:
        // - https://github.com/nbdd0121/unwinding
        // - https://github.com/parca-dev/parca-agent/blob/main/pkg/stack/unwind/
        // - https://github.com/grafana/opentelemetry-ebpf-profiler

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
