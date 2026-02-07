# Quick Implementation Guide: Completing DWARF Unwinding

This guide provides step-by-step instructions for completing the DWARF unwinding implementation using code from the wip2 branch.

## Prerequisites

Ensure you're on the `copilot/support-dwarf-no-frame-pointer` branch and have analyzed the WIP branches.

## Step-by-Step Implementation

### Step 1: Extract Core Modules from wip2

```bash
# Create subdirectory for DWARF modules
mkdir -p profile-bee/src/dwarf_unwind

# Extract ehframe module (DWARF parsing with gimli)
git show 163c972:profile-bee/src/unwinder/ehframe.rs > profile-bee/src/dwarf_unwind/ehframe.rs

# Extract maps module (process memory maps)
git show 163c972:profile-bee/src/unwinder/maps.rs > profile-bee/src/dwarf_unwind/maps.rs
```

### Step 2: Update Dependencies

Add to `profile-bee/Cargo.toml`:

```toml
[dependencies]
# ... existing deps ...
procmaps = "0.7"  # Better /proc/maps parsing (replaces proc-maps)
nix = { version = "0.29", features = ["process"] }  # For process_vm_readv
```

### Step 3: Update StackInfo to Include RSP

In `profile-bee-common/src/lib.rs`:

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct StackInfo {
    pub tgid: u32,
    pub user_stack_id: i32,
    pub kernel_stack_id: i32,
    pub cmd: [u8; 16],
    pub cpu: u32,
    pub bp: u64,   // Base pointer (frame pointer)
    pub ip: u64,   // Instruction pointer
    pub sp: u64,   // ADD THIS: Stack pointer (RSP)
}
```

### Step 4: Capture RSP in eBPF

In `profile-bee-ebpf/src/lib.rs`, update `copy_stack`:

```rust
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, u64, usize) {
    let regs = ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;

    let ip = regs.rip;
    let mut bp = regs.rbp;
    let sp = regs.rsp;  // ADD THIS

    pointers[0] = ip;

    let mut len = pointers.len();
    for i in 1..pointers.len() {
        let Some(ret_addr) = get_frame(&mut bp) else {
            len = i;
            break;
        };
        pointers[i] = ret_addr;
    }

    (ip, bp, sp, len)  // Return sp as well
}
```

And update `collect_trace`:

```rust
pub unsafe fn collect_trace<C: EbpfContext>(ctx: C) {
    // ... existing code ...
    
    let pointer = &mut *pointer;
    let (ip, bp, sp, len) = copy_stack(&ctx, &mut pointer.pointers);  // Get sp
    pointer.len = len;

    let stack_info = StackInfo {
        tgid,
        user_stack_id,
        kernel_stack_id,
        cmd,
        cpu,
        ip,
        bp,
        sp,  // ADD THIS
    };
    
    // ... rest of function ...
}
```

### Step 5: Restructure dwarf_unwind.rs

Replace the current `profile-bee/src/dwarf_unwind.rs` content with module structure:

```rust
/// DWARF-based stack unwinding for processes without frame pointers
///
/// See docs/dwarf_unwinding_design.md and docs/wip_insights.md for architecture details.

mod ehframe;
mod maps;

use anyhow::{Context, Result};
use blazesym::Addr;
use std::collections::HashMap;
use std::path::PathBuf;

pub use ehframe::{UnwindTable, UnwindTableRow, Instruction};
pub use maps::{AddressMap, AddressEntry};

const MIN_FRAMES_FOR_FP_UNWINDING: usize = 10;

/// DWARF-based stack unwinder
pub struct DwarfUnwinder {
    /// Cache of parsed unwind tables per binary
    unwind_cache: HashMap<PathBuf, UnwindTable>,
    /// Whether DWARF unwinding is enabled
    enabled: bool,
}

impl DwarfUnwinder {
    pub fn new(enabled: bool) -> Self {
        DwarfUnwinder {
            unwind_cache: HashMap::new(),
            enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn unwind_stack(&mut self, pid: u32, initial_addresses: &[Addr]) -> Result<Option<Vec<Addr>>> {
        if !self.enabled {
            return Ok(None);
        }

        if initial_addresses.len() >= MIN_FRAMES_FOR_FP_UNWINDING {
            tracing::trace!("Frame pointer unwinding sufficient");
            return Ok(None);
        }

        match self.try_dwarf_unwind(pid, initial_addresses) {
            Ok(addrs) if addrs.len() > initial_addresses.len() => {
                tracing::debug!(
                    "DWARF unwinding enhanced stack from {} to {} frames",
                    initial_addresses.len(),
                    addrs.len()
                );
                Ok(Some(addrs))
            }
            Ok(_) => Ok(None),
            Err(e) => {
                tracing::trace!("DWARF unwinding failed: {:?}", e);
                Ok(None)
            }
        }
    }

    fn try_dwarf_unwind(&mut self, pid: u32, initial_addresses: &[Addr]) -> Result<Vec<Addr>> {
        // Load process memory maps
        let maps = AddressMap::load_pid(pid)?;
        
        // Load and cache unwind tables for all executable regions
        for entry in maps.iter() {
            if !self.unwind_cache.contains_key(&entry.path) {
                if let Ok(table) = ehframe::get_unwind_table(&entry.path) {
                    tracing::debug!("Cached unwind table for {:?}: {} rows", 
                        entry.path, table.rows.len());
                    self.unwind_cache.insert(entry.path.clone(), table);
                }
            }
        }

        // Get initial state (need IP and RSP from last frame)
        // TODO: Get RSP from StackInfo
        let mut stack = initial_addresses.to_vec();
        
        // Perform unwinding
        // TODO: Implement actual unwinding loop
        
        Ok(stack)
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
}
```

### Step 6: Implement Process Memory Reading

Create `profile-bee/src/dwarf_unwind/memory.rs`:

```rust
use anyhow::Result;
use nix::sys::uio::{process_vm_readv, RemoteIoVec, IoSliceMut};
use nix::unistd::Pid;

/// Read a u64 value from target process memory
pub fn read_u64(pid: u32, addr: u64) -> Result<u64> {
    let mut buf = [0u8; 8];
    let local = [IoSliceMut::new(&mut buf)];
    let remote = [RemoteIoVec { base: addr as usize, len: 8 }];
    
    process_vm_readv(
        Pid::from_raw(pid as i32),
        &local[..],
        &remote[..]
    )?;
    
    Ok(u64::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_own_memory() {
        let test_value: u64 = 0x1234567890ABCDEF;
        let addr = &test_value as *const u64 as u64;
        let result = read_u64(std::process::id(), addr).unwrap();
        assert_eq!(result, test_value);
    }
}
```

### Step 7: Implement Unwinding Algorithm

Add to `profile-bee/src/dwarf_unwind.rs`:

```rust
mod memory;

// In try_dwarf_unwind method:
fn try_dwarf_unwind(&mut self, pid: u32, initial_addresses: &[Addr]) -> Result<Vec<Addr>> {
    let maps = AddressMap::load_pid(pid)?;
    
    // Cache unwind tables
    for entry in maps.iter() {
        if !self.unwind_cache.contains_key(&entry.path) {
            if let Ok(table) = ehframe::get_unwind_table(&entry.path) {
                self.unwind_cache.insert(entry.path.clone(), table);
            }
        }
    }

    let mut stack = initial_addresses.to_vec();
    
    // Get last known IP and RSP
    // For now, we don't have RSP from StackInfo yet
    // This will be completed when Step 3-4 are done
    
    let mut ip = *initial_addresses.last().unwrap_or(&0);
    let mut sp: u64 = 0; // TODO: Get from StackInfo
    
    const MAX_FRAMES: usize = 128;
    
    while stack.len() < MAX_FRAMES {
        // Find which binary contains this IP
        let entry = maps.iter()
            .find(|e| ip >= e.start_addr as u64 && ip < e.end_addr as u64);
        
        let entry = match entry {
            Some(e) => e,
            None => break, // IP not in any mapped region
        };
        
        // Get unwind table for this binary
        let table = match self.unwind_cache.get(&entry.path) {
            Some(t) => t,
            None => break, // No unwind info available
        };
        
        // Find unwind row for this IP
        let relative_ip = (ip - entry.start_addr as u64) as usize;
        let row = table.find_row(relative_ip);
        
        let row = match row {
            Some(r) => r,
            None => break, // No unwind info for this address
        };
        
        // Calculate CFA (Canonical Frame Address)
        let cfa = match row.cfa_offset() {
            Some(offset) => (sp as i64 + offset) as u64,
            None => break,
        };
        
        // Get return address
        let ret_addr = match row.rip_offset() {
            Some(offset) => {
                let addr = (cfa as i64 + offset) as u64;
                match memory::read_u64(pid, addr) {
                    Ok(val) => val,
                    Err(_) => break,
                }
            }
            None => break,
        };
        
        // Validate return address
        if ret_addr == 0 || ret_addr >= 0xffff_ffff_8000_0000 {
            break; // Invalid address
        }
        
        // Update for next iteration
        ip = ret_addr;
        sp = cfa;
        
        stack.push(ret_addr);
    }

    Ok(stack)
}
```

### Step 8: Update ehframe.rs Helper Methods

Add to `profile-bee/src/dwarf_unwind/ehframe.rs`:

```rust
impl UnwindTable {
    /// Find the unwind row for a given instruction pointer
    pub fn find_row(&self, ip: usize) -> Option<&UnwindTableRow> {
        let idx = self.rows
            .binary_search_by_key(&ip, |row| row.start_address)
            .unwrap_or_else(|i| i.saturating_sub(1));
        
        self.rows.get(idx).filter(|row| {
            ip >= row.start_address && ip < row.end_address
        })
    }
}

impl UnwindTableRow {
    /// Get the CFA offset if it's a simple RSP+offset pattern
    pub fn cfa_offset(&self) -> Option<i64> {
        self.rsp.offset()
    }
    
    /// Get the RIP offset if it's a simple CFA+offset pattern
    pub fn rip_offset(&self) -> Option<i64> {
        self.rip.offset()
    }
}

/// Parse unwind table from file path (public API)
pub fn get_unwind_table(path: impl AsRef<std::path::Path>) -> Result<UnwindTable> {
    let data = std::fs::read(path.as_ref())?;
    let file = object::File::parse(&*data)?;
    UnwindTable::parse(&file)
}
```

### Step 9: Build and Test

```bash
# Build eBPF
cargo xtask build-ebpf

# Build userspace
cargo build

# Run tests
cargo test

# Test with a simple program
cargo build --release
sudo ./target/release/profile-bee --svg test.svg --time 1000 --cmd "ls -la"
```

### Step 10: Validation

Create a test program without frame pointers:

```rust
// test_no_fp.rs
fn recursive(n: usize) -> usize {
    if n == 0 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        return 1;
    }
    recursive(n - 1) + 1
}

fn main() {
    println!("Result: {}", recursive(10));
}
```

Compile without FP and test:

```bash
rustc -O test_no_fp.rs -o test_no_fp
sudo ./target/release/profile-bee --svg test_no_fp.svg --time 1000 --cmd "./test_no_fp"
```

Expected: Should show full call stack even without frame pointers.

## Troubleshooting

### Missing RSP values
- Ensure eBPF captures `regs.rsp`
- Check `StackInfo` includes `sp` field
- Verify `pt_regs` structure has `rsp` member

### Memory read permission denied
- Run with sudo/root
- Check SELinux/AppArmor settings
- Verify `process_vm_readv` permissions

### No unwind info found
- Check binary has `.eh_frame` section: `readelf -S binary | grep eh_frame`
- Ensure binary wasn't stripped: `file binary`
- Try compiling test program with `-g` flag

### Unwinding stops early
- Check validation logic isn't too strict
- Verify CFA calculation is correct
- Log intermediate values for debugging

## Next Steps

After basic implementation works:

1. Add comprehensive tests
2. Benchmark performance
3. Optimize caching
4. Handle edge cases
5. Consider Phase 2: eBPF-side unwinding with DwarfDelta

## References

- `docs/wip_branches_comparison.md` - Detailed WIP analysis
- `docs/wip_insights.md` - Top 10 insights
- `docs/dwarf_unwinding_design.md` - Architecture overview
- wip2 branch (163c972) - Working implementation
