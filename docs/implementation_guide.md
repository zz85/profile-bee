# Implementation Guide: Completing DWARF Unwinding

This guide covers the remaining steps to complete DWARF stack unwinding on the `dwarf_unwind_wip2` branch.

## Current State

The `unwinder/` module already has the infrastructure:

```
profile-bee/src/unwinder/
├── mod.rs       - get_mappings(), find_instruction(), execute_instruction(), get_unwind_table()
├── ehframe.rs   - UnwindTable, UnwindTableRow, Instruction, Op, Reg (~250 lines)
└── maps.rs      - AddressMap, AddressEntry (~100 lines)
```

What's missing: RSP capture, process memory reading, and the unwinding loop.

## Step 1: Add RSP to StackInfo

In `profile-bee-common/src/lib.rs`, add `sp` field:

```rust
pub struct StackInfo {
    pub tgid: u32,
    pub user_stack_id: i32,
    pub kernel_stack_id: i32,
    pub cmd: [u8; 16],
    pub cpu: u32,
    pub bp: u64,
    pub ip: u64,
    pub sp: u64,   // ADD: Stack pointer for DWARF unwinding
}
```

## Step 2: Capture RSP in eBPF

In `profile-bee-ebpf/src/lib.rs`, update `copy_stack` to return RSP:

```rust
unsafe fn copy_stack<C: EbpfContext>(ctx: &C, pointers: &mut [u64]) -> (u64, u64, u64, usize) {
    let regs = ctx.as_ptr() as *const pt_regs;
    let regs = &*regs;
    let ip = regs.rip;
    let mut bp = regs.rbp;
    let sp = regs.rsp;  // ADD
    // ... existing frame pointer walk ...
    (ip, bp, sp, len)
}
```

And pass `sp` into `StackInfo` in `collect_trace`.

## Step 3: Add Dependencies

In `profile-bee/Cargo.toml`:

```toml
[dependencies]
nix = { version = "0.29", features = ["process"] }  # For process_vm_readv
```

Note: `procmaps` is already available via the existing `unwinder/maps.rs`.

## Step 4: Implement Process Memory Reading

Create `profile-bee/src/unwinder/memory.rs`:

```rust
use anyhow::Result;
use nix::sys::uio::{process_vm_readv, RemoteIoVec, IoSliceMut};
use nix::unistd::Pid;

pub fn read_u64(pid: u32, addr: u64) -> Result<u64> {
    let mut buf = [0u8; 8];
    let local = [IoSliceMut::new(&mut buf)];
    let remote = [RemoteIoVec { base: addr as usize, len: 8 }];
    process_vm_readv(Pid::from_raw(pid as i32), &local[..], &remote[..])?;
    Ok(u64::from_ne_bytes(buf))
}
```

Add `mod memory;` to `unwinder/mod.rs`.

## Step 5: Implement Unwinding Loop

In `unwinder/mod.rs`, implement the full unwinding function:

```rust
pub fn unwind_stack(pid: u32, initial_ip: u64, initial_rsp: u64, table: &UnwindTable) -> Vec<u64> {
    let mut stack = vec![initial_ip];
    let mut ip = initial_ip;
    let mut rsp = initial_rsp;

    const MAX_FRAMES: usize = 128;

    while stack.len() < MAX_FRAMES {
        let row = match table.find_row(ip as usize) {
            Some(r) => r,
            None => break,
        };

        let cfa = match row.rsp.offset() {
            Some(offset) => (rsp as i64 + offset) as u64,
            None => break,
        };

        let ret_addr = match row.rip.offset() {
            Some(offset) => {
                let addr = (cfa as i64 + offset) as u64;
                match memory::read_u64(pid, addr) {
                    Ok(val) => val,
                    Err(_) => break,
                }
            }
            None => break,
        };

        if ret_addr == 0 || ret_addr >= 0xffff_ffff_8000_0000 {
            break;
        }

        ip = ret_addr;
        rsp = cfa;
        stack.push(ret_addr);
    }

    stack
}
```

Add helper methods to `ehframe.rs` if not already present:

```rust
impl UnwindTable {
    pub fn find_row(&self, ip: usize) -> Option<&UnwindTableRow> {
        let idx = self.rows
            .binary_search_by_key(&ip, |row| row.start_address)
            .unwrap_or_else(|i| i.saturating_sub(1));
        self.rows.get(idx).filter(|row| ip >= row.start_address && ip < row.end_address)
    }
}

impl Instruction {
    pub fn offset(&self) -> Option<i64> {
        self.offset
    }
}
```

## Step 6: Integrate with TraceHandler

In `trace_handler.rs`, when processing stacks with fewer than ~10 frames, call the unwinder to enhance them using the RSP from `StackInfo`.

## Step 7: Build and Test

```bash
cargo xtask build-ebpf
cargo build

# Test with frame pointers (should match FP results)
rustc -g -C force-frame-pointers=yes sample/fibonacci.rs -o sample/fibonacci
sudo ./target/release/profile-bee --svg test-fp.svg --time 1000 --cmd "./sample/fibonacci"

# Test without frame pointers (DWARF should produce more frames)
rustc -O sample/fibonacci.rs -o sample/fibonacci
sudo ./target/release/profile-bee --svg test-no-fp.svg --time 1000 --cmd "./sample/fibonacci"
```

## Troubleshooting

- **Permission denied on memory read**: Run with sudo/root
- **No unwind info**: Check binary has `.eh_frame`: `readelf -S binary | grep eh_frame`
- **Unwinding stops early**: Log CFA/return address values to debug

## References

- `docs/dwarf_unwinding_design.md` - Architecture overview
- `docs/wip_insights.md` - Key insights from WIP analysis
- `profile-bee/src/unwinder/` - Current implementation
