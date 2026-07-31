# preempt_count-Based Execution Context Detection

Status: **plan, not implemented.** Supersedes the symbol-matching approach in
`SymbolFormatter` for *context determination* (task / softirq / hardirq / NMI).
Symbol matching is retained for identifying *which* softirq or IRQ vector.

## 0. Summary of key decisions

| Question | Decision |
|---|---|
| How to read preempt_count | **Userspace-computed offsets injected via `override_global`**, not CO-RE. Verified: `aya-obj-0.2.1` makes `Struct::members()` `pub(crate)` (`btf/types.rs:1395`), and the only public lookup is `Btf::id_by_type_name_kind` — enough to prove a type exists, not to get a member offset. bpf-linker also has no `__builtin_preserve_access_index` equivalent. So profile-bee needs its own minimal BTF reader plus kallsyms. |
| x86_64 source | `__per_cpu_offset[cpu]` (absolute address from `/proc/kallsyms`) + percpu section offset of `__preempt_count`. Two `bpf_probe_read_kernel` calls. |
| aarch64 source | `offsetof(task_struct, thread_info) + offsetof(thread_info, preempt_count)` from `/sys/kernel/btf/vmlinux`, via `bpf_get_current_task_btf()`. One `bpf_probe_read_kernel`. |
| StackInfo change | Add `context: u32` + `_reserved: u32`. Verified: keeps size at exactly 64 with **zero implicit padding** (56 → 64, field sums match both before and after). Store a *normalized enum*, never raw preempt_count. |
| Parallel map instead? | **No.** Context must be part of the aggregation key, and `StackInfo` already is that key. A parallel map would be last-writer-wins. |
| Symbol lists | Retained, demoted to answering *which* softirq (`net_rx` vs `timer` vs `rcu`) and *which* IRQ vector. |
| Biggest risk | **The sampling interrupt contributes its own level to preempt_count.** See §5 — the one issue that could block full replacement. |

## 1. Background: why the current approach is broken

Context is inferred in `profile-bee/src/trace_handler.rs`:

| Function | Role |
|---|---|
| `classify_softirq_symbol` | softirq handler name → `softirq:net_rx_k` etc. |
| `is_generic_softirq_symbol` | `__do_softirq` / `handle_softirqs` / `____do_softirq` → generic softirq |
| `classify_interrupt_symbol` | entry symbols → `interrupt:*_k` |
| `is_interrupt_entry_symbol` | entry trampolines (x86 + aarch64) |
| `is_sampling_induced_interrupt` | suppress bare sampling-timer entry |
| `infer_kernel_context_label` | orchestrator |

The lists are architecture-specific by nature. Most of `classify_interrupt_symbol`
is x86_64-only (`sysvec_*`, `asm_sysvec_*`, `common_interrupt`, `do_IRQ`); the
aarch64 IRQ entry symbols (`el1h_64_irq_handler`, `el1_interrupt`,
`call_on_irq_stack`) were added as an interim measure and can only ever produce a
generic `interrupt_k`, because aarch64 dispatches every interrupt through one EL1
vector rather than per-vector entry points. `____do_softirq` is separate — it
lives in `is_generic_softirq_symbol` and produces the appropriate generic
`softirq_k` fallback, since it is aarch64's `do_softirq_own_stack` trampoline
into the softirq path, not an interrupt entry.

The kernel's canonical answer is `preempt_count` (`include/linux/preempt.h`):

```text
PREEMPT_BITS 8   shift 0    mask 0x000000ff
SOFTIRQ_BITS 8   shift 8    mask 0x0000ff00
HARDIRQ_BITS 4   shift 16   mask 0x000f0000
NMI_BITS     4   shift 20   mask 0x00f00000

SOFTIRQ_OFFSET         = 1 << 8
SOFTIRQ_DISABLE_OFFSET = 2 << 8
in_serving_softirq() = (softirq_count() & SOFTIRQ_OFFSET)   // bit 8 only
interrupt_context_level() = 0 task / 1 softirq / 2 hardirq / 3 NMI
```

Bit 8 specifically distinguishes *running a softirq handler* from *merely having
BH disabled*. Masking the whole `0x0000ff00` field would label every
`spin_lock_bh()` critical section as softirq.

There is **no BPF helper** exposing preempt_count (checked against
`include/uapi/linux/bpf.h`).

## 2. Reading preempt_count in eBPF

### 2.1 Why not CO-RE

CO-RE field relocation is the textbook answer and is not available here:

1. `aya-ebpf` exposes no `preserve_access_index` / `bpf_core_read` equivalent;
   LLVM's BPF CO-RE intrinsics are not reachable from Rust source.
2. `aya-obj` can *consume* CO-RE relocations, but only ones already present in
   `.BTF.ext`. Our object's `.BTF.ext` carries only func/line info.
3. Reading offsets in userspace via aya's `Btf` is blocked — see §0.

Userspace resolution also lets us fail cleanly and log *why*, which CO-RE load
failures do not. It sidesteps `bpf_this_cpu_ptr` / `bpf_per_cpu_ptr` too, which
need a `PTR_TO_PERCPU_BTF_ID` from `BPF_PSEUDO_BTF_ID` — aya has no extern-ksym
support.

### 2.2 New userspace module: `profile-bee/src/kernel_layout.rs`

A minimal, dependency-free BTF reader plus kallsyms lookups (~250–350 LOC).

```rust
pub enum PreemptSource {
    /// x86_64: per-CPU variable.
    PerCpu { per_cpu_offset_array: u64, var_offset: u64 },
    /// aarch64: task_struct field.
    TaskStruct { byte_offset: u32 },
    Unavailable(&'static str),   // carries the reason, for logging
}

pub struct KernelLayout {
    pub preempt: PreemptSource,
    /// false under CONFIG_PREEMPT_RT — softirq bits are not in preempt_count
    pub softirq_bits_valid: bool,
    pub is_preempt_rt: bool,
}

pub fn detect() -> KernelLayout;
```

BTF reader scope — only what is needed, not a general library:

- Parse the `/sys/kernel/btf/vmlinux` header (magic `0xeb9f`, `hdr_len`,
  `type_off/len`, `str_off/len`), respecting host endianness.
- Struct/union member byte offset by (type name, member name), following
  `typedef`/`const`/`volatile` and recursing into **anonymous** members —
  required, since aarch64 `preempt_count` lives in an anonymous union.
- `VAR` type-id by name; `DATASEC` entry offset for a type-id (for
  `.data..percpu`).
- Reject bitfields outright rather than risk mis-handling them.

**aarch64 resolution:**

```text
byte_offset = offsetof(task_struct, thread_info)      // expect 0, but read it
            + offsetof(thread_info, preempt_count)     // varies with CONFIG_ARM64_SW_TTBR0_PAN
```

`thread_info.preempt_count` is a `u64` in an anonymous union with
`struct { u32 count; u32 need_resched; }`, field order flipping under
`CONFIG_CPU_BIG_ENDIAN`. Prefer resolving the union member `preempt.count`
directly; fall back to `preempt_count` with an endian adjustment.

**x86_64 resolution:** x86 `struct thread_info` holds only `flags` and `status`
(confirmed via BTF on the dev host), so we must go through the per-CPU variable.
Resolution chain:

1. kallsyms `__preempt_count` (type `A`) → percpu section offset.
2. If absent, `pcpu_hot` offset + BTF `offsetof(struct pcpu_hot, preempt_count)`.
3. If absent, `const_pcpu_hot`.
4. Cross-check against BTF `VAR '__preempt_count'` and its `.data..percpu`
   DATASEC offset. Prefer kallsyms on disagreement (kallsyms carries runtime
   truth for the loaded image); log both.

Then kallsyms `__per_cpu_offset` (type `D`) gives the absolute address of the
per-CPU offset array — this cannot come from BTF, which carries no addresses.
eBPF computes:

```text
percpu_base   = *(u64 *)(per_cpu_offset_array + cpu * 8)
preempt_count = *(u32 *)(percpu_base + var_offset)
```

The x86_64 path therefore needs readable kallsyms addresses: root (already
required) **and** `kptr_restrict != 2`. If all addresses read as zero, treat as
`Unavailable("kallsyms addresses masked (kptr_restrict=2?)")`.

**PREEMPT_RT detection** (`softirq_bits_valid`):

- Primary: BTF — `struct task_struct` has `softirq_disable_cnt` **only** under
  `CONFIG_PREEMPT_RT`. Verified as a clean probe: 0 occurrences on the non-RT
  dev host.
- Secondary: `CONFIG_PREEMPT_RT=y` in `/boot/config-$(uname -r)`.
- Tertiary: `uname -v` containing `PREEMPT_RT`.

### 2.3 Globals injected into eBPF

Follow the existing `#[no_mangle] static` + `read_volatile` + `override_global`
pattern in `profile-bee-ebpf/src/lib.rs` and `profile-bee/src/ebpf.rs`:

```rust
/// 0 = disabled, 1 = x86 per-CPU var, 2 = arm64 task_struct field
#[no_mangle] static PREEMPT_CTX_MODE: u8 = 0;
#[no_mangle] static PREEMPT_PERCPU_OFFSET_ARRAY: u64 = 0;
#[no_mangle] static PREEMPT_PERCPU_VAR_OFFSET: u64 = 0;
#[no_mangle] static PREEMPT_TASK_BYTE_OFFSET: u32 = 0;
/// Levels contributed by the profiler's own sampling interrupt. See §5.
#[no_mangle] static PREEMPT_SELF_HARDIRQ: u8 = 0;
#[no_mangle] static PREEMPT_SELF_NMI: u8 = 0;
#[no_mangle] static PREEMPT_SELF_SOFTIRQ: u8 = 0;
```

Chained onto the `EbpfLoader` in `load_ebpf` with `must_exist = true`, so a stale
prebuilt object fails loudly at startup rather than silently misbehaving (§4.5.5).

### 2.4 The eBPF read

```rust
/// Normalized execution context of the *sampled* code, from preempt_count.
/// Returns EXEC_CTX_UNKNOWN when the layout is unavailable or a read fails.
#[inline(always)]
unsafe fn current_exec_context(cpu: u32) -> u32 {
    let mode = core::ptr::read_volatile(&PREEMPT_CTX_MODE);
    if mode == 0 {
        return EXEC_CTX_UNKNOWN;
    }

    let raw: u32 = if mode == 1 {
        let arr = core::ptr::read_volatile(&PREEMPT_PERCPU_OFFSET_ARRAY);
        let voff = core::ptr::read_volatile(&PREEMPT_PERCPU_VAR_OFFSET);
        let Ok(base) = bpf_probe_read_kernel((arr + (cpu as u64) * 8) as *const u64) else {
            return EXEC_CTX_UNKNOWN;
        };
        let Ok(v) = bpf_probe_read_kernel((base + voff) as *const u32) else {
            return EXEC_CTX_UNKNOWN;
        };
        // CRITICAL: x86 stores PREEMPT_NEED_RESCHED (0x80000000) inside
        // __preempt_count, inverted. preempt_count() masks it off.
        v & !0x8000_0000u32
    } else if mode == 2 {
        let off = core::ptr::read_volatile(&PREEMPT_TASK_BYTE_OFFSET);
        let task = bpf_get_current_task_btf() as *const u8;
        if task.is_null() { return EXEC_CTX_UNKNOWN; }
        let Ok(v) = bpf_probe_read_kernel(task.add(off as usize) as *const u32) else {
            return EXEC_CTX_UNKNOWN;
        };
        v   // arm64 keeps need_resched in a separate u32 — no masking
    } else {
        return EXEC_CTX_UNKNOWN;
    };

    normalize_exec_context(raw)
}
```

The x86 mask is easy to miss and would corrupt every reading. Verified against
`arch/x86/include/asm/preempt.h`:

```c
#define PREEMPT_NEED_RESCHED 0x80000000
static __always_inline int preempt_count(void) {
    return raw_cpu_read_4(__preempt_count) & ~PREEMPT_NEED_RESCHED;
}
```

The bit is stored *inverted* (set means no resched needed), so leaving it in
place makes the count appear non-zero even when preemption is allowed. arm64 does
not do this.

```rust
#[inline(always)]
unsafe fn normalize_exec_context(raw: u32) -> u32 {
    let nmi     = (raw & 0x00f0_0000) >> 20;
    let hardirq = (raw & 0x000f_0000) >> 16;
    let softirq = (raw & 0x0000_ff00) >> 8;

    let nmi     = nmi.saturating_sub(read_volatile(&PREEMPT_SELF_NMI) as u32);
    let hardirq = hardirq.saturating_sub(read_volatile(&PREEMPT_SELF_HARDIRQ) as u32);
    let softirq = softirq.saturating_sub(read_volatile(&PREEMPT_SELF_SOFTIRQ) as u32);

    // Bit 0 of the softirq field (bit 8 of raw preempt_count) is the
    // "serving softirq" flag.  After subtracting the profiler's own
    // contribution, check both the flag AND remaining count > 0.
    let softirq_serving = (softirq & 1) != 0 && softirq > 0;

    if nmi > 0              { EXEC_CTX_NMI }
    else if hardirq > 0     { EXEC_CTX_HARDIRQ }
    else if softirq_serving { EXEC_CTX_SOFTIRQ }
    else                    { EXEC_CTX_TASK }
}
```

`saturating_sub` handles nesting: `hardirq_count() == 2` with
`PREEMPT_SELF_HARDIRQ == 1` is a genuine hardirq; `== 1` is the sampling
interrupt itself.

## 3. StackInfo changes

### 3.1 Current layout (verified: zero implicit padding)

```text
tgid            u32     @  0
user_stack_id   i32     @  4
kernel_stack_id i32     @  8
cmd             [u8;16] @ 12 .. 28
cpu             u32     @ 28
bp              u64     @ 32
ip              u64     @ 40
sp              u64     @ 48
                        size 56, align 8, sum of fields 56
```

The zero-padding property is load-bearing and currently accidental. `StackInfo`
is the key of two BPF hash maps (`counts`, `stacked_pointers`) and of the
userspace `HashMap<StackInfo, usize>`. BPF hash maps compare keys as raw bytes
over `key_size`, and Rust struct-literal initialization does not guarantee
padding bytes are written — on BPF, padding would carry whatever was on the
stack, producing phantom keys and lookup misses. **Do not introduce implicit
padding.**

### 3.2 New layout

```rust
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[repr(C)]
pub struct StackInfo {
    pub tgid: u32,
    pub user_stack_id: i32,
    pub kernel_stack_id: i32,
    pub cmd: [u8; 16],
    pub cpu: u32,
    pub bp: u64,
    pub ip: u64,
    pub sp: u64,
    /// Normalized execution context: EXEC_CTX_* constant.
    /// u32 rather than u8 to keep the layout explicit and padding-free.
    pub context: u32,
    /// MUST always be 0. This struct is a BPF hash map key compared as raw
    /// bytes; a nonzero or uninitialized value creates phantom keys.
    pub _reserved: u32,
}
// verified: size 64, align 8, sum of fields 64
```

Constants in `profile-bee-common/src/lib.rs` beside the `PROCESS_EVENT_*` block:

```rust
pub const EXEC_CTX_UNKNOWN: u32 = 0;  // layout unavailable -> symbol heuristics
pub const EXEC_CTX_TASK:    u32 = 1;
pub const EXEC_CTX_SOFTIRQ: u32 = 2;
pub const EXEC_CTX_HARDIRQ: u32 = 3;
pub const EXEC_CTX_NMI:     u32 = 4;
```

### 3.3 Why normalized, not raw

Raw `preempt_count` would be more informative but unacceptable: the `PREEMPT_BITS`
field churns on every `preempt_disable`/`rcu_read_lock` under `CONFIG_PREEMPT`,
exploding the cardinality of `counts` (max `STACK_ENTRIES` = 16392) and
fragmenting the flamegraph. Normalize in eBPF, in the key. Expose raw values
through the §6.3 diagnostic if needed, never the key.

### 3.4 Why in StackInfo, not a parallel map

If two samples share an identical `StackInfo` but differ in context, a parallel
map is last-writer-wins and the already-merged counts cannot be split. Context
must be *in* the key for aggregation to be correct. Added cardinality is near
zero in practice, since softirq/hardirq samples already have distinct
`kernel_stack_id` values.

### 3.5 Consequences to handle

1. **Size 56 → 64 (+14%).** `RING_BUF_STACKS` is
   `RingBuf::with_byte_size(STACK_SIZE)` where `STACK_SIZE = 2048`, dropping
   in-flight capacity from ~28 to ~25 entries. That buffer is already very small;
   consider bumping it to 64 KiB in the same change. `pipeline.rs`'s
   `item.len() < StackInfo::STRUCT_SIZE` check auto-adapts.

2. **The symbolization cache key must include context.**
   `TraceHandler::stack_cache_key` returns `(tgid, ktrace_id, utrace_id)` and
   `PointerStackFramesCache` keys an `LruCache` on that tuple. Two samples with
   the same stack IDs but different contexts would get each other's cached label.
   **This is the most likely subtle bug in the change** — it is the same class of
   defect as the CPU-key collision fixed in `7d5209e`. Widen both to
   `(u32, i32, i32, u32)`, keeping `invalidate_pid` working.

3. **All 8 eBPF `StackInfo` construction sites must set both new fields** —
   verified at `profile-bee-ebpf/src/lib.rs` lines 314, 445, 514, 594, 631, 1065,
   1310, 1651. Rust will not let you omit them, which is the point.

4. **`DwarfUnwindState`** gains `context: u32` + `_pad3: u32` so the tail-call
   finalizers reuse the value read once in `collect_trace` instead of re-reading.
   Tail calls preserve interrupt context, so this is semantically valid, and it
   saves verifier budget in two extra programs.

5. **The prebuilt object must be regenerated in the same commit.**
   `profile-bee/ebpf-bin/profile-bee.bpf.o` is checked in (verified via
   `git ls-files`) and embedded by `build.rs` when no fresh build exists. A stale
   copy means userspace `StackInfo` is 64 bytes while loaded programs use 56 —
   silent corruption of every sample. `must_exist = true` converts this into a
   loud startup failure, but add a CI check that the committed object matches a
   fresh `cargo xtask build-ebpf --release`, or at minimum assert
   `StackInfo::STRUCT_SIZE` equals the loaded map's `key_size` at startup.

## 4. The self-interrupt problem (highest risk — read before implementing)

`preempt_count` read from inside the profiler's own perf_event program reflects
the context of the **sampling interrupt**, not of the sampled code.

profile-bee samples with `PerfEventConfig::Software(SoftwareEvent::CpuClock)`.
The overflow handler runs from `perf_swevent_hrtimer`, which on x86 with
`CONFIG_HIGH_RES_TIMERS` runs inside `hrtimer_interrupt` in the APIC timer
**hardirq** — `irq_enter_rcu()` has already done
`preempt_count_add(HARDIRQ_OFFSET)`. A naive read therefore reports `HARDIRQ` for
essentially every sample, including pure userspace CPU burn.

This is why `is_sampling_induced_interrupt` exists: the current code already
fights the same artifact from the symbol side.

| eBPF program | Self-contribution |
|---|---|
| `profile_cpu` (software CpuClock, high-res hrtimer) | +1 hardirq |
| `profile_cpu` (software CpuClock, hrtimer from timer softirq) | +1 softirq |
| `profile_cpu` (hardware PMU event, if added) | +1 NMI |
| `kprobe_profile`, `uprobe_profile`, `uretprobe_profile` | 0 (PREEMPT bits, not hardirq) |
| `tracepoint_profile`, `raw_tp_*` | 0 |
| `offcpu_profile` (kprobe on `finish_task_switch`) | 0 |

Hence three `PREEMPT_SELF_*` globals rather than one hard-coded subtraction.

**Mitigation (a): static defaults per attach point.** Set
`PREEMPT_SELF_HARDIRQ = 1` for the perf software-clock path, 0 elsewhere. With
`HARDIRQ_BITS = 4`, genuine nesting remains representable, so
`hardirq_count() >= 2` still yields `HARDIRQ`.

**Mitigation (b): startup self-calibration (strongly recommended).** The static
default is wrong where hrtimers run from the timer softirq. Over the first
~100–300 samples take the **element-wise minimum** of the raw
`(nmi, hardirq, softirq_bit)` triple; genuine nesting only *adds* levels, so the
minimum converges to the profiler's own contribution. Gate behind a flag.

**Honest consequence:** until (b) is validated across several kernel
configurations, treat preempt_count as *authoritative for NMI and for
`count >= 2` nesting* and *corroborating* elsewhere, keeping symbol heuristics as
a tiebreaker. Deleting `is_sampling_induced_interrupt` is Phase 5, gated on
validation. Presenting this as a clean drop-in replacement would be false
certainty.

## 5. Userspace consumption

### 5.1 Signature and logic

```rust
fn infer_kernel_context_label(
    kernel_syms: &[StackFrameInfo],
    ctx: u32,                    // EXEC_CTX_* from StackInfo.context
    softirq_bits_valid: bool,    // false under PREEMPT_RT
) -> Option<&'static str>
```

- **`EXEC_CTX_NMI`** → `Some("nmi_k")`; symbol lists not consulted.
- **`EXEC_CTX_HARDIRQ`** → `classify_interrupt_symbol` for the specific vector;
  fall back to `Some("interrupt_k")`. **Never `None`** — preempt_count already
  established hardirq, so `is_sampling_induced_interrupt` is not consulted
  (Phase 5) or only logged as a sanity check (Phase 4).
- **`EXEC_CTX_SOFTIRQ`** → `classify_softirq_symbol` for *which* softirq; fall
  back to `Some("softirq_k")`. This is the intended division of labour:
  preempt_count says *softirq*, the symbol list says *net_rx*.
- **`EXEC_CTX_TASK`** → `None`, except when `!softirq_bits_valid` (PREEMPT_RT),
  where the softirq symbol heuristics still run (§5.4).
- **`EXEC_CTX_UNKNOWN`** → today's body verbatim, preserving current behavior
  bit-for-bit on hosts without the layout.

Keep `classify_softirq_symbol`, `is_generic_softirq_symbol`, and
`classify_interrupt_symbol` permanently — they answer *which*, which
preempt_count cannot. `is_interrupt_entry_symbol` and
`is_sampling_induced_interrupt` become fallback-only.

Continue calling this on `kernel_syms` *before* combining with user frames, to
avoid userspace symbols that happen to end in `_k`.

### 5.2 Call sites

- **`format_stack_trace`, `tgid == 0` branch.** Today it symbolizes the kernel
  stack purely to decide idle vs softirq-on-idle. With a known context this
  becomes free and correct — the single most valuable case this fixes, and where
  aarch64 breakage is most visible.
- **`format_stack_trace`, normal branch.** Pass `stack_info.context`.
- **`stack_cache_key` / `PointerStackFramesCache`.** Add context (§3.5.2).
- **`get_raw_addresses` / `RawAddressSample`.** `.raw` output loses context
  today; add `context: u32` and encode it in `RawCollapseSink` as a synthetic
  frame so offline re-symbolization keeps attribution. Optional.
- **Tests.** All `infer_kernel_context_label` tests need new arguments; add a
  matrix of `EXEC_CTX_*` × (specific / generic / no matching symbol) × RT.

### 5.3 Diagnostics (ship this — the main cross-arch validation tool)

A hidden `PROBEE_DEBUG_CONTEXT=1` / `--debug-context` that records
`(context_from_preempt_count, context_from_symbols)` per sample and prints a
confusion matrix at shutdown:

```text
context agreement: 48213/49001 (98.4%)
  pc=HARDIRQ sym=none      : 612   <-- likely self-interrupt over-subtraction
  pc=TASK    sym=softirq_k : 176   <-- likely PREEMPT_RT or bit-8 subtlety
```

This works on any architecture and kernel with no reference tool, and is the only
practical way to validate aarch64 from an x86_64 dev box — a user or CI runner
just pastes the matrix.

### 5.4 CONFIG_PREEMPT_RT

Under RT, softirq state moves out of `preempt_count` into
`current->softirq_disable_cnt` plus a per-CPU `softirq_ctrl.cnt`. Hardirq and NMI
fields remain valid.

**Decision: do not reconstruct RT softirq state in eBPF.** It needs two more
version-dependent offsets (one another per-CPU variable) and the semantics have
changed across RT releases. Instead:

- `softirq_bits_valid = false` when RT is detected.
- eBPF still reports `HARDIRQ` / `NMI` — the two contexts symbol matching handles
  worst.
- eBPF never reports `SOFTIRQ` on RT (bit 8 simply is not set, so logic naturally
  yields `TASK`).
- Userspace, when `!softirq_bits_valid && ctx == EXEC_CTX_TASK`, runs the softirq
  symbol heuristics. On RT this is *more* reliable than non-RT, since RT softirqs
  run in `ksoftirqd`/task context with clearly-named handler frames.
- Log at startup: `"PREEMPT_RT detected: hardirq/NMI from preempt_count, softirq
  from symbol heuristics"`.

## 6. Fallback matrix

| Host condition | `PREEMPT_CTX_MODE` | Behaviour |
|---|---|---|
| x86_64, kallsyms readable, symbols found | 1 | preempt_count authoritative |
| x86_64, `kptr_restrict=2` or non-root | 0 | `EXEC_CTX_UNKNOWN` → today's heuristics |
| x86_64, `__preempt_count` renamed, chain exhausted | 0 | same + `warn!` naming the symbol |
| aarch64, `/sys/kernel/btf/vmlinux` present | 2 | preempt_count authoritative |
| aarch64, no BTF (`CONFIG_DEBUG_INFO_BTF=n`) | 0 | aarch64 symbol lists |
| any arch, BTF present but members not found | 0 | `warn!` with the failing type/member |
| PREEMPT_RT (any arch) | 1 or 2 | hardirq/NMI from pc, softirq from symbols |
| big-endian aarch64 | 0 | unsupported; log and degrade |
| unknown arch (riscv64, ppc64, s390x) | 0 | degrade; code still compiles and runs |

Invariants:

- `EXEC_CTX_UNKNOWN` **must** reproduce today's output exactly. Guarantee with a
  test comparing old and new implementations over the same fixtures.
- The feature must never abort startup. Every `detect()` failure returns
  `Unavailable(reason)` and logs; never `Err`.
- **Do not guess offsets.** An unvalidated hard-coded arm64 offset would produce
  *confidently wrong* labels — worse than an honest heuristic. Add a plausibility
  guard (reject `raw & 0xff00_0000 != 0` after masking; no valid preempt_count
  has bits 24–31 set) and count rejections into a per-CPU counter, so a bad
  offset surfaces as "unavailable" plus a loud metric rather than garbage.

## 7. Verifier budget

`AGENTS.md` warns `collect_trace` is near the instruction limit, and
`LEGACY_MAX_DWARF_STACK_DEPTH` was already cut for this reason.

**Cost added:** `current_exec_context` is straight-line — two
`bpf_probe_read_kernel` calls, ~6 `.rodata` loads, ~12 ALU ops, ~6 branches, no
loops. Roughly **30–40 instructions**.

**Cost multiplication:** `collect_trace` is `#[inline(always)]` and generic over
`C: EbpfContext`, so it is instantiated into `profile_cpu`, `kprobe_profile`,
`uprobe_profile`, `uretprobe_profile`. Each is verified independently against its
own limit, so per-program cost is what matters, not the sum.

Keeping it minimal:

1. **One read site per program** — call it once in `collect_trace` after the
   `skip_idle` and target-PID filters, so filtered samples pay nothing. Thread
   the result through `DwarfUnwindState` (§3.5.4).
2. **Rely on `.rodata` constant propagation when disabled.** `override_global`
   rewrites `.rodata`, which the kernel freezes into a read-only map; the
   verifier constant-folds reads from those (5.2+), so `if mode == 0 { return }`
   should prune the body. **Verify empirically** — `read_volatile` blocks
   *compile-time* folding by design, so pruning depends on the verifier.
3. `saturating_sub` over branchy clamping (compare + select).
4. **Do not** add the read to `collect_trace_stackid_only` initially. Tracepoint
   programs are least affected; keep the blast radius small.

Measurement gate (do this first):

```bash
sudo probee --time 1000 --collapse /dev/null &
sudo bpftool prog show | grep -E 'profile_cpu|dwarf_unwind_step'
# record verified_insns; repeat after the change with the feature both
# disabled (expect ~unchanged) and enabled (expect +30-60)
```

Also test `--dwarf` specifically, since `dwarf_copy_stack_regs` is closest to the
limit.

## 8. Testing strategy

### 8.1 Unit tests (x86_64 dev host, no root)

- **BTF reader.** Hand-construct minimal BTF blobs: header + `struct thread_info`
  with an anonymous union containing `preempt_count` and `preempt.count` +
  `struct task_struct` with a `thread_info` member + a `VAR`/`DATASEC` pair.
  Cover anonymous-union recursion, `typedef`/`const` chains, member-not-found,
  malformed header, truncated section, bitfield rejection. **This is where the
  aarch64 logic gets tested on an x86_64 box.**
- **Trimmed real-BTF fixtures.** Capture `bpftool btf dump ... format raw` from
  an aarch64 host once and check in a trimmed blob (only reachable types, a few
  KB); assert the known-good offset. Same for an x86_64 `pcpu_hot` blob.
- **`normalize_exec_context`** — extract the bit math into a pure function in
  `profile-bee-common` so both sides can test it. Table-driven:
  - `0x0001_0000`, self=1 hardirq → `TASK`
  - `0x0002_0000`, self=1 hardirq → `HARDIRQ`
  - `0x0000_0100` → `SOFTIRQ`
  - `0x0000_0200` (BH disabled) → `TASK` ← the bit-8 subtlety
  - `0x0000_0300` (BH disabled *and* serving) → `SOFTIRQ`
  - `0x0010_0000` self=1 nmi → `TASK`; `0x0020_0000` → `NMI`
  - `0x8000_0005` x86 → need-resched masked, PREEMPT depth 5 → `TASK`
  - `0x8010_0100` → `NMI` dominates
- **`infer_kernel_context_label`** matrix across all five contexts × symbol
  scenarios × `softirq_bits_valid`.
- **`EXEC_CTX_UNKNOWN` equivalence** against pre-change behavior.
- **Layout assertions:** `size_of::<StackInfo>() == 64`,
  `offset_of!(StackInfo, context) == 56`, and sum-of-field-sizes == `size_of`
  (the no-implicit-padding guard).

### 8.2 x86_64 e2e (dev host, root)

Dev host is 5.10, `CONFIG_PREEMPT_NONE=y`, `CONFIG_DEBUG_INFO_BTF=y`,
`kptr_restrict=1`, `__preempt_count` present — good for the mode-1 path.

- **Softirq:** `ping -f -c 20000 127.0.0.1` → expect `softirq:net_rx_k`; assert
  the count correlates order-of-magnitude with the `/proc/softirqs` `NET_RX`
  delta over the same window.
- **Block softirq:** `dd ... oflag=direct` → `softirq:block_k`.
- **Timer:** assert `interrupt:timer_k` is *low* on an idle CPU — regression
  guard against §4; if the self-adjustment breaks, this count explodes.
- **Pure-userspace baseline:** a pinned spin loop under `taskset -c N`; assert
  ≥95% of samples on CPU N report `EXEC_CTX_TASK`. **The single most important
  test** — it directly detects a broken self-adjustment.
- **Agreement matrix** (§5.3) above a threshold; start permissive (90%).
- **Fallback path:** set the environment variable `PROBEE_DISABLE_PREEMPT_CTX=1`
  (checked at startup; any non-empty value forces `PREEMPT_CTX_MODE = 0` before
  `override_global`, so the eBPF programs never attempt preempt_count reads) and
  assert output matches the pre-change golden files in `tests/output/*.collapse`.
- **Verifier regression:** assert `verified_insns` for `profile_cpu` stays under
  a checked-in ceiling.

### 8.3 aarch64 — the hard part

The dev host is x86_64-only. In order of preference:

1. **GitHub Actions arm64 runners** (`ubuntu-24.04-arm`), free for public repos.
   Add a matrix leg to `.github/workflows/rust.yml`. **Verify first** that
   eBPF perf_event sampling works and `/sys/kernel/btf/vmlinux` exists there.
2. **A Graviton instance** run manually for initial validation, with the §5.3
   agreement matrix pasted into this doc as evidence.
3. **`qemu-system-aarch64`** with a BTF-enabled arm64 image — usable for "does it
   load, are offsets right", not for timing-sensitive statistical assertions.
4. **`cross`/`qemu-user`** — useless; cannot run eBPF.

Interim posture until (1) or (2): ship the aarch64 symbol lists plus the mode-2
path **defaulting to disabled on aarch64** behind
`--experimental-preempt-context`, flipping the default only after real hardware
validation. The trimmed arm64 BTF fixture validates offset *computation* today;
only the *read* stays unvalidated.

### 8.4 Other kernels worth checking

- **A `CONFIG_PREEMPT=y` kernel** — the dev host is `PREEMPT_NONE`, so
  `PREEMPT_BITS` is nearly always 0 there. A preemptible kernel exercises the
  masking logic and would catch a naive `raw != 0 → not task` bug.
- **6.6+ / 6.12+ x86_64** — see open question 1.
- **A PREEMPT_RT kernel** — validates §5.4. Low priority; fallback is safe.

## 9. Sequenced implementation

| Phase | Work | Ships independently? |
|---|---|---|
| **0** | aarch64/generic symbol lists + tests | **Done** (commit `1685842`) |
| **1** | Baseline verifier measurement across all programs, FP and DWARF | n/a; gates Phase 3 |
| **2** | `kernel_layout.rs`: BTF reader + kallsyms + RT detection + unit tests; wire into a `--print-kernel-layout` debug subcommand so it validates with zero eBPF risk | **Yes** |
| **3** | `StackInfo` + `DwarfUnwindState` + `EXEC_CTX_*`; all 8 construction sites; `current_exec_context` + `normalize_exec_context`; globals + `override_global`; regenerate `ebpf-bin/*.o`; widen cache key. Userspace still ignores `context` except in diagnostics. | **Yes** — pure plumbing. Re-measure verifier. |
| **3.5** | Self-interrupt calibration (§4b) + confusion matrix; validate static default against calibrated value on every available kernel | Yes |
| **4** | `infer_kernel_context_label` consumes `context`; both `format_stack_trace` branches; `softirq_bits_valid`; full test matrix; x86_64 e2e | Yes — **the user-visible change** |
| **5** | aarch64 validation (CI leg or Graviton); flip aarch64 default on; retire `is_sampling_induced_interrupt` to fallback-only; optional `--group-by-context`; optional context in `.raw` | Yes |

Phases 1 and 2 carry no eBPF risk and should land before anything touches
`collect_trace`.

## 10. Risks and open questions

**Risks**

1. **Self-interrupt contamination (§4) — highest.** A wrong adjustment mislabels
   every sample `HARDIRQ`, worse than today. Mitigated by the pinned-spin-loop
   assertion, startup calibration, and `PROBEE_DISABLE_PREEMPT_CTX=1`.
2. **Stale `ebpf-bin/profile-bee.bpf.o`** → 56 vs 64 byte mismatch → silent
   corruption. Mitigated by `must_exist = true` and a CI freshness check. This is
   the classic footgun of the two-workspace layout.
3. **Cache-key omission (§3.5.2)** → wrong labels served from cache, no crash, no
   log. Same class as the bug fixed in `7d5209e`. Catch with a test inserting two
   entries differing only in context.
4. **Verifier limit.** Believed negligible, but must be measured, especially
   `--dwarf`.
5. **Wrong offset → confidently wrong output.** Mitigated by the plausibility
   guard and rejection counter.
6. **Cardinality growth in `counts`** (16392 max). Believed near-zero; instrument
   by logging occupancy at shutdown before and after.
7. **Endianness on aarch64.** LE only. A BE arm64 kernel needs a `bpfeb` object
   anyway, and nothing currently builds one. Degrade to mode 0.

**Open questions — verify, do not assume**

1. **Does `__preempt_count` still exist as a standalone percpu symbol on 6.6+?**
   Partially resolved: current mainline
   `arch/x86/include/asm/preempt.h` declares
   `DECLARE_PER_CPU_CACHE_HOT(int, __preempt_count)` and accesses it as a bare
   per-CPU variable (`per_cpu(__preempt_count, cpu)`, `raw_cpu_read_4`) — *not* a
   `pcpu_hot` member. So chain step 1 appears valid on mainline, and the
   `_CACHE_HOT` declaration macro superseded the hot-struct grouping. Still
   unverified on the intermediate 6.6–6.12 range where `pcpu_hot` existed; keep
   steps 2 and 3 as fallbacks and confirm on real hosts.
2. **Are vmlinux BTF `.data..percpu` DATASEC offsets relative to
   `__per_cpu_start`?** Believed yes; unconfirmed against
   `__per_cpu_end - __per_cpu_start`. Verify before using BTF as the x86 offset
   *source* rather than a cross-check.
3. **Does the verifier actually prune the disabled path?** Expected on 5.2+, but
   `read_volatile` interacts with this in a way worth measuring.
4. **Do GitHub-hosted `ubuntu-*-arm` runners allow eBPF perf_event sampling and
   expose `/sys/kernel/btf/vmlinux`?** The aarch64 CI plan depends on it.
5. **On which x86 configurations does the perf software CpuClock hrtimer run from
   the timer softirq rather than the APIC hardirq?** Determines whether the static
   `PREEMPT_SELF_HARDIRQ = 1` default suffices or calibration is mandatory.
6. **Should context frames be inserted into the stack (as today) or become a
   separate dimension?** A `--group-by-context` flag placing it above the process
   frame may read better. Deferred; not a blocker.
7. **Is `offsetof(task_struct, thread_info) == 0` guaranteed on aarch64?**
   Believed yes, but read it from BTF rather than hard-coding — costs nothing.

## 11. Critical files

- `profile-bee/src/trace_handler.rs` — `SymbolFormatter` context logic,
  `stack_cache_key`, `format_stack_trace`, tests
- `profile-bee-ebpf/src/lib.rs` — globals, `collect_trace`, the 8 `StackInfo`
  construction sites (314, 445, 514, 594, 631, 1065, 1310, 1651)
- `profile-bee-common/src/lib.rs` — `StackInfo`, `EXEC_CTX_*`,
  `DwarfUnwindState`
- `profile-bee/src/ebpf.rs` — `load_ebpf` / `override_global` chain, perf event
  config
- `profile-bee/src/kernel_layout.rs` — **new**: BTF reader, kallsyms, RT
  detection
- `profile-bee/src/cache.rs` — `PointerStackFramesCache` key widening
- `profile-bee/ebpf-bin/profile-bee.bpf.o` — must be regenerated in the same
  commit as any `StackInfo` change
