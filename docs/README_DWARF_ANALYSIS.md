# DWARF Unwinding Analysis - Navigation Guide

This directory contains analysis and documentation for the DWARF-based stack unwinding implementation.

## Quick Start

**Want to implement DWARF unwinding?**
→ Start with **[implementation_guide.md](implementation_guide.md)**

**Want to understand the architecture?**
→ Read **[dwarf_unwinding_design.md](dwarf_unwinding_design.md)**

## Document Overview

### [DWARF_ANALYSIS_SUMMARY.md](DWARF_ANALYSIS_SUMMARY.md) ⭐ START HERE
Executive summary: current status, critical findings, implementation path, risk assessment.

### [implementation_guide.md](implementation_guide.md) ⭐ FOR DEVELOPERS
Step-by-step instructions to complete the DWARF unwinding algorithm. Covers RSP capture, memory reading, unwinding loop, and TraceHandler integration.

### [dwarf_unwinding_design.md](dwarf_unwinding_design.md) 🏗️ ARCHITECTURE
Hybrid eBPF/userspace architecture, flow diagrams, design rationale, and the simplified DWARF model.

### [wip_insights.md](wip_insights.md) 💡 KEY INSIGHTS
Top 10 actionable insights from WIP branch analysis: simplified DWARF model, DwarfDelta innovation, gimli integration patterns, performance optimization.

### [wip_branches_comparison.md](wip_branches_comparison.md) 📊 HISTORICAL ANALYSIS
Technical comparison of the `dwarf_unwind_wip` and `dwarf_unwind_wip2` branches. Note: this is historical context — the wip2 code is now the active implementation in `profile-bee/src/unwinder/`.

## Code Location

The DWARF unwinding code lives in:

```
profile-bee/src/unwinder/
├── mod.rs       - Main logic (get_mappings, find_instruction, get_unwind_table)
├── ehframe.rs   - DWARF .eh_frame parsing (UnwindTable, UnwindTableRow, Instruction)
└── maps.rs      - Process memory maps (AddressMap, AddressEntry)
```

Supporting structures in `profile-bee-common/src/lib.rs`: `DwarfDelta`, `DwarfUnwindInfo`, `StackInfo`.

## What's Left to Implement

1. Add RSP to `StackInfo`, capture in eBPF
2. Process memory reading (`process_vm_readv`)
3. Unwinding loop
4. TraceHandler integration

See `implementation_guide.md` for details.
