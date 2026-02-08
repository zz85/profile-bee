# DWARF Unwinding Analysis - Navigation Guide

This directory contains comprehensive analysis of the `dwarf_unwind_wip` and `dwarf_unwind_wip2` branches, extracting insights for implementing DWARF-based stack unwinding.

## Quick Start

**Want to implement DWARF unwinding?** 
→ Start with **[implementation_guide.md](implementation_guide.md)**

**Want to understand the WIP branches?** 
→ Read **[DWARF_ANALYSIS_SUMMARY.md](DWARF_ANALYSIS_SUMMARY.md)**

## Document Overview

### [DWARF_ANALYSIS_SUMMARY.md](DWARF_ANALYSIS_SUMMARY.md) ⭐ START HERE
**Executive summary of everything learned**
- What was discovered
- Critical findings (RSP capture, simplified DWARF model)
- Implementation path (Phase 1 & 2)
- Timeline estimates (~1 week)
- Success criteria
- Risk assessment

**Read this first** for high-level understanding.

### [implementation_guide.md](implementation_guide.md) ⭐ FOR DEVELOPERS
**Step-by-step implementation instructions**
- Prerequisites and setup
- 10 detailed steps with code
- Dependency updates
- Build and test procedures
- Troubleshooting guide
- Validation strategy

**Use this** to actually implement DWARF unwinding.

### [wip_insights.md](wip_insights.md) 💡 KEY INSIGHTS
**Top 10 actionable insights from WIP branches**
- Simplified DWARF model explained
- DwarfDelta innovation (wip2)
- Missing RSP capture issue
- Actual unwinding algorithm
- gimli integration pattern
- Memory reading challenge
- Performance optimization
- Testing strategy
- Module organization
- Implementation roadmap

**Read this** to understand the "why" behind the implementation.

### [wip_branches_comparison.md](wip_branches_comparison.md) 📊 DETAILED ANALYSIS
**Comprehensive technical comparison**
- Branch details (wip1 vs wip2)
- Architecture differences
- Code component analysis
- Comparison matrix
- Code reuse opportunities
- Migration path
- Challenges identified

**Read this** for deep technical details.

### [dwarf_unwinding_design.md](dwarf_unwinding_design.md) 🏗️ ARCHITECTURE
**Original architecture documentation**
- eBPF vs userland unwinding
- Hybrid strategy rationale
- Flow diagrams
- Current implementation status
- Design decisions

**Read this** for architectural context.

## Information Flow

```
1. DWARF_ANALYSIS_SUMMARY.md
   ↓ (Get overview)
   
2. wip_insights.md
   ↓ (Understand key concepts)
   
3. implementation_guide.md
   ↓ (Follow step-by-step)
   
4. wip_branches_comparison.md
   ↓ (Deep dive on specific details)
   
5. dwarf_unwinding_design.md
   (Reference for architecture)
```

## Key Takeaways

### What We Learned

1. **Working code exists** in wip2 branch (~500 lines ready to extract)
2. **Simplified DWARF works** (no need for complex expression evaluation)
3. **RSP capture missing** (easy fix: add to StackInfo)
4. **Clear implementation path** (detailed in implementation guide)
5. **Two-phase approach** (userspace now, eBPF later)

### What to Do Next

**Option 1: Quick Understanding (15 min)**
→ Read DWARF_ANALYSIS_SUMMARY.md

**Option 2: Deep Understanding (1 hour)**
→ Read all docs in order

**Option 3: Start Implementing (1 week)**
→ Follow implementation_guide.md step-by-step

## Code Locations in WIP Branches

### wip2 (commit 163c972) - Most Complete

**Core modules to extract**:
- `profile-bee/src/unwinder/ehframe.rs` - DWARF parsing (250 lines)
- `profile-bee/src/unwinder/maps.rs` - Memory maps (100 lines)
- `profile-bee/src/unwinder/mod.rs` - Main logic

**Data structures**:
- `profile-bee-common/src/lib.rs` - DwarfDelta, DwarfUnwindInfo

**eBPF integration**:
- `profile-bee-ebpf/src/lib.rs` - RSP capture
- `profile-bee-ebpf/src/pt_regs.rs` - Register helpers

**Test programs**:
- `sample/fibonacci.rs` - Deep recursion test
- `sample/inefficient.rs` - Complex calls test

### wip1 (commit c153343) - Basic Implementation

Simpler but less complete. Use wip2 as primary source.

## Dependencies to Add

```toml
[dependencies]
procmaps = "0.7"  # Better /proc/maps parsing
nix = { version = "0.29", features = ["process"] }  # For process_vm_readv
```

## Timeline

- **Phase 1** (Userspace unwinding): 2-3 days implementation + 1-2 days testing
- **Phase 2** (eBPF unwinding): 3-4 days (future work)

**Total for Phase 1**: ~1 week

## Success Metrics

Implementation successful when:
- ✅ Builds without errors
- ✅ All tests pass
- ✅ Works with FP binaries (matches FP results)
- ✅ Works with non-FP binaries (complete stacks)
- ✅ Performance acceptable (<10% overhead)

## Questions?

Refer to specific documents:

- **How does it work?** → wip_insights.md #5 (Unwinding Algorithm)
- **What needs to change?** → implementation_guide.md
- **Why userspace?** → dwarf_unwinding_design.md (Why Not DWARF in eBPF)
- **What's the risk?** → DWARF_ANALYSIS_SUMMARY.md (Risk Assessment)
- **How long will it take?** → DWARF_ANALYSIS_SUMMARY.md (Timeline Estimate)

## Repository Structure

```
docs/
├── README_DWARF_ANALYSIS.md          ← You are here
├── DWARF_ANALYSIS_SUMMARY.md         ← Start here
├── implementation_guide.md            ← How to implement
├── wip_insights.md                    ← Key insights
├── wip_branches_comparison.md         ← Detailed comparison
└── dwarf_unwinding_design.md          ← Architecture
```

## Additional Resources

- [Polar Signals Blog](https://www.polarsignals.com/blog/posts/2022/11/29/profiling-without-frame-pointers) - DWARF unwinding explanation
- [gimli Documentation](https://docs.rs/gimli/) - DWARF parser library
- [DWARF Standard](http://dwarfstd.org/) - Official specification

## Contact

For questions or clarifications, refer to the issue discussion or PR comments.

---

**Last Updated**: 2026-02-07
**Analysis of**: dwarf_unwind_wip (c153343) and dwarf_unwind_wip2 (163c972)
**Current Branch**: copilot/support-dwarf-no-frame-pointer
