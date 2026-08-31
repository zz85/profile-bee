//! Out-of-process HotSpot VM-structs reader (foundation for true Java frame
//! reconstruction — naming interpreted methods and de-inlining compiled ones).
//!
//! HotSpot's `libjvm.so` exports a serviceability-agent table describing the
//! runtime layout of its own C++ structs:
//!
//! - `gHotSpotVMStructs` — pointer to an array of `VMStructEntry`
//! - `gHotSpotVMStructEntry{TypeName,FieldName,Offset,Address}Offset` — the byte
//!   offsets of each field *within* a `VMStructEntry` (so the layout is
//!   self-describing and version-independent)
//! - `gHotSpotVMStructEntryArrayStride` — size of one entry
//!
//! Each entry is `{ typeName: char*, fieldName: char*, typeString: char*,
//! isStatic: int, offset: u64, address: void* }`. We walk the array, matching
//! `(typeName, fieldName)` pairs, and record the `offset` values we need to
//! chase `Method* → ConstMethod* → ConstantPool* → Symbol` (method name) and
//! `ConstantPool → InstanceKlass → Symbol` (class name).
//!
//! Unlike the V8 `v8dbg_*` constants (compile-time values baked into the ELF),
//! these are populated at JVM startup, so every field must be read from the
//! *live* process via `process_vm_readv(2)` at the symbol's runtime address.
//!
//! This module is the userspace half. Shipping the per-frame `Method*` from the
//! eBPF unwinder (mirroring the V8 `v8_sfi` side-channel) is the remaining
//! step; see `docs/java_profiling.md`.

use object::{Object, ObjectSymbol};
use std::collections::HashMap;
use std::io;

use super::find_libjvm_path;

/// Resolved HotSpot struct-field offsets for one JVM process.
///
/// Every offset defaults to `-1` (unresolved). `is_complete()` reports whether
/// the minimum set needed for method naming was found.
#[derive(Debug, Clone)]
pub struct VmOffsets {
    // Method -> ConstMethod*
    pub method_constmethod: i32,
    // ConstMethod -> ConstantPool* and the u2 name/signature indices
    pub constmethod_constants: i32,
    pub constmethod_name_index: i32,
    pub constmethod_signature_index: i32,
    // ConstantPool -> InstanceKlass* (holder)
    pub pool_holder: i32,
    // InstanceKlass/Klass -> Symbol* (class name)
    pub klass_name: i32,
    // Symbol layout: length (or length_and_refcount) + inline utf8 body
    pub symbol_length: i32,
    pub symbol_length_and_refcount: i32,
    pub symbol_body: i32,
    /// `sizeof(ConstantPool)` — the symbol-slot array begins right after the
    /// ConstantPool object, so `symbol_at(i) = *(base + size + i*8)`.
    pub constantpool_size: i32,
}

impl Default for VmOffsets {
    /// Delegates to `new()` so unresolved offsets are `-1` sentinels, not `0`
    /// (a derived `Default` of `0` would make `is_complete()` lie).
    fn default() -> Self {
        Self::new()
    }
}

impl VmOffsets {
    fn new() -> Self {
        Self {
            method_constmethod: -1,
            constmethod_constants: -1,
            constmethod_name_index: -1,
            constmethod_signature_index: -1,
            pool_holder: -1,
            klass_name: -1,
            symbol_length: -1,
            symbol_length_and_refcount: -1,
            symbol_body: -1,
            constantpool_size: -1,
        }
    }

    /// True if the offsets required to resolve a `Method*` to a name are present.
    pub fn is_complete(&self) -> bool {
        self.method_constmethod >= 0
            && self.constmethod_constants >= 0
            && self.constmethod_name_index >= 0
            && self.constmethod_signature_index >= 0
            && self.pool_holder >= 0
            && self.klass_name >= 0
            && self.symbol_body >= 0
            && self.constantpool_size >= 0
            && (self.symbol_length >= 0 || self.symbol_length_and_refcount >= 0)
    }
}

/// Reads a live JVM's memory to resolve HotSpot struct offsets.
pub struct VmStructsReader {
    pid: u32,
    /// Runtime load bias for libjvm.so (`runtime_addr = link_vaddr + bias`).
    bias: u64,
}

impl VmStructsReader {
    /// Locate `libjvm.so` for `pid`, compute its load bias, and prepare a reader.
    pub fn new(pid: u32) -> Option<Self> {
        let bias = libjvm_load_bias(pid)?;
        Some(Self { pid, bias })
    }

    // ── remote memory ────────────────────────────────────────────
    fn read_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: len,
        };
        let ret =
            unsafe { libc::process_vm_readv(self.pid as libc::pid_t, &local, 1, &remote, 1, 0) };
        if ret < 0 || (ret as usize) < len {
            return None;
        }
        Some(buf)
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.read_bytes(addr, 8)?.try_into().ok()?,
        ))
    }
    fn read_i32(&self, addr: u64) -> Option<i32> {
        Some(i32::from_le_bytes(
            self.read_bytes(addr, 4)?.try_into().ok()?,
        ))
    }

    /// Read a NUL-terminated C string from the target at `addr` (bounded).
    fn read_cstr(&self, addr: u64) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let bytes = self.read_bytes(addr, 64)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    /// Parse `gHotSpotVMStructs` from the live process and extract needed offsets.
    pub fn resolve_offsets(&self) -> io::Result<VmOffsets> {
        // Load libjvm.so from disk to resolve the exported data-symbol addresses.
        let path = find_libjvm_path(self.pid)
            .ok_or_else(|| io::Error::other("libjvm.so path not found"))?;
        let data = std::fs::read(&path)?;
        let elf = object::File::parse(&*data)
            .map_err(|e| io::Error::other(format!("parse {}: {e}", path.display())))?;

        let mut syms: HashMap<String, u64> = HashMap::new();
        for sym in elf.symbols().chain(elf.dynamic_symbols()) {
            if let Ok(name) = sym.name() {
                // Both the struct table (gHotSpotVMStruct*) and the type table
                // (gHotSpotVMType*) meta-symbols are needed.
                if name.starts_with("gHotSpotVM") {
                    syms.entry(name.to_string()).or_insert(sym.address());
                }
            }
        }

        // Read a `void*`/`uintptr` value that a gHotSpot* symbol points at.
        let read_sym = |name: &str| -> Option<u64> {
            let &link_vaddr = syms.get(name)?;
            self.read_u64(link_vaddr.wrapping_add(self.bias))
        };

        let entry0 = read_sym("gHotSpotVMStructs")
            .ok_or_else(|| io::Error::other("cannot read gHotSpotVMStructs"))?;
        let stride = read_sym("gHotSpotVMStructEntryArrayStride")
            .ok_or_else(|| io::Error::other("cannot read entry stride"))?;
        let type_off = read_sym("gHotSpotVMStructEntryTypeNameOffset")
            .ok_or_else(|| io::Error::other("cannot read type-name offset"))?;
        let field_off = read_sym("gHotSpotVMStructEntryFieldNameOffset")
            .ok_or_else(|| io::Error::other("cannot read field-name offset"))?;
        let offset_off = read_sym("gHotSpotVMStructEntryOffsetOffset")
            .ok_or_else(|| io::Error::other("cannot read offset offset"))?;

        if entry0 == 0 || stride == 0 {
            return Err(io::Error::other("null VMStructs table"));
        }

        let mut out = VmOffsets::new();
        let mut entry = entry0;
        // Bounded walk: the table is a few thousand entries; cap to be safe.
        for _ in 0..20_000 {
            let type_ptr = self.read_u64(entry.wrapping_add(type_off)).unwrap_or(0);
            let field_ptr = self.read_u64(entry.wrapping_add(field_off)).unwrap_or(0);
            if type_ptr == 0 || field_ptr == 0 {
                break; // sentinel terminator
            }
            let ty = self.read_cstr(type_ptr).unwrap_or_default();
            let field = self.read_cstr(field_ptr).unwrap_or_default();
            let off = || self.read_i32(entry.wrapping_add(offset_off)).unwrap_or(-1);

            match (ty.as_str(), field.as_str()) {
                ("Method", "_constMethod") => out.method_constmethod = off(),
                ("ConstMethod", "_constants") => out.constmethod_constants = off(),
                ("ConstMethod", "_name_index") => out.constmethod_name_index = off(),
                ("ConstMethod", "_signature_index") => out.constmethod_signature_index = off(),
                ("ConstantPool", "_pool_holder") => out.pool_holder = off(),
                ("Klass", "_name") => out.klass_name = off(),
                ("Symbol", "_length") => out.symbol_length = off(),
                ("Symbol", "_length_and_refcount") => out.symbol_length_and_refcount = off(),
                ("Symbol", "_body") => out.symbol_body = off(),
                _ => {}
            }
            entry = entry.wrapping_add(stride);
        }

        // Parse gHotSpotVMTypes for sizeof(ConstantPool) (symbol-slot base).
        if let (Some(t0), Some(tstride), Some(tname_off), Some(tsize_off)) = (
            read_sym("gHotSpotVMTypes"),
            read_sym("gHotSpotVMTypeEntryArrayStride"),
            read_sym("gHotSpotVMTypeEntryTypeNameOffset"),
            read_sym("gHotSpotVMTypeEntrySizeOffset"),
        ) {
            let mut te = t0;
            for _ in 0..20_000 {
                let name_ptr = self.read_u64(te.wrapping_add(tname_off)).unwrap_or(0);
                if name_ptr == 0 {
                    break;
                }
                if self.read_cstr(name_ptr).as_deref() == Some("ConstantPool") {
                    out.constantpool_size = self.read_i32(te.wrapping_add(tsize_off)).unwrap_or(-1);
                    break;
                }
                te = te.wrapping_add(tstride);
            }
        }

        Ok(out)
    }

    /// Resolve a live `Method*` to a display name `pkg.Class.method`.
    ///
    /// Chases `Method → ConstMethod → ConstantPool`, reads the method-name
    /// Symbol via the constant-pool slot at `_name_index`, and the class-name
    /// Symbol via `_pool_holder → Klass._name`. All reads are bounds-guarded;
    /// any failure yields `None` (caller keeps the raw frame).
    pub fn resolve_method_name(&self, o: &VmOffsets, method: u64) -> Option<String> {
        if !o.is_complete() || method == 0 {
            return None;
        }
        let const_method = self.read_u64(method.wrapping_add(o.method_constmethod as u64))?;
        let cpool = self.read_u64(const_method.wrapping_add(o.constmethod_constants as u64))?;
        if const_method == 0 || cpool == 0 {
            return None;
        }

        // Class name: ConstantPool -> _pool_holder (Klass) -> _name (Symbol).
        let holder = self.read_u64(cpool.wrapping_add(o.pool_holder as u64))?;
        let class_sym = self.read_u64(holder.wrapping_add(o.klass_name as u64))?;
        let class_name = self.read_symbol(o, class_sym).map(|s| s.replace('/', "."));

        // Method name: ConstMethod._name_index -> ConstantPool symbol slot.
        let method_name = if o.constantpool_size >= 0 {
            let name_idx =
                self.read_u16(const_method.wrapping_add(o.constmethod_name_index as u64))?;
            let slot = cpool
                .wrapping_add(o.constantpool_size as u64)
                .wrapping_add((name_idx as u64).wrapping_mul(8));
            let sym = self.read_u64(slot)?;
            self.read_symbol(o, sym)
        } else {
            None
        };

        match (class_name, method_name) {
            (Some(c), Some(m)) => Some(format!("{c}.{m}")),
            (Some(c), None) => Some(c),
            (None, Some(m)) => Some(m),
            (None, None) => None,
        }
    }

    fn read_u16(&self, addr: u64) -> Option<u16> {
        Some(u16::from_le_bytes(
            self.read_bytes(addr, 2)?.try_into().ok()?,
        ))
    }

    /// Read a HotSpot `Symbol`'s UTF-8 body (`_length` u16 + inline `_body`).
    fn read_symbol(&self, o: &VmOffsets, sym: u64) -> Option<String> {
        if sym == 0 {
            return None;
        }
        let len = if o.symbol_length >= 0 {
            self.read_u16(sym.wrapping_add(o.symbol_length as u64))? as usize
        } else if o.symbol_length_and_refcount >= 0 {
            // JDK 9+: `_length_and_refcount` is a u32 with length in the HIGH
            // 16 bits and refcount in the low 16.
            let raw = u32::from_le_bytes(
                self.read_bytes(sym.wrapping_add(o.symbol_length_and_refcount as u64), 4)?
                    .try_into()
                    .ok()?,
            );
            (raw >> 16) as usize
        } else {
            return None;
        };
        if len == 0 || len > 4096 {
            return None;
        }
        let body = self.read_bytes(sym.wrapping_add(o.symbol_body as u64), len)?;
        decode_symbol_body(&body)
    }
}

/// Decode a HotSpot Symbol UTF-8 body to a Rust string (lossy on bad bytes).
fn decode_symbol_body(body: &[u8]) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(body).into_owned())
}

/// Compute the runtime load bias of `libjvm.so` in `pid` so that a link-time
/// symbol vaddr maps to a live address: `runtime = link_vaddr + bias`.
///
/// For a normal shared object the first `PT_LOAD` has `p_vaddr == 0`, so the
/// bias is the base of the mapping at file offset 0. We derive it from
/// `/proc/<pid>/maps` via procfs, matching the mapped `libjvm.so`.
fn libjvm_load_bias(pid: u32) -> Option<u64> {
    use procfs::process::{MMapPath, Process};
    let proc = Process::new(pid as i32).ok()?;
    let maps = proc.maps().ok()?;
    // The mapping with file offset 0 is the ELF header; its start is the base
    // (link base 0 for .so). Fall back to the lowest libjvm mapping start.
    let mut base: Option<u64> = None;
    for m in maps.iter() {
        if let MMapPath::Path(p) = &m.pathname {
            let s = p.to_string_lossy();
            let s = s.strip_suffix(" (deleted)").unwrap_or(&s);
            if s.ends_with("libjvm.so") {
                if m.offset == 0 {
                    return Some(m.address.0);
                }
                base = Some(base.map_or(m.address.0, |b: u64| b.min(m.address.0)));
            }
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_symbol_body() {
        assert_eq!(decode_symbol_body(b"fib").as_deref(), Some("fib"));
        assert_eq!(
            decode_symbol_body(b"java/lang/String").as_deref(),
            Some("java/lang/String")
        );
        assert_eq!(decode_symbol_body(b""), None);
    }

    #[test]
    fn offsets_incomplete_by_default() {
        // A freshly constructed offset set must not claim completeness.
        assert!(!VmOffsets::default().is_complete());
    }
}
