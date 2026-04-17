//! V8 heap object reader — read JSFunction, SharedFunctionInfo, Script, and
//! String objects from a live V8 process's memory via `process_vm_readv(2)`.
//!
//! This is the userspace half of V8 symbol resolution. Given a heap pointer
//! (extracted by the eBPF V8 unwinder from the FP context), this module
//! chases the object graph to extract JavaScript function names, source file
//! paths, and line numbers.

use std::collections::HashMap;
use std::io;

use super::types::{self, V8IntrospectionData};

/// Reader for V8 heap objects in a target process.
pub struct V8HeapReader {
    pid: u32,
    data: V8IntrospectionData,
    /// Cache: heap address → resolved string
    string_cache: HashMap<u64, String>,
    /// Cache: SFI address → (function_name, source_file)
    sfi_cache: HashMap<u64, (String, Option<String>)>,
}

/// Result of resolving a V8 frame to a human-readable symbol.
#[derive(Debug, Clone)]
pub struct V8Symbol {
    /// JavaScript function name (e.g., "processData")
    pub function_name: String,
    /// Source file path (e.g., "/app/server.js")
    pub source_file: Option<String>,
    /// Source line number (1-indexed)
    pub line_number: Option<u32>,
}

impl V8HeapReader {
    pub fn new(pid: u32, data: V8IntrospectionData) -> Self {
        Self {
            pid,
            data,
            string_cache: HashMap::new(),
            sfi_cache: HashMap::new(),
        }
    }

    /// Resolve a SharedFunctionInfo tagged pointer to a JS symbol.
    ///
    /// The SFI pointer comes from the eBPF V8 unwinder (extracted from the
    /// JSFunction in the FP context). This chases:
    ///   SFI → name_or_scope_info → function name
    ///   SFI → script_or_debug_info → Script → source file name
    pub fn resolve_sfi(&mut self, sfi_tagged: u64) -> Option<V8Symbol> {
        if !types::is_heap_object(sfi_tagged) {
            return None;
        }
        let sfi_addr = types::untag_ptr(sfi_tagged);

        // Check cache
        if let Some((name, source)) = self.sfi_cache.get(&sfi_addr) {
            return Some(V8Symbol {
                function_name: name.clone(),
                source_file: source.clone(),
                line_number: None,
            });
        }

        // Verify it's a SharedFunctionInfo
        let instance_type = self.read_instance_type(sfi_addr)?;
        if instance_type != self.data.type_shared_function_info {
            tracing::trace!(
                "not a SharedFunctionInfo at {:#x}: type={}",
                sfi_addr,
                instance_type
            );
            return None;
        }

        // Read function name from SFI.name_or_scope_info
        let function_name = self
            .read_sfi_name(sfi_addr)
            .unwrap_or_else(|| "<anonymous>".to_string());

        // Read source file from SFI.script_or_debug_info → Script.name
        let source_file = self.read_sfi_source_file(sfi_addr);

        let result = (function_name.clone(), source_file.clone());
        self.sfi_cache.insert(sfi_addr, result);

        Some(V8Symbol {
            function_name,
            source_file,
            line_number: None,
        })
    }

    /// Read the function name from SharedFunctionInfo.name_or_scope_info.
    fn read_sfi_name(&mut self, sfi_addr: u64) -> Option<String> {
        let nos_tagged = self.read_ptr(sfi_addr + self.data.off_sfi_name_or_scope_info as u64)?;

        if !types::is_heap_object(nos_tagged) {
            return None;
        }
        let nos_addr = types::untag_ptr(nos_tagged);
        let nos_type = self.read_instance_type(nos_addr)?;

        if nos_type == self.data.type_scope_info {
            // ScopeInfo — use heuristic to find function name string
            // (ScopeInfo layout changes frequently, so we scan for the first string)
            self.extract_name_from_scope_info(nos_addr)
        } else if nos_type < self.data.first_nonstring_type {
            // It's a String — read directly
            self.read_v8_string(nos_tagged)
        } else {
            None
        }
    }

    /// Extract function name from a ScopeInfo object using the OTel heuristic.
    ///
    /// ScopeInfo layout changes across V8 versions. We scan slots after the
    /// reserved header looking for the first valid string (the function name).
    fn extract_name_from_scope_info(&mut self, scope_addr: u64) -> Option<String> {
        // Skip the header — start scanning from a few pointer-sized slots in.
        // The header size varies, but function name is typically within the
        // first 16 slots after the fixed header.
        let ptr_size = 8u64;
        let start = scope_addr + 3 * ptr_size; // skip Map + flags + a couple reserved slots

        for i in 0..16u64 {
            let tagged = self.read_ptr(start + i * ptr_size)?;
            if !types::is_heap_object(tagged) {
                continue;
            }
            let addr = types::untag_ptr(tagged);
            if let Some(instance_type) = self.read_instance_type(addr) {
                if instance_type < self.data.first_nonstring_type {
                    // Found a string — likely the function name
                    if let Some(s) = self.read_v8_string(tagged) {
                        if !s.is_empty() {
                            return Some(s);
                        }
                    }
                }
            }
        }
        None
    }

    /// Read the source file path from SFI → Script.name.
    fn read_sfi_source_file(&mut self, sfi_addr: u64) -> Option<String> {
        let script_tagged =
            self.read_ptr(sfi_addr + self.data.off_sfi_script_or_debug_info as u64)?;
        if !types::is_heap_object(script_tagged) {
            return None;
        }
        let script_addr = types::untag_ptr(script_tagged);
        let script_type = self.read_instance_type(script_addr)?;
        if script_type != self.data.type_script {
            return None;
        }

        let name_tagged = self.read_ptr(script_addr + self.data.off_script_name as u64)?;
        self.read_v8_string(name_tagged)
    }

    /// Read the instance type of a heap object: HeapObject.map → Map.instance_type.
    fn read_instance_type(&self, addr: u64) -> Option<u16> {
        let map_tagged = self.read_ptr(addr + self.data.off_heap_object_map as u64)?;
        if !types::is_heap_object(map_tagged) {
            return None;
        }
        let map_addr = types::untag_ptr(map_tagged);
        self.read_u16(map_addr + self.data.off_map_instance_type as u64)
    }

    /// Read a V8 string from a tagged pointer. Handles Seq, Cons, and Thin strings.
    fn read_v8_string(&mut self, tagged: u64) -> Option<String> {
        if !types::is_heap_object(tagged) {
            return None;
        }
        let addr = types::untag_ptr(tagged);

        // Check cache
        if let Some(cached) = self.string_cache.get(&addr) {
            return Some(cached.clone());
        }

        let result = self.extract_string(addr, 0);

        if let Some(ref s) = result {
            // Cache with a 1KB limit
            if s.len() <= 1024 {
                self.string_cache.insert(addr, s.clone());
            }
        }

        result
    }

    /// Extract string content from a V8 string object.
    fn extract_string(&mut self, addr: u64, depth: usize) -> Option<String> {
        if depth > 10 {
            return None; // prevent infinite recursion on cons strings
        }

        let instance_type = self.read_instance_type(addr)?;
        if instance_type >= self.data.first_nonstring_type {
            return None; // not a string type
        }

        let rep_tag = instance_type & self.data.string_representation_mask;
        let enc_tag = instance_type & self.data.string_encoding_mask;

        if rep_tag == self.data.seq_string_tag {
            // Sequential string
            if enc_tag == self.data.one_byte_string_tag {
                return self.read_seq_one_byte_string(addr);
            }
            // Two-byte strings not supported
            return None;
        }

        if rep_tag == self.data.cons_string_tag {
            // Cons string = first + second
            let first_tagged = self.read_ptr(addr + self.data.off_cons_string_first as u64)?;
            let second_tagged = self.read_ptr(addr + self.data.off_cons_string_second as u64)?;

            let first = if types::is_heap_object(first_tagged) {
                self.extract_string(types::untag_ptr(first_tagged), depth + 1)
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let second = if types::is_heap_object(second_tagged) {
                self.extract_string(types::untag_ptr(second_tagged), depth + 1)
                    .unwrap_or_default()
            } else {
                String::new()
            };

            return Some(format!("{}{}", first, second));
        }

        if rep_tag == self.data.thin_string_tag {
            // Thin string = indirection
            let actual_tagged = self.read_ptr(addr + self.data.off_thin_string_actual as u64)?;
            if types::is_heap_object(actual_tagged) {
                return self.extract_string(types::untag_ptr(actual_tagged), depth + 1);
            }
            return None;
        }

        // SlicedString, ExternalString — not supported
        None
    }

    /// Read a SeqOneByteString: length at String.length, chars at SeqOneByteString.chars.
    fn read_seq_one_byte_string(&self, addr: u64) -> Option<String> {
        let length = self.read_u32(addr + self.data.off_string_length as u64)? as usize;
        if length == 0 || length > 16 * 1024 {
            return if length == 0 {
                Some(String::new())
            } else {
                None // refuse to read huge strings
            };
        }

        let chars_addr = addr + self.data.off_seq_one_byte_string_chars as u64;
        let bytes = self.read_bytes(chars_addr, length)?;
        Some(String::from_utf8_lossy(&bytes).to_string())
    }

    // ── Low-level memory reading via process_vm_readv ──────────────

    /// Read a pointer (8 bytes) from the target process's memory.
    fn read_ptr(&self, addr: u64) -> Option<u64> {
        let bytes = self.read_bytes(addr, 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Read a u32 from the target process's memory.
    fn read_u32(&self, addr: u64) -> Option<u32> {
        let bytes = self.read_bytes(addr, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Read a u16 from the target process's memory.
    fn read_u16(&self, addr: u64) -> Option<u16> {
        let bytes = self.read_bytes(addr, 2)?;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Read `len` bytes from the target process at `addr` via process_vm_readv.
    fn read_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];

        let local_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: len,
        };
        let remote_iov = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: len,
        };

        let ret = unsafe {
            libc::process_vm_readv(
                self.pid as libc::pid_t,
                &local_iov as *const libc::iovec,
                1,
                &remote_iov as *const libc::iovec,
                1,
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            tracing::trace!(
                "process_vm_readv(pid={}, addr={:#x}, len={}) failed: {}",
                self.pid,
                addr,
                len,
                err
            );
            return None;
        }
        if (ret as usize) < len {
            return None;
        }

        Some(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v8_heap_reader_creation() {
        let data = V8IntrospectionData::default();
        let reader = V8HeapReader::new(1, data);
        assert_eq!(reader.pid, 1);
    }
}
