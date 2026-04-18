//! V8-specific types and constants for heap introspection.
//!
//! V8 uses tagged pointers where the low bits indicate the value type:
//! - SMI (Small Integer): LSB == 0, value in upper 32 bits
//! - HeapObject pointer: low 2 bits == 01, rest is the address
//!
//! All constants here match V8's `v8dbg_*` symbol scheme and are valid
//! for V8 8.1+ (Node.js 14+).

/// V8 tagged pointer constants (stable across versions).
pub const SMI_TAG: u64 = 0x0;
pub const SMI_TAG_MASK: u64 = 0x1;
pub const SMI_VALUE_SHIFT: u32 = 32;

pub const HEAP_OBJECT_TAG: u64 = 0x1;
pub const HEAP_OBJECT_TAG_MASK: u64 = 0x3;

/// Size of the FP context buffer read by the eBPF V8 unwinder.
/// The eBPF code reads this many bytes from [fp - FP_CONTEXT_SIZE].
pub const FP_CONTEXT_SIZE: usize = 64;

/// V8 frame types for classifying stack frames.
/// Low 3 bits of the pointer field in the trace data encode the frame type.
pub const FILE_TYPE_MARKER: u64 = 0;
pub const FILE_TYPE_BYTECODE: u64 = 1;
pub const FILE_TYPE_NATIVE_SFI: u64 = 2;
pub const FILE_TYPE_NATIVE_CODE: u64 = 3;
pub const FILE_TYPE_NATIVE_JSFUNC: u64 = 4;
pub const FILE_TYPE_MASK: u64 = 7;

/// Check if a tagged value is a V8 SMI (Small Integer).
/// SMIs have their LSB set to 0.
#[inline]
pub fn is_smi(val: u64) -> bool {
    val & SMI_TAG_MASK == SMI_TAG
}

/// Decode a V8 SMI value (upper 32 bits of the tagged word).
#[inline]
pub fn decode_smi(val: u64) -> u32 {
    (val >> SMI_VALUE_SHIFT) as u32
}

/// Check if a tagged value is a V8 heap object pointer.
/// Heap objects have their low 2 bits set to 01.
#[inline]
pub fn is_heap_object(val: u64) -> bool {
    val & HEAP_OBJECT_TAG_MASK == HEAP_OBJECT_TAG
}

/// Untag a V8 heap object pointer (clear low 2 bits).
#[inline]
pub fn untag_ptr(val: u64) -> u64 {
    val & !HEAP_OBJECT_TAG_MASK
}

/// V8 string representation tags (from StringRepresentationMask).
pub const SEQ_STRING_TAG: u16 = 0;
pub const CONS_STRING_TAG: u16 = 1;
pub const SLICED_STRING_TAG: u16 = 3;
pub const THIN_STRING_TAG: u16 = 5;

// Compact V8 introspection data for the eBPF V8 unwinder is defined in
// `profile_bee_common::V8ProcInfo` (shared between eBPF and userspace).
// See `V8IntrospectionData::to_proc_info` for the conversion.

/// Full V8 introspection data parsed from v8dbg_* ELF symbols.
///
/// This contains everything needed for both eBPF (via [`V8ProcInfo`]) and
/// userspace symbolization (field offsets for reading JSFunction, SFI, Script,
/// String objects from the target process's memory).
#[derive(Debug, Clone, Default)]
pub struct V8IntrospectionData {
    /// V8 version: (major, minor, patch)
    pub version: (u32, u32, u32),

    // ── Tag constants ──────────────────────────────────────────────
    pub heap_object_tag_mask: u64,
    pub smi_tag_mask: u64,
    pub heap_object_tag: u16,
    pub smi_tag: u16,
    pub smi_shift_size: u16,
    pub first_nonstring_type: u16,
    pub string_encoding_mask: u16,
    pub string_representation_mask: u16,
    pub seq_string_tag: u16,
    pub cons_string_tag: u16,
    pub one_byte_string_tag: u16,
    pub two_byte_string_tag: u16,
    pub thin_string_tag: u16,
    pub sliced_string_tag: u16,
    pub first_jsfunction_type: u16,
    pub last_jsfunction_type: u16,

    // ── Frame pointer offsets (signed byte offsets relative to FP) ──
    pub fp_function: i8,
    pub fp_context: i8,
    pub fp_bytecode_array: i8,
    pub fp_bytecode_offset: i8,

    // ── HeapObject ─────────────────────────────────────────────────
    pub off_heap_object_map: u32,

    // ── Map ────────────────────────────────────────────────────────
    pub off_map_instance_type: u32,

    // ── JSFunction ─────────────────────────────────────────────────
    pub off_jsfunction_code: u32,
    pub off_jsfunction_shared: u32,

    // ── Code ───────────────────────────────────────────────────────
    pub off_code_instruction_start: u32,
    pub off_code_instruction_size: u32,
    pub off_code_flags: u32,
    pub off_code_deoptimization_data: u32,
    pub off_code_source_position_table: u32,

    // ── SharedFunctionInfo ─────────────────────────────────────────
    pub off_sfi_name_or_scope_info: u32,
    pub off_sfi_function_data: u32,
    pub off_sfi_script_or_debug_info: u32,

    // ── Script ─────────────────────────────────────────────────────
    pub off_script_name: u32,
    pub off_script_line_ends: u32,
    pub off_script_source: u32,

    // ── String ─────────────────────────────────────────────────────
    pub off_string_length: u32,
    pub off_seq_one_byte_string_chars: u32,
    pub off_cons_string_first: u32,
    pub off_cons_string_second: u32,
    pub off_thin_string_actual: u32,

    // ── FixedArray ─────────────────────────────────────────────────
    pub off_fixed_array_base_length: u32,
    pub off_fixed_array_data: u32,

    // ── BytecodeArray ──────────────────────────────────────────────
    pub off_bytecode_array_source_position_table: u32,

    // ── Instance types ─────────────────────────────────────────────
    pub type_jsfunction: u16,
    pub type_code: u16,
    pub type_shared_function_info: u16,
    pub type_scope_info: u16,
    pub type_script: u16,
    pub type_bytecode_array: u16,
    pub type_fixed_array: u16,
    pub type_byte_array: u16,

    // ── CodeKind ───────────────────────────────────────────────────
    pub codekind_field_mask: u32,
    pub codekind_field_shift: u8,
    pub codekind_baseline: u8,

    /// Whether Code.instruction_start is a pointer (V8 >= 11.1.204)
    pub code_instructions_is_pointer: bool,
}

impl V8IntrospectionData {
    /// Build the compact [`profile_bee_common::V8ProcInfo`] for the eBPF V8 unwinder.
    ///
    /// Returns `None` if any u32 offset exceeds the u8 range (255), which would
    /// indicate an unusual V8 build or parsing error.
    pub fn to_proc_info(&self) -> Option<profile_bee_common::V8ProcInfo> {
        let (major, minor, patch) = self.version;
        let version = (major << 24) | (minor << 16) | patch;

        // Validate that all offsets fit in u8 before constructing
        if self.off_heap_object_map > 255
            || self.off_map_instance_type > 255
            || self.off_jsfunction_shared > 255
        {
            tracing::warn!(
                "V8 offset out of u8 range: heap_object_map={}, map_instance_type={}, jsfunction_shared={}",
                self.off_heap_object_map, self.off_map_instance_type, self.off_jsfunction_shared,
            );
            return None;
        }

        Some(profile_bee_common::V8ProcInfo {
            version,
            type_jsfunction_first: self.first_jsfunction_type,
            type_jsfunction_last: self.last_jsfunction_type,
            type_code: self.type_code,
            type_shared_function_info: self.type_shared_function_info,
            off_heap_object_map: self.off_heap_object_map as u8,
            off_map_instance_type: self.off_map_instance_type as u8,
            off_jsfunction_shared: self.off_jsfunction_shared as u8,
            fp_function: map_fp_offset(self.fp_function),
            _pad: [0; 4],
        })
    }
}

/// Convert a signed FP-relative byte offset to a byte offset within the
/// 64-byte FP context buffer. Returns FP_CONTEXT_SIZE as sentinel if invalid.
fn map_fp_offset(rel_bytes: i8) -> u8 {
    let slot_offset = FP_CONTEXT_SIZE as i32 + rel_bytes as i32;
    if slot_offset < 0 || slot_offset > (FP_CONTEXT_SIZE - 8) as i32 {
        FP_CONTEXT_SIZE as u8 // invalid sentinel
    } else {
        slot_offset as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smi() {
        assert!(is_smi(0));
        assert!(is_smi(0x0000002A_00000000)); // SMI value 42
        assert!(!is_smi(0x0000002A_00000001)); // heap object
        assert_eq!(decode_smi(0x0000002A_00000000), 42);
    }

    #[test]
    fn test_heap_object() {
        assert!(is_heap_object(0x7f000001));
        assert!(!is_heap_object(0x7f000000)); // SMI
        assert!(!is_heap_object(0x7f000002)); // not heap obj tag
        assert_eq!(untag_ptr(0x7f000001), 0x7f000000);
        assert_eq!(untag_ptr(0x7f000003), 0x7f000000);
    }

    #[test]
    fn test_map_fp_offset() {
        // -24 as i8 = 0xE8 → 64 + (-24) = 40
        assert_eq!(map_fp_offset(-24), 40);
        // -16 → 48
        assert_eq!(map_fp_offset(-16), 48);
        // -8 → 56 (max valid: 64 - 8 = 56)
        assert_eq!(map_fp_offset(-8), 56);
        // Out of range
        assert_eq!(map_fp_offset(-65), FP_CONTEXT_SIZE as u8);
        assert_eq!(map_fp_offset(1), FP_CONTEXT_SIZE as u8);
    }
}
