//! OTLP Profiles export support.
//!
//! Converts profile-bee's collapse-format stack traces into the OpenTelemetry
//! Profiles protocol format and exports them via gRPC to an OTLP-compatible
//! backend (devfiler, OTel Collector, Pyroscope, etc.).
//!
//! The OTLP Profiles format uses a shared dictionary pattern where strings,
//! functions, locations, stacks, and attributes are deduplicated into tables
//! and referenced by index. This module builds those dictionary tables from
//! collapse-format stacks (e.g. "main;foo;bar 42") and constructs a valid
//! `ExportProfilesServiceRequest` for gRPC transport.
//!
//! Reference: <https://github.com/open-telemetry/opentelemetry-proto/blob/v1.10.0/opentelemetry/proto/profiles/v1development/profiles.proto>

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// Generated protobuf types from tonic-build + protox.
// Module hierarchy must match the proto package hierarchy so that
// cross-package `super::super::` references resolve correctly.
pub mod proto {
    pub mod opentelemetry {
        pub mod proto {
            pub mod common {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.common.v1");
                }
            }
            pub mod resource {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.resource.v1");
                }
            }
            pub mod profiles {
                pub mod v1development {
                    tonic::include_proto!("opentelemetry.proto.profiles.v1development");
                }
            }
            pub mod collector {
                pub mod profiles {
                    pub mod v1development {
                        tonic::include_proto!(
                            "opentelemetry.proto.collector.profiles.v1development"
                        );
                    }
                }
            }
        }
    }
}

use proto::opentelemetry::proto::collector::profiles::v1development::ExportProfilesServiceRequest;
use proto::opentelemetry::proto::common::v1::{AnyValue, KeyValue};
use proto::opentelemetry::proto::profiles::v1development::{
    Function, KeyValueAndUnit, Line, Location, Mapping, Profile, ProfilesDictionary,
    ResourceProfiles, Sample, ScopeProfiles, Stack, ValueType,
};
use proto::opentelemetry::proto::resource::v1::Resource;

// Re-export the generated gRPC client for use by the sink.
pub use proto::opentelemetry::proto::collector::profiles::v1development::profiles_service_client::ProfilesServiceClient;

// ---------------------------------------------------------------------------
// String interning (same pattern as pprof.rs)
// ---------------------------------------------------------------------------

/// Deduplicated string table. `string_table[0]` is always "".
struct StringTable {
    table: Vec<String>,
    index: HashMap<String, i32>,
}

impl StringTable {
    fn new() -> Self {
        let mut st = Self {
            table: Vec::new(),
            index: HashMap::new(),
        };
        st.intern(""); // slot 0 must be ""
        st
    }

    fn intern(&mut self, s: &str) -> i32 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = self.table.len() as i32;
        self.table.push(s.to_owned());
        self.index.insert(s.to_owned(), idx);
        idx
    }

    fn into_vec(self) -> Vec<String> {
        self.table
    }
}

// ---------------------------------------------------------------------------
// Ordered dedup set for dictionary tables
// ---------------------------------------------------------------------------

/// Insertion-ordered dedup set. Returns the index of each inserted item.
/// Index 0 is reserved for the zero/null entry (inserted by caller).
struct OrderedSet<K: std::hash::Hash + Eq + Clone> {
    map: HashMap<K, i32>,
    len: i32,
}

impl<K: std::hash::Hash + Eq + Clone> OrderedSet<K> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            len: 0,
        }
    }

    /// Insert a key, returning its index. If already present, returns existing index.
    fn insert(&mut self, key: K) -> i32 {
        if let Some(&idx) = self.map.get(&key) {
            return idx;
        }
        let idx = self.len;
        self.map.insert(key, idx);
        self.len += 1;
        idx
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Configuration for OTLP profile generation.
pub struct OtlpOptions {
    /// Service name for the resource attribute.
    pub service_name: String,
    /// Sampling frequency in Hz (default 99).
    pub frequency_hz: u64,
    /// Profiling duration in milliseconds (0 if unknown).
    pub duration_ms: u64,
    /// Whether this is off-CPU profiling.
    pub off_cpu: bool,
}

impl Default for OtlpOptions {
    fn default() -> Self {
        Self {
            service_name: "profile-bee".to_string(),
            frequency_hz: 99,
            duration_ms: 0,
            off_cpu: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Keys for dedup
// ---------------------------------------------------------------------------

/// Function identity for deduplication.
#[derive(Hash, Eq, PartialEq, Clone)]
struct FuncKey {
    name_strindex: i32,
}

/// Location identity for deduplication.
#[derive(Hash, Eq, PartialEq, Clone)]
struct LocationKey {
    function_index: i32,
    is_kernel: bool,
}

/// Stack identity: the ordered list of location indices.
#[derive(Hash, Eq, PartialEq, Clone)]
struct StackKey {
    location_indices: Vec<i32>,
}

// ---------------------------------------------------------------------------
// Conversion: collapse format -> OTLP ExportProfilesServiceRequest
// ---------------------------------------------------------------------------

/// Convert collapse-format stack strings to an OTLP `ExportProfilesServiceRequest`.
///
/// Input format: `"frame1;frame2;frame3 count"` (root to leaf, left to right).
///
/// OTLP convention: `Stack.location_indices[0]` is the **leaf** (innermost frame),
/// so the frame order is reversed during conversion. This matches what devfiler
/// and the OTel eBPF profiler expect.
pub fn collapse_to_otlp_request(
    stacks: &[String],
    opts: &OtlpOptions,
) -> ExportProfilesServiceRequest {
    let mut strings = StringTable::new();

    // Pre-intern well-known strings for sample/period types
    let (sample_type_str, sample_unit_str, period_type_str, period_unit_str) = if opts.off_cpu {
        (
            strings.intern("off_cpu"),
            strings.intern("nanoseconds"),
            strings.intern("off_cpu"),
            strings.intern("nanoseconds"),
        )
    } else {
        (
            strings.intern("samples"),
            strings.intern("count"),
            strings.intern("cpu"),
            strings.intern("nanoseconds"),
        )
    };

    // Pre-intern attribute keys
    let frame_type_key = strings.intern("profile.frame.type");
    let build_id_key = strings.intern("process.executable.build_id.htlhash");

    // Create a synthetic build ID for the profiled service so devfiler groups
    // all frames under one executable rather than creating one per function.
    let build_id_str = format!("profile-bee:{}", opts.service_name);
    let build_id_attr_val = format!("{:032x}", {
        // Simple hash of the service name to produce a stable 128-bit ID.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
        for b in build_id_str.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3); // FNV prime
        }
        h as u128 | ((h as u128) << 64)
    });

    // Dictionary tables (index 0 = zero/null entry for each)
    let mut func_set = OrderedSet::<FuncKey>::new();
    let mut functions: Vec<Function> = vec![Function::default()]; // index 0 = null
    func_set.insert(FuncKey { name_strindex: 0 }); // reserve index 0

    let mut loc_set = OrderedSet::<LocationKey>::new();
    let mut locations: Vec<Location> = vec![Location::default()]; // index 0 = null
    loc_set.insert(LocationKey {
        function_index: 0,
        is_kernel: false,
    }); // reserve index 0

    let mut stack_set = OrderedSet::<StackKey>::new();
    let mut stack_table: Vec<Stack> = vec![Stack::default()]; // index 0 = null
    stack_set.insert(StackKey {
        location_indices: vec![],
    }); // reserve index 0

    // Attribute table: index 0 = null entry
    let mut attr_table: Vec<KeyValueAndUnit> = vec![KeyValueAndUnit::default()];
    // (key_strindex, value_string) -> attr index
    let mut attr_map: HashMap<(i32, String), i32> = HashMap::new();
    attr_map.insert((0, String::new()), 0); // reserve index 0

    // Helper: get or create attribute index for (key, string_value).
    // Uses StringValue (actual string) rather than StringValueStrindex because
    // devfiler and some receivers don't support the strindex variant in attributes.
    let get_attr_index =
        |attr_table: &mut Vec<KeyValueAndUnit>,
         attr_map: &mut HashMap<(i32, String), i32>,
         key_idx: i32,
         val_str: &str| {
            *attr_map
                .entry((key_idx, val_str.to_owned()))
                .or_insert_with(|| {
                    let idx = attr_table.len() as i32;
                    attr_table.push(KeyValueAndUnit {
                        key_strindex: key_idx,
                        value: Some(AnyValue {
                            value: Some(
                                proto::opentelemetry::proto::common::v1::any_value::Value::StringValue(
                                    val_str.to_owned(),
                                ),
                            ),
                        }),
                        unit_strindex: 0,
                    });
                    idx
                })
        };

    // Pre-create the two frame-type attributes.
    //
    // We use "go" instead of "native" for user-space frames because devfiler
    // treats "native" specially: it ignores function names in the proto and
    // tries to symbolize from the binary by address. Since profile-bee has
    // already symbolized frames into function names (collapse format), we
    // need a type where devfiler reads names from the proto's function_table.
    // "go" is the closest compiled-language type and works with unmodified
    // devfiler, OTel Collector, and Pyroscope. The trade-off is a "[Go]"
    // label in devfiler's flamegraph UI.
    //
    // "kernel" frames also get their names read from the proto (not address-based).
    let native_attr_idx =
        get_attr_index(&mut attr_table, &mut attr_map, frame_type_key, "go");
    let kernel_attr_idx =
        get_attr_index(&mut attr_table, &mut attr_map, frame_type_key, "kernel");

    // Create build-ID attribute for the user-space mapping so devfiler groups
    // all frames under one executable instead of one per function.
    let build_id_attr_idx = get_attr_index(
        &mut attr_table,
        &mut attr_map,
        build_id_key,
        &build_id_attr_val,
    );

    // Mapping table: index 0 = null, index 1 = user-space executable
    let svc_filename_idx = strings.intern(&opts.service_name);
    let user_mapping_index: i32 = 1;
    // Kernel frames will use mapping index 0 (null / unknown).

    let mut samples: Vec<Sample> = Vec::new();

    for line in stacks {
        if line.is_empty() {
            continue;
        }

        // Parse "frame1;frame2;...;frameN count"
        let (stack_part, count_str) = match line.rsplit_once(' ') {
            Some(parts) => parts,
            None => {
                tracing::warn!("OTLP: skipping malformed collapse line: {}", line);
                continue;
            }
        };
        let count: i64 = match count_str.parse() {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("OTLP: skipping line with non-numeric count: {}", line);
                continue;
            }
        };

        let frames: Vec<&str> = stack_part.split(';').collect();

        // Build location indices (leaf first = reversed from collapse order)
        let mut location_indices: Vec<i32> = Vec::with_capacity(frames.len());
        for &frame in frames.iter().rev() {
            let is_kernel = frame.ends_with("_k");
            let frame_name = if is_kernel {
                &frame[..frame.len() - 2]
            } else {
                frame
            };

            let name_idx = strings.intern(frame_name);

            // Use a hash of the function name as a synthetic address so that
            // each function gets a unique FrameId in devfiler's DB.
            // Without this, all frames share address 0 and collide.
            let synthetic_addr = fnv1a_hash(frame_name.as_bytes());

            // Get or create function
            let func_key = FuncKey {
                name_strindex: name_idx,
            };
            let func_index = func_set.insert(func_key.clone());
            if func_index as usize >= functions.len() {
                functions.push(Function {
                    name_strindex: name_idx,
                    system_name_strindex: name_idx,
                    filename_strindex: 0,
                    start_line: 0,
                });
            }

            // Get or create location
            let loc_key = LocationKey {
                function_index: func_index,
                is_kernel,
            };
            let loc_index = loc_set.insert(loc_key.clone());
            if loc_index as usize >= locations.len() {
                let (attr_idx, mapping_idx) = if is_kernel {
                    (kernel_attr_idx, 0) // null mapping for kernel frames
                } else {
                    (native_attr_idx, user_mapping_index)
                };
                locations.push(Location {
                    mapping_index: mapping_idx,
                    address: synthetic_addr,
                    lines: vec![Line {
                        function_index: func_index,
                        line: 0,
                        column: 0,
                    }],
                    attribute_indices: vec![attr_idx],
                });
            }

            location_indices.push(loc_index);
        }

        // Get or create stack
        let stack_key = StackKey {
            location_indices: location_indices.clone(),
        };
        let stack_index = stack_set.insert(stack_key);
        if stack_index as usize >= stack_table.len() {
            stack_table.push(Stack { location_indices });
        }

        samples.push(Sample {
            stack_index,
            attribute_indices: vec![],
            link_index: 0,
            values: vec![count],
            timestamps_unix_nano: vec![],
        });
    }

    // Compute timing
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let start_nanos = if opts.duration_ms > 0 {
        now_nanos.saturating_sub(opts.duration_ms as u64 * 1_000_000)
    } else {
        now_nanos
    };

    let period_nanos = if opts.off_cpu {
        1
    } else if opts.frequency_hz > 0 {
        (1_000_000_000u64) / opts.frequency_hz
    } else {
        0
    };

    // Expand aggregated counts into individual timestamps.
    // devfiler (and the OTel eBPF profiler convention) determines sample count
    // from timestamps_unix_nano.len(), ignoring the `values` field for on-CPU.
    // We spread timestamps evenly across the profiling duration.
    let total_samples: u64 = samples.iter().map(|s| s.values[0].max(0) as u64).sum();
    let duration_nanos = opts.duration_ms as u64 * 1_000_000;

    for sample in &mut samples {
        let count = sample.values[0].max(1) as u64;
        let mut timestamps = Vec::with_capacity(count as usize);

        if total_samples > 0 && duration_nanos > 0 {
            // Spread this sample's timestamps proportionally across the duration.
            let step = duration_nanos / total_samples.max(1);
            // Use a deterministic offset based on stack_index to avoid all samples
            // having identical timestamps.
            let offset = (sample.stack_index as u64).wrapping_mul(7919) % step.max(1);
            for i in 0..count {
                timestamps.push(start_nanos + offset + i * step);
            }
        } else {
            // No duration info; use current time for all occurrences.
            for _ in 0..count {
                timestamps.push(now_nanos);
            }
        }

        sample.timestamps_unix_nano = timestamps;
        // Clear values for on-CPU (devfiler ignores them; count is from timestamps).
        // Keep values for off-CPU (duration per event).
        if !opts.off_cpu {
            sample.values.clear();
        }
    }

    // Build the Profile
    let profile = Profile {
        sample_type: Some(ValueType {
            type_strindex: sample_type_str,
            unit_strindex: sample_unit_str,
        }),
        samples,
        time_unix_nano: start_nanos,
        duration_nano: duration_nanos,
        period_type: Some(ValueType {
            type_strindex: period_type_str,
            unit_strindex: period_unit_str,
        }),
        period: period_nanos as i64,
        profile_id: generate_profile_id(),
        dropped_attributes_count: 0,
        original_payload_format: String::new(),
        original_payload: vec![],
        attribute_indices: vec![],
    };

    // Build resource attributes
    let service_name_key = strings.intern("service.name");
    // Intern the scope name/version for InstrumentationScope
    let scope_name = "profile-bee".to_string();
    let scope_version = env!("CARGO_PKG_VERSION").to_string();

    // Build the dictionary
    let dictionary = ProfilesDictionary {
        mapping_table: vec![
            Mapping::default(), // index 0 = null
            Mapping {
                // index 1 = user-space executable
                memory_start: 0,
                memory_limit: 0,
                file_offset: 0,
                filename_strindex: svc_filename_idx,
                attribute_indices: vec![build_id_attr_idx],
            },
        ],
        location_table: locations,
        function_table: functions,
        link_table: vec![proto::opentelemetry::proto::profiles::v1development::Link::default()], // index 0 = null
        string_table: strings.into_vec(),
        attribute_table: attr_table,
        stack_table,
    };

    // Build the envelope
    ExportProfilesServiceRequest {
        resource_profiles: vec![ResourceProfiles {
            resource: Some(Resource {
                attributes: vec![KeyValue {
                    key: "service.name".to_string(),
                    value: Some(AnyValue {
                        value: Some(
                            proto::opentelemetry::proto::common::v1::any_value::Value::StringValue(
                                opts.service_name.clone(),
                            ),
                        ),
                    }),
                    key_strindex: service_name_key,
                }],
                dropped_attributes_count: 0,
                entity_refs: vec![],
            }),
            scope_profiles: vec![ScopeProfiles {
                scope: Some(proto::opentelemetry::proto::common::v1::InstrumentationScope {
                    name: scope_name,
                    version: scope_version,
                    attributes: vec![],
                    dropped_attributes_count: 0,
                }),
                profiles: vec![profile],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
        dictionary: Some(dictionary),
    }
}

/// Generate a random 16-byte profile ID.
fn generate_profile_id() -> Vec<u8> {
    // Simple random ID using current time + a counter to avoid collisions.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut id = vec![0u8; 16];
    id[..8].copy_from_slice(&nanos.to_le_bytes()[..8]);
    // Mix in some entropy from the stack pointer address
    let stack_addr = &id as *const _ as u64;
    id[8..16].copy_from_slice(&stack_addr.to_le_bytes());
    id
}

/// FNV-1a hash producing a stable u64 from a byte slice.
/// Used to generate unique synthetic addresses per function name.
fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3); // FNV-1a prime
    }
    h
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn test_empty_input() {
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&[], &opts);

        let dict = req.dictionary.as_ref().unwrap();
        // String table slot 0 must be ""
        assert_eq!(dict.string_table[0], "");
        // All dictionary tables must have a null entry at index 0
        assert!(!dict.function_table.is_empty());
        assert!(!dict.location_table.is_empty());
        assert!(!dict.stack_table.is_empty());
        assert!(!dict.mapping_table.is_empty());
        assert!(!dict.link_table.is_empty());
        assert!(!dict.attribute_table.is_empty());

        // Profile should have no samples
        let profile = &req.resource_profiles[0].scope_profiles[0].profiles[0];
        assert!(profile.samples.is_empty());
    }

    #[test]
    fn test_single_stack() {
        let stacks = vec!["main;foo;bar 42".to_string()];
        let opts = OtlpOptions {
            service_name: "test-app".to_string(),
            ..Default::default()
        };
        let req = collapse_to_otlp_request(&stacks, &opts);

        let dict = req.dictionary.as_ref().unwrap();
        let profile = &req.resource_profiles[0].scope_profiles[0].profiles[0];

        // Should have one sample
        assert_eq!(profile.samples.len(), 1);
        // On-CPU: values are cleared; count is derived from timestamps
        assert!(profile.samples[0].values.is_empty());
        // 42 occurrences -> 42 timestamps
        assert_eq!(profile.samples[0].timestamps_unix_nano.len(), 42);

        // Stack should exist in the stack table
        let stack_idx = profile.samples[0].stack_index as usize;
        assert!(stack_idx > 0);
        let stack = &dict.stack_table[stack_idx];

        // Stack should have 3 locations (leaf first: bar, foo, main)
        assert_eq!(stack.location_indices.len(), 3);

        // Verify leaf is "bar"
        let leaf_loc_idx = stack.location_indices[0] as usize;
        let leaf_loc = &dict.location_table[leaf_loc_idx];
        let leaf_func_idx = leaf_loc.lines[0].function_index as usize;
        let leaf_func = &dict.function_table[leaf_func_idx];
        assert_eq!(
            dict.string_table[leaf_func.name_strindex as usize],
            "bar"
        );

        // Verify root is "main"
        let root_loc_idx = stack.location_indices[2] as usize;
        let root_loc = &dict.location_table[root_loc_idx];
        let root_func_idx = root_loc.lines[0].function_index as usize;
        let root_func = &dict.function_table[root_func_idx];
        assert_eq!(
            dict.string_table[root_func.name_strindex as usize],
            "main"
        );

        // Verify sample type
        let st = profile.sample_type.as_ref().unwrap();
        assert_eq!(dict.string_table[st.type_strindex as usize], "samples");
        assert_eq!(dict.string_table[st.unit_strindex as usize], "count");

        // Resource should have service.name
        let resource = req.resource_profiles[0].resource.as_ref().unwrap();
        assert!(resource.attributes.iter().any(|kv| kv.key == "service.name"));
    }

    #[test]
    fn test_shared_frames_deduped() {
        let stacks = vec![
            "main;foo;bar 10".to_string(),
            "main;foo;baz 20".to_string(),
            "main;qux 5".to_string(),
        ];
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&stacks, &opts);

        let dict = req.dictionary.as_ref().unwrap();
        let profile = &req.resource_profiles[0].scope_profiles[0].profiles[0];

        assert_eq!(profile.samples.len(), 3);

        // Functions: null + main, foo, bar, baz, qux = 6
        assert_eq!(dict.function_table.len(), 6);
        // Locations: null + 5 unique = 6 (all native, no kernel overlap)
        assert_eq!(dict.location_table.len(), 6);
    }

    #[test]
    fn test_kernel_frames() {
        let stacks = vec!["myapp;do_syscall_k;vfs_read_k;userland_fn 100".to_string()];
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&stacks, &opts);

        let dict = req.dictionary.as_ref().unwrap();

        // Verify kernel frames have _k stripped from the function name
        let kernel_names: Vec<&str> = dict
            .function_table
            .iter()
            .skip(1) // skip null
            .filter_map(|f| {
                let name = &dict.string_table[f.name_strindex as usize];
                if name == "do_syscall" || name == "vfs_read" {
                    Some(name.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(kernel_names.len(), 2);

        // Verify kernel locations have the kernel attribute
        let frame_type_key_str = "profile.frame.type";
        let frame_type_key_idx = dict
            .string_table
            .iter()
            .position(|s| s == frame_type_key_str)
            .unwrap() as i32;

        for loc in &dict.location_table[1..] {
            if !loc.attribute_indices.is_empty() {
                let attr_idx = loc.attribute_indices[0] as usize;
                let attr = &dict.attribute_table[attr_idx];
                assert_eq!(attr.key_strindex, frame_type_key_idx);
            }
        }
    }

    #[test]
    fn test_off_cpu_mode() {
        let stacks = vec!["main;sleep 1000".to_string()];
        let opts = OtlpOptions {
            off_cpu: true,
            ..Default::default()
        };
        let req = collapse_to_otlp_request(&stacks, &opts);

        let dict = req.dictionary.as_ref().unwrap();
        let profile = &req.resource_profiles[0].scope_profiles[0].profiles[0];

        let st = profile.sample_type.as_ref().unwrap();
        assert_eq!(dict.string_table[st.type_strindex as usize], "off_cpu");
        assert_eq!(
            dict.string_table[st.unit_strindex as usize],
            "nanoseconds"
        );
    }

    #[test]
    fn test_malformed_lines_skipped() {
        let stacks = vec![
            "main;foo 10".to_string(),
            "malformed_no_space".to_string(),
            "".to_string(),
            "main;bar abc".to_string(),
            "main;baz 5".to_string(),
        ];
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&stacks, &opts);

        let profile = &req.resource_profiles[0].scope_profiles[0].profiles[0];
        // Only 2 valid lines should produce samples
        assert_eq!(profile.samples.len(), 2);
    }

    #[test]
    fn test_dictionary_zero_entries() {
        let stacks = vec!["a;b 1".to_string()];
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&stacks, &opts);

        let dict = req.dictionary.as_ref().unwrap();

        // All dictionary tables must have index 0 as zero/null value
        assert_eq!(dict.string_table[0], "");
        assert_eq!(dict.function_table[0], Function::default());
        assert_eq!(dict.location_table[0], Location::default());
        assert_eq!(dict.stack_table[0], Stack::default());
        assert_eq!(dict.mapping_table[0], Mapping::default());
    }

    #[test]
    fn test_request_serializable() {
        let stacks = vec!["main;foo;bar 42".to_string()];
        let opts = OtlpOptions::default();
        let req = collapse_to_otlp_request(&stacks, &opts);

        // Verify the request can be serialized to protobuf bytes
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        assert!(!buf.is_empty());

        // Verify it can be deserialized back
        let decoded = ExportProfilesServiceRequest::decode(buf.as_slice()).unwrap();
        assert_eq!(decoded.resource_profiles.len(), 1);
    }
}
