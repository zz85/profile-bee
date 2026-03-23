//! Pprof protobuf format support.
//!
//! Converts profile-bee's collapse-format stack traces into Google's pprof
//! protobuf format (gzip-compressed). The output is compatible with:
//! - `go tool pprof`
//! - Grafana / Pyroscope
//! - Speedscope
//! - Datadog Continuous Profiler
//! - Polar Signals / Parca
//!
//! Reference: <https://github.com/google/pprof/blob/main/proto/profile.proto>

use std::collections::HashMap;
use std::io::Write;

use flate2::write::GzEncoder;
use flate2::Compression;
use prost::Message;

// ---------------------------------------------------------------------------
// Pprof protobuf message types (vendored from profile.proto)
// ---------------------------------------------------------------------------
// These types are derived from Google's pprof proto schema.
// Vendored to avoid a build-time prost-build / protoc dependency.

/// Top-level profile message.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Profile {
    #[prost(message, repeated, tag = "1")]
    pub sample_type: Vec<ValueType>,
    #[prost(message, repeated, tag = "2")]
    pub sample: Vec<Sample>,
    #[prost(message, repeated, tag = "3")]
    pub mapping: Vec<Mapping>,
    #[prost(message, repeated, tag = "4")]
    pub location: Vec<Location>,
    #[prost(message, repeated, tag = "5")]
    pub function: Vec<Function>,
    #[prost(string, repeated, tag = "6")]
    pub string_table: Vec<String>,
    #[prost(int64, tag = "7")]
    pub drop_frames: i64,
    #[prost(int64, tag = "8")]
    pub keep_frames: i64,
    #[prost(int64, tag = "9")]
    pub time_nanos: i64,
    #[prost(int64, tag = "10")]
    pub duration_nanos: i64,
    #[prost(message, optional, tag = "11")]
    pub period_type: Option<ValueType>,
    #[prost(int64, tag = "12")]
    pub period: i64,
    #[prost(int64, repeated, tag = "13")]
    pub comment: Vec<i64>,
    #[prost(int64, tag = "14")]
    pub default_sample_type: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ValueType {
    /// Index into string table. Named `ty` because `type` is a Rust keyword.
    #[prost(int64, tag = "1")]
    pub r#type: i64,
    #[prost(int64, tag = "2")]
    pub unit: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Sample {
    #[prost(uint64, repeated, tag = "1")]
    pub location_id: Vec<u64>,
    #[prost(int64, repeated, tag = "2")]
    pub value: Vec<i64>,
    #[prost(message, repeated, tag = "3")]
    pub label: Vec<Label>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Label {
    #[prost(int64, tag = "1")]
    pub key: i64,
    #[prost(int64, tag = "2")]
    pub str: i64,
    #[prost(int64, tag = "3")]
    pub num: i64,
    #[prost(int64, tag = "4")]
    pub num_unit: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Mapping {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub memory_start: u64,
    #[prost(uint64, tag = "3")]
    pub memory_limit: u64,
    #[prost(uint64, tag = "4")]
    pub file_offset: u64,
    #[prost(int64, tag = "5")]
    pub filename: i64,
    #[prost(int64, tag = "6")]
    pub build_id: i64,
    #[prost(bool, tag = "7")]
    pub has_functions: bool,
    #[prost(bool, tag = "8")]
    pub has_filenames: bool,
    #[prost(bool, tag = "9")]
    pub has_line_numbers: bool,
    #[prost(bool, tag = "10")]
    pub has_inline_frames: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Location {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(uint64, tag = "2")]
    pub mapping_id: u64,
    #[prost(uint64, tag = "3")]
    pub address: u64,
    #[prost(message, repeated, tag = "4")]
    pub line: Vec<Line>,
    #[prost(bool, tag = "5")]
    pub is_folded: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Line {
    #[prost(uint64, tag = "1")]
    pub function_id: u64,
    #[prost(int64, tag = "2")]
    pub line: i64,
    #[prost(int64, tag = "3")]
    pub column: i64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Function {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(int64, tag = "2")]
    pub name: i64,
    #[prost(int64, tag = "3")]
    pub system_name: i64,
    #[prost(int64, tag = "4")]
    pub filename: i64,
    #[prost(int64, tag = "5")]
    pub start_line: i64,
}

// ---------------------------------------------------------------------------
// String interning helper
// ---------------------------------------------------------------------------

/// Intern strings into a dedup'd table. `string_table[0]` is always "".
struct StringTable {
    table: Vec<String>,
    index: HashMap<String, i64>,
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

    fn intern(&mut self, s: &str) -> i64 {
        if let Some(&idx) = self.index.get(s) {
            return idx;
        }
        let idx = self.table.len() as i64;
        self.table.push(s.to_owned());
        self.index.insert(s.to_owned(), idx);
        idx
    }

    fn into_vec(self) -> Vec<String> {
        self.table
    }
}

// ---------------------------------------------------------------------------
// Conversion: collapse format → pprof
// ---------------------------------------------------------------------------

/// Options for pprof generation.
pub struct PprofOptions {
    /// Sampling frequency in Hz (default 99).
    pub frequency_hz: u64,
    /// Profiling duration in milliseconds (0 if unknown).
    pub duration_ms: u64,
    /// Whether this is off-CPU profiling (changes units to microseconds).
    pub off_cpu: bool,
}

impl Default for PprofOptions {
    fn default() -> Self {
        Self {
            frequency_hz: 99,
            duration_ms: 0,
            off_cpu: false,
        }
    }
}

/// Convert collapse-format stack strings to gzip-compressed pprof protobuf.
///
/// Input format: `"frame1;frame2;frame3 count"` (root to leaf, left to right).
/// Output: gzip-compressed protobuf bytes suitable for writing to `.pb.gz`.
///
/// Pprof convention: `Sample.location_id[0]` is the **leaf** (innermost frame),
/// so the frame order is reversed during conversion.
pub fn collapse_to_pprof(stacks: &[String], opts: &PprofOptions) -> anyhow::Result<Vec<u8>> {
    let mut strings = StringTable::new();

    // Pre-intern well-known strings
    let (sample_type_str, sample_unit_str, period_type_str, period_unit_str) = if opts.off_cpu {
        (
            strings.intern("off-cpu-time"),
            strings.intern("microseconds"),
            strings.intern("off-cpu"),
            strings.intern("microseconds"),
        )
    } else {
        (
            strings.intern("samples"),
            strings.intern("count"),
            strings.intern("cpu"),
            strings.intern("nanoseconds"),
        )
    };

    // Dedup tables: name -> id (1-based)
    let mut func_map: HashMap<String, u64> = HashMap::new();
    let mut func_list: Vec<Function> = Vec::new();
    // For collapse format (no addresses), location = function 1:1
    let mut loc_map: HashMap<String, u64> = HashMap::new();
    let mut loc_list: Vec<Location> = Vec::new();

    let mut samples: Vec<Sample> = Vec::new();

    for line in stacks {
        if line.is_empty() {
            continue;
        }

        // Parse "frame1;frame2;...;frameN count"
        let (stack_part, count_str) = match line.rsplit_once(' ') {
            Some(parts) => parts,
            None => {
                tracing::warn!("Skipping malformed collapse line: {}", line);
                continue;
            }
        };
        let count: i64 = match count_str.parse() {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("Skipping line with non-numeric count: {}", line);
                continue;
            }
        };

        let frames: Vec<&str> = stack_part.split(';').collect();

        // Build location_id chain (leaf first = reversed)
        let mut location_ids: Vec<u64> = Vec::with_capacity(frames.len());
        for &frame in frames.iter().rev() {
            let loc_id = *loc_map.entry(frame.to_owned()).or_insert_with(|| {
                // Create function
                let func_id = *func_map.entry(frame.to_owned()).or_insert_with(|| {
                    let id = func_list.len() as u64 + 1;
                    let name_idx = strings.intern(frame);
                    func_list.push(Function {
                        id,
                        name: name_idx,
                        system_name: name_idx,
                        filename: 0,
                        start_line: 0,
                    });
                    id
                });

                // Create location (1:1 with function for symbol-only profiles)
                let id = loc_list.len() as u64 + 1;
                loc_list.push(Location {
                    id,
                    mapping_id: 0,
                    address: 0,
                    line: vec![Line {
                        function_id: func_id,
                        line: 0,
                        column: 0,
                    }],
                    is_folded: false,
                });
                id
            });
            location_ids.push(loc_id);
        }

        samples.push(Sample {
            location_id: location_ids,
            value: vec![count],
            label: vec![],
        });
    }

    // Compute timing
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64;

    let period = if opts.off_cpu {
        1 // off-cpu values are already in microseconds
    } else if opts.frequency_hz > 0 {
        (1_000_000_000i64) / (opts.frequency_hz as i64) // nanoseconds per sample
    } else {
        0
    };

    let profile = Profile {
        sample_type: vec![ValueType {
            r#type: sample_type_str,
            unit: sample_unit_str,
        }],
        sample: samples,
        mapping: vec![],
        location: loc_list,
        function: func_list,
        string_table: strings.into_vec(),
        drop_frames: 0,
        keep_frames: 0,
        time_nanos: now_nanos,
        duration_nanos: (opts.duration_ms as i64) * 1_000_000,
        period_type: Some(ValueType {
            r#type: period_type_str,
            unit: period_unit_str,
        }),
        period,
        comment: vec![],
        default_sample_type: 0,
    };

    // Serialize protobuf
    let mut proto_buf = Vec::new();
    profile.encode(&mut proto_buf)?;

    // Gzip compress (required by pprof spec)
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&proto_buf)?;
    let compressed = encoder.finish()?;

    Ok(compressed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let opts = PprofOptions::default();
        let result = collapse_to_pprof(&[], &opts).unwrap();
        assert!(!result.is_empty()); // gzip header at minimum

        // Decompress and verify it's valid protobuf
        let profile = decompress_and_decode(&result);
        assert!(profile.sample.is_empty());
        assert_eq!(profile.string_table[0], "");
    }

    #[test]
    fn test_single_stack() {
        let stacks = vec!["main;foo;bar 42".to_string()];
        let opts = PprofOptions {
            frequency_hz: 99,
            ..Default::default()
        };
        let result = collapse_to_pprof(&stacks, &opts).unwrap();
        let profile = decompress_and_decode(&result);

        // Verify structure
        assert_eq!(profile.sample.len(), 1);
        assert_eq!(profile.sample[0].value, vec![42]);

        // Verify leaf-first ordering: bar is the leaf, should be location_id[0]
        let sample = &profile.sample[0];
        assert_eq!(sample.location_id.len(), 3);

        // Resolve function names
        let leaf_loc = profile
            .location
            .iter()
            .find(|l| l.id == sample.location_id[0])
            .unwrap();
        let leaf_func = profile
            .function
            .iter()
            .find(|f| f.id == leaf_loc.line[0].function_id)
            .unwrap();
        assert_eq!(profile.string_table[leaf_func.name as usize], "bar");

        let root_loc = profile
            .location
            .iter()
            .find(|l| l.id == sample.location_id[2])
            .unwrap();
        let root_func = profile
            .function
            .iter()
            .find(|f| f.id == root_loc.line[0].function_id)
            .unwrap();
        assert_eq!(profile.string_table[root_func.name as usize], "main");

        // Verify metadata
        assert_eq!(profile.sample_type.len(), 1);
        assert_eq!(
            profile.string_table[profile.sample_type[0].r#type as usize],
            "samples"
        );
        assert_eq!(
            profile.string_table[profile.sample_type[0].unit as usize],
            "count"
        );
        assert!(profile.period > 0);
        assert!(profile.time_nanos > 0);
    }

    #[test]
    fn test_multiple_stacks_with_shared_frames() {
        let stacks = vec![
            "main;foo;bar 10".to_string(),
            "main;foo;baz 20".to_string(),
            "main;qux 5".to_string(),
        ];
        let opts = PprofOptions::default();
        let result = collapse_to_pprof(&stacks, &opts).unwrap();
        let profile = decompress_and_decode(&result);

        assert_eq!(profile.sample.len(), 3);

        // Functions should be deduped: main, foo, bar, baz, qux = 5
        assert_eq!(profile.function.len(), 5);

        // Locations should also be deduped (1:1 with functions)
        assert_eq!(profile.location.len(), 5);

        // String table should have: "", "samples", "count", "cpu", "nanoseconds",
        // "main", "foo", "bar", "baz", "qux"
        assert!(profile.string_table.len() >= 10);
    }

    #[test]
    fn test_off_cpu_mode() {
        let stacks = vec!["main;sleep 1000".to_string()];
        let opts = PprofOptions {
            off_cpu: true,
            ..Default::default()
        };
        let result = collapse_to_pprof(&stacks, &opts).unwrap();
        let profile = decompress_and_decode(&result);

        assert_eq!(
            profile.string_table[profile.sample_type[0].r#type as usize],
            "off-cpu-time"
        );
        assert_eq!(
            profile.string_table[profile.sample_type[0].unit as usize],
            "microseconds"
        );
    }

    #[test]
    fn test_malformed_lines_skipped() {
        let stacks = vec![
            "main;foo 10".to_string(),
            "malformed_no_space".to_string(),
            "".to_string(),
            "main;bar abc".to_string(), // non-numeric count
            "main;baz 5".to_string(),
        ];
        let opts = PprofOptions::default();
        let result = collapse_to_pprof(&stacks, &opts).unwrap();
        let profile = decompress_and_decode(&result);

        // Only valid lines should produce samples
        assert_eq!(profile.sample.len(), 2);
    }

    #[test]
    fn test_string_table_slot_zero_is_empty() {
        let stacks = vec!["a;b 1".to_string()];
        let opts = PprofOptions::default();
        let result = collapse_to_pprof(&stacks, &opts).unwrap();
        let profile = decompress_and_decode(&result);

        assert_eq!(profile.string_table[0], "");
    }

    /// Helper: decompress gzip and decode pprof protobuf.
    fn decompress_and_decode(data: &[u8]) -> Profile {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf).unwrap();
        Profile::decode(buf.as_slice()).unwrap()
    }
}
