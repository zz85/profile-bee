//! AWS CodeGuru Profiler JSON format support.
//!
//! Converts profile-bee's collapse-format stack traces into the JSON call-tree
//! format accepted by CodeGuru's `PostAgentProfile` API.
//!
//! Schema referenced from:
//! - Open-source [Python agent](https://github.com/aws/amazon-codeguru-profiler-python-agent)
//!   (`profile_encoder.py`, `agent_metadata.py`, `call_graph_node.py`)
//! - AWS docs on [thread state visualizations](https://docs.aws.amazon.com/codeguru/latest/profiler-ug/working-with-visualizations-thread-states.html)
//!
//! See `docs/codeguru_format.md` for full schema documentation.
//!
//! # Counter Types
//!
//! CodeGuru supports multiple counter types in the `counts` object:
//!
//! | Key | Meaning | CPU view | Latency view |
//! |-----|---------|----------|--------------|
//! | `RUNNABLE` | Thread actively on CPU | Yes | Yes |
//! | `BLOCKED` | Blocked on monitor lock | Yes | Yes |
//! | `NATIVE` | Running native/FFI code | Yes | Yes |
//! | `WAITING` | In wait/join/sleep | No | Yes |
//! | `TIMED_WAITING` | In timed wait | No | Yes |
//! | `IDLE` | Parked/idle thread | No | No |
//! | `WALL_TIME` | Generic wall-clock (Python agent default) | Yes | Yes |
//!
//! For eBPF CPU profiling, profile-bee uses:
//! - `RUNNABLE` for on-CPU samples (default mode)
//! - `WAITING` for off-CPU samples (`--off-cpu` mode)
//! - `IDLE` for idle/swapper stacks (pid == 0)
//!
//! # Usage
//!
//! ```rust,no_run
//! use profile_bee::codeguru::{collapse_to_codeguru, CodeGuruOptions, CounterType};
//!
//! let stacks = vec!["main;foo;bar 10".to_string(), "main;foo;baz 5".to_string()];
//! let opts = CodeGuruOptions {
//!     duration_ms: 10000,
//!     frequency_hz: 99,
//!     counter_type: CounterType::Runnable,
//!     ..Default::default()
//! };
//! let json = collapse_to_codeguru(&stacks, &opts);
//! println!("{}", json);
//! ```

use std::collections::BTreeMap;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Counter types
// ---------------------------------------------------------------------------

/// CodeGuru thread-state counter types.
///
/// These correspond to the keys used in the `counts` object on call graph
/// leaf nodes and in `sampleWeights` metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterType {
    /// Thread actively executing on CPU. Shown in CPU and Latency views.
    Runnable,
    /// Thread blocked on a monitor/lock. Shown in CPU and Latency views.
    Blocked,
    /// Thread running native (JNI/FFI) code. Shown in CPU and Latency views.
    Native,
    /// Thread waiting (Object.wait, Thread.join). Shown in Latency view only.
    Waiting,
    /// Thread in timed wait (Thread.sleep, timed wait). Shown in Latency view only.
    TimedWaiting,
    /// Thread idle/parked (daemon threads, pool waiters). Not shown in either view.
    Idle,
    /// Generic wall-clock time. Used by the Python agent as a catch-all.
    WallTime,
}

impl CounterType {
    /// Returns the JSON key string used in `counts` and `sampleWeights`.
    pub fn as_str(&self) -> &'static str {
        match self {
            CounterType::Runnable => "RUNNABLE",
            CounterType::Blocked => "BLOCKED",
            CounterType::Native => "NATIVE",
            CounterType::Waiting => "WAITING",
            CounterType::TimedWaiting => "TIMED_WAITING",
            CounterType::Idle => "IDLE",
            CounterType::WallTime => "WALL_TIME",
        }
    }
}

// ---------------------------------------------------------------------------
// CodeGuru profile JSON types
// ---------------------------------------------------------------------------

/// Top-level profile structure for CodeGuru `PostAgentProfile` API.
#[derive(Serialize)]
pub struct CodeGuruProfile {
    /// Start time in milliseconds since epoch.
    pub start: i64,
    /// End time in milliseconds since epoch.
    pub end: i64,
    /// Agent and environment metadata.
    #[serde(rename = "agentMetadata")]
    pub agent_metadata: AgentMetadata,
    /// The call tree root.
    pub callgraph: CallGraphNode,
}

/// Agent metadata included with each profile upload.
#[derive(Serialize)]
pub struct AgentMetadata {
    /// Sample weights per counter type (samples-per-second scaling factor).
    #[serde(rename = "sampleWeights")]
    pub sample_weights: BTreeMap<String, f64>,
    /// Duration of the profiling window in milliseconds.
    #[serde(rename = "durationInMs")]
    pub duration_in_ms: i64,
    /// Fleet/host identification.
    #[serde(rename = "fleetInfo")]
    pub fleet_info: FleetInfo,
    /// Agent identification.
    #[serde(rename = "agentInfo")]
    pub agent_info: AgentInfo,
    /// Total number of samples collected.
    #[serde(rename = "numTimesSampled")]
    pub num_times_sampled: u64,
}

/// Fleet/host identification.
///
/// Field names match the Python agent's `agent_metadata.py` serialization:
/// `fleetInstanceId` and `hostType`.
#[derive(Serialize)]
pub struct FleetInfo {
    /// Instance/task/host identifier (e.g., EC2 instance ID, hostname).
    #[serde(rename = "fleetInstanceId")]
    pub fleet_instance_id: String,
    /// Host type (e.g., "c5.xlarge", "unknown").
    #[serde(rename = "hostType")]
    pub host_type: String,
}

/// Agent identification.
#[derive(Serialize)]
pub struct AgentInfo {
    /// Agent name.
    #[serde(rename = "type")]
    pub agent_type: String,
    /// Agent version.
    pub version: String,
}

/// A node in the call tree.
///
/// `children` is a `BTreeMap` (JSON object) keyed by frame name.
/// `counts` is only present on leaf nodes where samples were recorded.
/// Multiple counter types can coexist in the same `counts` map.
#[derive(Serialize, Default)]
pub struct CallGraphNode {
    /// Self-time sample counts by counter type. Only present at leaf nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<BTreeMap<String, u64>>,
    /// Child frames. Keys are frame name strings.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub children: BTreeMap<String, CallGraphNode>,
}

impl CallGraphNode {
    fn new() -> Self {
        Self::default()
    }

    /// Insert a stack trace into the tree with the given counter type.
    /// Only the leaf node gets a count.
    fn insert(&mut self, frames: &[&str], count: u64, counter_type: &str) {
        if frames.is_empty() {
            return;
        }

        let child = self.children.entry(frames[0].to_owned()).or_default();

        if frames.len() == 1 {
            // Leaf node — add self-time count
            let counts = child.counts.get_or_insert_with(BTreeMap::new);
            *counts.entry(counter_type.to_owned()).or_insert(0) += count;
        } else {
            child.insert(&frames[1..], count, counter_type);
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion options
// ---------------------------------------------------------------------------

/// Options for CodeGuru profile generation.
pub struct CodeGuruOptions {
    /// Sampling frequency in Hz (default 99).
    pub frequency_hz: u64,
    /// Profiling duration in milliseconds.
    pub duration_ms: u64,
    /// Fleet instance ID (e.g., EC2 instance ID, hostname).
    /// Defaults to hostname if empty.
    pub fleet_id: String,
    /// Host type (e.g., "c5.xlarge"). Defaults to "unknown".
    pub host_type: String,
    /// Counter type for samples. Determines which CodeGuru visualization
    /// views display the data.
    pub counter_type: CounterType,
}

impl Default for CodeGuruOptions {
    fn default() -> Self {
        let hostname = hostname_or_unknown();
        Self {
            frequency_hz: 99,
            duration_ms: 0,
            fleet_id: hostname,
            host_type: "unknown".to_owned(),
            counter_type: CounterType::Runnable,
        }
    }
}

/// Best-effort hostname retrieval.
fn hostname_or_unknown() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

// ---------------------------------------------------------------------------
// Conversion: collapse format → CodeGuru JSON
// ---------------------------------------------------------------------------

/// Convert collapse-format stack strings to CodeGuru JSON profile string.
///
/// Input format: `"frame1;frame2;frame3 count"` (root to leaf, left to right).
/// Output: JSON string suitable for `PostAgentProfile` with `Content-Type: application/json`.
///
/// The counter type is determined by `opts.counter_type`:
/// - `CounterType::Runnable` for on-CPU profiling (default)
/// - `CounterType::Waiting` for off-CPU profiling
/// - `CounterType::WallTime` for generic/mixed profiling
pub fn collapse_to_codeguru(stacks: &[String], opts: &CodeGuruOptions) -> String {
    let mut root = CallGraphNode::new();
    let mut total_samples: u64 = 0;
    let mut counter_samples: BTreeMap<String, u64> = BTreeMap::new();
    let counter_key = opts.counter_type.as_str();

    for line in stacks {
        if line.is_empty() {
            continue;
        }

        let (stack_part, count_str) = match line.rsplit_once(' ') {
            Some(parts) => parts,
            None => {
                tracing::warn!("Skipping malformed collapse line: {}", line);
                continue;
            }
        };
        let count: u64 = match count_str.parse() {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("Skipping line with non-numeric count: {}", line);
                continue;
            }
        };

        let frames: Vec<&str> = stack_part.split(';').collect();

        // Detect idle/swapper stacks (tgid == 0 produces "cpu_NN;idle" frames)
        // and classify them as IDLE so CodeGuru excludes them from CPU/Latency views.
        let effective_counter = if frames.last() == Some(&"idle") {
            CounterType::Idle.as_str()
        } else {
            counter_key
        };

        root.insert(&frames, count, effective_counter);
        *counter_samples
            .entry(effective_counter.to_owned())
            .or_insert(0u64) += count;
        total_samples += count;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let duration_ms = opts.duration_ms as i64;
    let start_ms = now_ms - duration_ms;

    // sample_weight = samples_for_counter / duration_seconds
    let duration_secs = (duration_ms as f64) / 1000.0;
    let mut sample_weights = BTreeMap::new();
    for (counter, count) in &counter_samples {
        let weight = if duration_secs > 0.0 {
            *count as f64 / duration_secs
        } else {
            *count as f64
        };
        sample_weights.insert(counter.clone(), weight);
    }
    // Ensure the primary counter always has an entry even if zero
    sample_weights.entry(counter_key.to_owned()).or_insert(0.0);

    let profile = CodeGuruProfile {
        start: start_ms,
        end: now_ms,
        agent_metadata: AgentMetadata {
            sample_weights,
            duration_in_ms: duration_ms,
            fleet_info: FleetInfo {
                fleet_instance_id: opts.fleet_id.clone(),
                host_type: opts.host_type.clone(),
            },
            agent_info: AgentInfo {
                agent_type: "profile-bee".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
            num_times_sampled: total_samples,
        },
        callgraph: root,
    };

    serde_json::to_string(&profile).expect("CodeGuru profile serialization should not fail")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&[], &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(
            parsed["callgraph"]["children"].is_null()
                || parsed["callgraph"]["children"]
                    .as_object()
                    .unwrap()
                    .is_empty()
        );
        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 0);
    }

    #[test]
    fn test_single_stack_runnable() {
        let stacks = vec!["main;foo;bar 42".to_string()];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            counter_type: CounterType::Runnable,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let bar = &parsed["callgraph"]["children"]["main"]["children"]["foo"]["children"]["bar"];
        assert_eq!(bar["counts"]["RUNNABLE"], 42);
        // Should NOT have WALL_TIME
        assert!(bar["counts"]["WALL_TIME"].is_null());

        // Intermediate nodes should NOT have counts
        assert!(parsed["callgraph"]["children"]["main"]["counts"].is_null());

        // sampleWeights should use RUNNABLE
        assert!(
            parsed["agentMetadata"]["sampleWeights"]["RUNNABLE"]
                .as_f64()
                .unwrap()
                > 0.0
        );
    }

    #[test]
    fn test_off_cpu_uses_waiting() {
        let stacks = vec!["main;sleep 100".to_string()];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            counter_type: CounterType::Waiting,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let sleep = &parsed["callgraph"]["children"]["main"]["children"]["sleep"];
        assert_eq!(sleep["counts"]["WAITING"], 100);
        assert!(sleep["counts"]["RUNNABLE"].is_null());

        assert!(
            parsed["agentMetadata"]["sampleWeights"]["WAITING"]
                .as_f64()
                .unwrap()
                > 0.0
        );
    }

    #[test]
    fn test_wall_time_counter() {
        let stacks = vec!["main;work 50".to_string()];
        let opts = CodeGuruOptions {
            counter_type: CounterType::WallTime,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let work = &parsed["callgraph"]["children"]["main"]["children"]["work"];
        assert_eq!(work["counts"]["WALL_TIME"], 50);
    }

    #[test]
    fn test_multiple_stacks_shared_prefix() {
        let stacks = vec![
            "main;process;compute 10".to_string(),
            "main;process;io_wait 5".to_string(),
            "main;cleanup 3".to_string(),
        ];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let main_children = parsed["callgraph"]["children"]["main"]["children"]
            .as_object()
            .unwrap();
        assert_eq!(main_children.len(), 2);

        let process_children = main_children["process"]["children"].as_object().unwrap();
        assert_eq!(process_children["compute"]["counts"]["RUNNABLE"], 10);
        assert_eq!(process_children["io_wait"]["counts"]["RUNNABLE"], 5);
        assert_eq!(main_children["cleanup"]["counts"]["RUNNABLE"], 3);

        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 18);
    }

    #[test]
    fn test_leaf_count_accumulation() {
        let stacks = vec!["main;foo 10".to_string(), "main;foo 5".to_string()];
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["callgraph"]["children"]["main"]["children"]["foo"]["counts"]["RUNNABLE"],
            15
        );
    }

    #[test]
    fn test_fleet_info_field_names() {
        let stacks = vec!["a;b 1".to_string()];
        let opts = CodeGuruOptions {
            frequency_hz: 99,
            duration_ms: 5000,
            fleet_id: "i-0abc123".to_owned(),
            host_type: "c5.xlarge".to_owned(),
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let meta = &parsed["agentMetadata"];
        assert_eq!(meta["durationInMs"], 5000);
        // Field names match Python agent: fleetInstanceId, hostType
        assert_eq!(meta["fleetInfo"]["fleetInstanceId"], "i-0abc123");
        assert_eq!(meta["fleetInfo"]["hostType"], "c5.xlarge");
        assert_eq!(meta["agentInfo"]["type"], "profile-bee");
        assert!(!meta["agentInfo"]["version"].as_str().unwrap().is_empty());
        assert_eq!(meta["numTimesSampled"], 1);

        let weight = meta["sampleWeights"]["RUNNABLE"].as_f64().unwrap();
        assert!((weight - 0.2).abs() < 0.001);

        assert!(parsed["start"].as_i64().unwrap() > 0);
        assert!(parsed["end"].as_i64().unwrap() > parsed["start"].as_i64().unwrap());
    }

    #[test]
    fn test_malformed_lines_skipped() {
        let stacks = vec![
            "good;stack 10".to_string(),
            "no_space_here".to_string(),
            "".to_string(),
            "bad;count abc".to_string(),
            "another;good 5".to_string(),
        ];
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 15);
        let children = parsed["callgraph"]["children"].as_object().unwrap();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_children_is_object_not_array() {
        let stacks = vec!["a;b 1".to_string(), "a;c 2".to_string()];
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed["callgraph"]["children"]["a"]["children"].is_object());
    }

    #[test]
    fn test_valid_json_structure() {
        let stacks = vec![
            "main;foo;bar 10".to_string(),
            "main;foo;baz 20".to_string(),
            "main;qux 5".to_string(),
        ];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "output must be valid JSON");

        let value = parsed.unwrap();
        assert!(value["start"].is_number());
        assert!(value["end"].is_number());
        assert!(value["agentMetadata"].is_object());
        assert!(value["callgraph"].is_object());
    }

    #[test]
    fn test_idle_stacks_use_idle_counter() {
        let stacks = vec![
            "main;compute 50".to_string(),
            "cpu_00;idle 200".to_string(),
            "cpu_01;idle 150".to_string(),
        ];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            counter_type: CounterType::Runnable,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Active stack should use RUNNABLE
        let compute = &parsed["callgraph"]["children"]["main"]["children"]["compute"];
        assert_eq!(compute["counts"]["RUNNABLE"], 50);
        assert!(compute["counts"]["IDLE"].is_null());

        // Idle stacks should use IDLE, not RUNNABLE
        let idle_00 = &parsed["callgraph"]["children"]["cpu_00"]["children"]["idle"];
        assert_eq!(idle_00["counts"]["IDLE"], 200);
        assert!(idle_00["counts"]["RUNNABLE"].is_null());

        let idle_01 = &parsed["callgraph"]["children"]["cpu_01"]["children"]["idle"];
        assert_eq!(idle_01["counts"]["IDLE"], 150);

        // Total samples includes both active and idle
        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 400);

        // sampleWeights should have per-counter entries
        let weights = &parsed["agentMetadata"]["sampleWeights"];
        // 50 samples / 10s = 5.0
        assert_eq!(weights["RUNNABLE"], 5.0);
        // 350 samples / 10s = 35.0
        assert_eq!(weights["IDLE"], 35.0);
    }
}
