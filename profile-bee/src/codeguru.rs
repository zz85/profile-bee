//! AWS CodeGuru Profiler JSON format support.
//!
//! Converts profile-bee's collapse-format stack traces into the JSON call-tree
//! format accepted by CodeGuru's `PostAgentProfile` API. Schema derived from
//! the open-source [Python agent](https://github.com/aws/amazon-codeguru-profiler-python-agent).
//!
//! The format is a recursive call tree where:
//! - `children` is a JSON **object** (map), not an array
//! - Only **leaf nodes** carry `counts` (self-time, not cumulative)
//! - The root node has no name; its children are the top-level frames
//!
//! # Usage
//!
//! ```rust,no_run
//! use profile_bee::codeguru::{collapse_to_codeguru, CodeGuruOptions};
//!
//! let stacks = vec!["main;foo;bar 10".to_string(), "main;foo;baz 5".to_string()];
//! let opts = CodeGuruOptions { duration_ms: 10000, frequency_hz: 99, ..Default::default() };
//! let json = collapse_to_codeguru(&stacks, &opts);
//! println!("{}", json);
//! ```

use std::collections::BTreeMap;

use serde::Serialize;

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
    /// Sample weights per profiling type.
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
#[derive(Serialize)]
pub struct FleetInfo {
    /// Instance/task/host identifier.
    pub id: String,
    /// Fleet type: "UNKNOWN", "AWS_EC2_INSTANCE", "AWS_ECS_FARGATE".
    #[serde(rename = "type")]
    pub fleet_type: String,
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
#[derive(Serialize, Default)]
pub struct CallGraphNode {
    /// Self-time sample counts. Only present at leaf nodes.
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

    /// Insert a stack trace into the tree. Only the leaf gets a count.
    fn insert(&mut self, frames: &[&str], count: u64) {
        if frames.is_empty() {
            return;
        }

        let child = self
            .children
            .entry(frames[0].to_owned())
            .or_insert_with(CallGraphNode::new);

        if frames.len() == 1 {
            // Leaf node — add self-time count
            let counts = child.counts.get_or_insert_with(BTreeMap::new);
            *counts.entry("WALL_TIME".to_owned()).or_insert(0) += count;
        } else {
            child.insert(&frames[1..], count);
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
    /// Fleet type: "UNKNOWN", "AWS_EC2_INSTANCE", "AWS_ECS_FARGATE".
    pub fleet_type: String,
}

impl Default for CodeGuruOptions {
    fn default() -> Self {
        let hostname = hostname_or_unknown();
        Self {
            frequency_hz: 99,
            duration_ms: 0,
            fleet_id: hostname,
            fleet_type: "UNKNOWN".to_owned(),
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
pub fn collapse_to_codeguru(stacks: &[String], opts: &CodeGuruOptions) -> String {
    let mut root = CallGraphNode::new();
    let mut total_samples: u64 = 0;

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
        root.insert(&frames, count);
        total_samples += count;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let duration_ms = opts.duration_ms as i64;
    let start_ms = now_ms - duration_ms;

    // sample_weight = total_samples / duration_seconds
    let duration_secs = (duration_ms as f64) / 1000.0;
    let sample_weight = if duration_secs > 0.0 {
        total_samples as f64 / duration_secs
    } else {
        total_samples as f64
    };

    let mut sample_weights = BTreeMap::new();
    sample_weights.insert("WALL_TIME".to_owned(), sample_weight);

    let profile = CodeGuruProfile {
        start: start_ms,
        end: now_ms,
        agent_metadata: AgentMetadata {
            sample_weights,
            duration_in_ms: duration_ms,
            fleet_info: FleetInfo {
                id: opts.fleet_id.clone(),
                fleet_type: opts.fleet_type.clone(),
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

        // Root callgraph should have no children
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
    fn test_single_stack() {
        let stacks = vec!["main;foo;bar 42".to_string()];
        let opts = CodeGuruOptions {
            duration_ms: 10000,
            ..Default::default()
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify tree structure: root -> main -> foo -> bar (leaf with count)
        let main = &parsed["callgraph"]["children"]["main"];
        assert!(!main.is_null(), "should have 'main' child");

        let foo = &main["children"]["foo"];
        assert!(!foo.is_null(), "should have 'foo' child");

        let bar = &foo["children"]["bar"];
        assert!(!bar.is_null(), "should have 'bar' child");

        // bar is the leaf — should have counts
        assert_eq!(bar["counts"]["WALL_TIME"], 42);

        // Intermediate nodes should NOT have counts
        assert!(main["counts"].is_null());
        assert!(foo["counts"].is_null());

        // bar should NOT have children
        assert!(bar["children"].is_null() || bar["children"].as_object().unwrap().is_empty());
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

        // main has two children: process and cleanup
        let main_children = parsed["callgraph"]["children"]["main"]["children"]
            .as_object()
            .unwrap();
        assert_eq!(main_children.len(), 2);
        assert!(main_children.contains_key("process"));
        assert!(main_children.contains_key("cleanup"));

        // process has two children: compute and io_wait
        let process_children = main_children["process"]["children"].as_object().unwrap();
        assert_eq!(process_children.len(), 2);
        assert_eq!(process_children["compute"]["counts"]["WALL_TIME"], 10);
        assert_eq!(process_children["io_wait"]["counts"]["WALL_TIME"], 5);

        // cleanup is a leaf with count 3
        assert_eq!(main_children["cleanup"]["counts"]["WALL_TIME"], 3);

        // Total samples
        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 18);
    }

    #[test]
    fn test_leaf_count_accumulation() {
        // Same leaf reached via same path — counts should accumulate
        let stacks = vec!["main;foo 10".to_string(), "main;foo 5".to_string()];
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed["callgraph"]["children"]["main"]["children"]["foo"]["counts"]["WALL_TIME"],
            15
        );
    }

    #[test]
    fn test_metadata_fields() {
        let stacks = vec!["a;b 1".to_string()];
        let opts = CodeGuruOptions {
            frequency_hz: 99,
            duration_ms: 5000,
            fleet_id: "i-0abc123".to_owned(),
            fleet_type: "AWS_EC2_INSTANCE".to_owned(),
        };
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        let meta = &parsed["agentMetadata"];
        assert_eq!(meta["durationInMs"], 5000);
        assert_eq!(meta["fleetInfo"]["id"], "i-0abc123");
        assert_eq!(meta["fleetInfo"]["type"], "AWS_EC2_INSTANCE");
        assert_eq!(meta["agentInfo"]["type"], "profile-bee");
        assert!(!meta["agentInfo"]["version"].as_str().unwrap().is_empty());
        assert_eq!(meta["numTimesSampled"], 1);

        // sample_weight = 1 sample / 5 seconds = 0.2
        let weight = meta["sampleWeights"]["WALL_TIME"].as_f64().unwrap();
        assert!((weight - 0.2).abs() < 0.001);

        // Timestamps
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

        // Only 2 valid stacks
        assert_eq!(parsed["agentMetadata"]["numTimesSampled"], 15);
        let children = parsed["callgraph"]["children"].as_object().unwrap();
        assert_eq!(children.len(), 2); // "good" and "another"
    }

    #[test]
    fn test_children_is_object_not_array() {
        let stacks = vec!["a;b 1".to_string(), "a;c 2".to_string()];
        let opts = CodeGuruOptions::default();
        let json = collapse_to_codeguru(&stacks, &opts);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // children must be a JSON object (map), not an array
        assert!(parsed["callgraph"]["children"]["a"]["children"].is_object());
    }

    #[test]
    fn test_valid_json_roundtrip() {
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

        // Should parse as valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
        assert!(parsed.is_ok(), "output must be valid JSON");

        // Verify the parsed structure has the expected top-level keys
        let value = parsed.unwrap();
        assert!(value["start"].is_number());
        assert!(value["end"].is_number());
        assert!(value["agentMetadata"].is_object());
        assert!(value["callgraph"].is_object());
    }
}
