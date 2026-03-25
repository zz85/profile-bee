# AWS CodeGuru Profiler JSON Format

This document describes the JSON profile format accepted by the AWS CodeGuru
Profiler `PostAgentProfile` API. No formal public schema exists; this
reference is based on the open-source
[Python agent](https://github.com/aws/amazon-codeguru-profiler-python-agent)
and the
[AWS thread-state documentation](https://docs.aws.amazon.com/codeguru/latest/profiler-ug/working-with-visualizations-thread-states.html).

## Overview

- **Encoding**: JSON (`Content-Type: application/json`)
- **Structure**: Recursive call tree where `children` is a JSON object (map), not an array
- **Counts**: Self-time only, stored at leaf nodes (not cumulative)
- **Upload**: `PostAgentProfile` API via AWS SDK or CLI

## Top-Level Structure

```json
{
  "start": 1711234567000,
  "end": 1711234577000,
  "agentMetadata": { ... },
  "callgraph": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `start` | `i64` | Profile start time (epoch milliseconds) |
| `end` | `i64` | Profile end time (epoch milliseconds) |
| `agentMetadata` | object | Agent, host, and sampling metadata |
| `callgraph` | object | Root node of the recursive call tree |

## Agent Metadata

```json
{
  "sampleWeights": { "RUNNABLE": 16.0 },
  "durationInMs": 10000,
  "fleetInfo": {
    "fleetInstanceId": "i-0abc123def456",
    "hostType": "c5.xlarge"
  },
  "agentInfo": {
    "type": "profile-bee",
    "version": "0.3.7"
  },
  "numTimesSampled": 160634
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sampleWeights` | `{string: f64}` | Counter-type to samples-per-second scaling factor. Key matches the counter type used in `counts`. |
| `durationInMs` | `i64` | Active profiling duration in milliseconds |
| `fleetInfo.fleetInstanceId` | `string` | Host identifier (EC2 instance ID, hostname, etc.) |
| `fleetInfo.hostType` | `string` | Host/instance type (e.g., `"c5.xlarge"`, `"unknown"`) |
| `agentInfo.type` | `string` | Agent name |
| `agentInfo.version` | `string` | Agent version |
| `numTimesSampled` | `u64` | Total number of samples collected |

### Additional Metadata Fields (Python/Java Agents)

These fields are emitted by other agents and accepted by the backend, but
not currently emitted by profile-bee:

| Field | Type | Description |
|-------|------|-------------|
| `agentOverhead.memoryInMB` | `int` | Agent memory usage |
| `agentOverhead.timeInMs` | `int` | Agent CPU overhead |
| `runtimeVersion` | `string` | Language runtime version |
| `cpuTimeInSeconds` | `f64` | Process CPU time during profile window |
| `metrics.numThreads` | `f64` | Average thread count per sample |

## Call Graph Nodes

Each node in the tree has optional `counts` and optional `children`:

```json
{
  "counts": { "RUNNABLE": 42 },
  "children": {
    "child_frame_name": { ... }
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `counts` | `{string: u64}` | Self-time sample counts by counter type. Only present at leaf nodes. Multiple counter types can coexist. |
| `children` | `{string: node}` | Child frames keyed by frame name. Omitted when empty. |
| `file` | `string` | Source file path (optional, not emitted by profile-bee) |
| `line` | `[int]` | Line number or `[start, end]` range (optional) |

### Important: children is an object, not an array

Children are keyed by frame name in a JSON object. This allows the backend
to efficiently merge profiles from multiple agents. Using an array would
break the merge algorithm.

## Counter Types

The `counts` keys correspond to thread states. The CodeGuru console uses
these to populate different visualization views:

| Key | Meaning | CPU View | Latency View |
|-----|---------|----------|--------------|
| `RUNNABLE` | Thread actively executing on CPU | Yes | Yes |
| `BLOCKED` | Thread blocked on a monitor/lock | Yes | Yes |
| `NATIVE` | Thread running native (JNI/FFI) code | Yes | Yes |
| `WAITING` | Thread in wait/join (unbounded) | No | Yes |
| `TIMED_WAITING` | Thread in timed wait/sleep | No | Yes |
| `IDLE` | Thread parked/idle (daemon, pool waiter) | No | No |
| `WALL_TIME` | Generic wall-clock (Python agent default) | Yes | Yes |

### CodeGuru Console Views

- **CPU view** shows: `RUNNABLE` + `BLOCKED` + `NATIVE`
- **Latency view** shows: everything **except** `IDLE`
- **Custom view** lets you pick any combination of counter types

### How profile-bee Maps Counter Types

| Profiling Mode | Counter Type | Rationale |
|----------------|-------------|-----------|
| On-CPU (`--frequency 99`) | `RUNNABLE` | Thread was on-CPU when sampled |
| Off-CPU (`--off-cpu`) | `WAITING` | Thread was blocked when context-switched |
| Generic/mixed | `WALL_TIME` | Catch-all for unclassified samples |

## Example: On-CPU Profile

```bash
sudo probee --codeguru profile.json --time 10000
```

```json
{
  "start": 1711234567000,
  "end": 1711234577000,
  "agentMetadata": {
    "sampleWeights": { "RUNNABLE": 16063.4 },
    "durationInMs": 10000,
    "fleetInfo": { "fleetInstanceId": "ip-10-0-1-42", "hostType": "unknown" },
    "agentInfo": { "type": "profile-bee", "version": "0.3.7" },
    "numTimesSampled": 160634
  },
  "callgraph": {
    "children": {
      "my_server": {
        "children": {
          "handle_request": {
            "children": {
              "parse_json": { "counts": { "RUNNABLE": 5000 } },
              "db_query": { "counts": { "RUNNABLE": 3000 } }
            }
          }
        }
      }
    }
  }
}
```

## Example: Off-CPU Profile

```bash
sudo probee --codeguru offcpu.json --off-cpu --time 10000
```

```json
{
  "start": 1711234567000,
  "end": 1711234577000,
  "agentMetadata": {
    "sampleWeights": { "WAITING": 500.0 },
    "durationInMs": 10000,
    "fleetInfo": { "fleetInstanceId": "ip-10-0-1-42", "hostType": "unknown" },
    "agentInfo": { "type": "profile-bee", "version": "0.3.7" },
    "numTimesSampled": 5000
  },
  "callgraph": {
    "children": {
      "my_server": {
        "children": {
          "handle_request": {
            "children": {
              "db_query": {
                "children": {
                  "io_wait_[k]": { "counts": { "WAITING": 3000 } }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## Upload

### Via AWS CLI

```bash
aws codeguruprofiler post-agent-profile \
  --profiling-group-name my-group \
  --agent-profile fileb://profile.json \
  --content-type application/json
```

### Via profile-bee (requires `aws` feature)

```bash
# Build with AWS support
cargo build --release --features aws

# Profile and upload directly (use sudo -E to preserve AWS credentials)
sudo -E probee \
  --codeguru-upload \
  --profiling-group my-group \
  --time 10000
```

### Verify Upload

```bash
aws codeguruprofiler list-profile-times \
  --profiling-group-name my-group \
  --period PT5M \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S)
```

## Sources

- [Python agent source](https://github.com/aws/amazon-codeguru-profiler-python-agent) — `codeguru_profiler_agent/reporter/agent_configuration.py`, `codeguru_profiler_agent/sdk_reporter/profile_encoder.py`, `codeguru_profiler_agent/agent_metadata/agent_metadata.py`
- [AWS thread state docs](https://docs.aws.amazon.com/codeguru/latest/profiler-ug/working-with-visualizations-thread-states.html)
- [PostAgentProfile API](https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_PostAgentProfile.html)
