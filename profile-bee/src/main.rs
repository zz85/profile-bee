use aya::maps::stack_trace::StackTrace;
use aya::maps::{MapRef, Queue, StackTraceMap};
use aya::programs::{
    perf_event::{PerfEventScope, PerfTypeId, SamplePolicy},
    KProbe, PerfEvent,
};

use aya::{include_bytes_aligned, util::online_cpus, Bpf};
use aya::{BpfLoader, Btf, Pod};
use aya_log::BpfLogger;
use clap::Parser;
use log::info;
use profile_bee_common::StackInfo;
use tokio::signal;

use std::path::PathBuf;
use std::time::{Duration, Instant};

mod symbols;
use symbols::ProcessMapper;

use crate::symbols::{StackFrameInfo, StackMeta, SymbolLookup};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// Filename to write in stackcollapse format
    #[arg(short, long)]
    collapse: Option<PathBuf>,

    #[arg(short, long)]
    svg: Option<PathBuf>,

    #[arg(long)]
    skip_idle: bool,

    /// time for profiling CPU in milliseconds,
    #[arg(short, long, default_value_t = 10000)]
    time: usize,

    /// frequency for sampling,
    #[arg(short, long, default_value_t = 99)]
    frequency: u64,
}

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/profile-bee");
    #[cfg(not(debug_assertions))]
    let data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/profile-bee");

    let skip_idle = if opt.skip_idle { 1u8 } else { 0u8 };

    let mut bpf = BpfLoader::new()
        .set_global("SKIP_IDLE", &skip_idle)
        .btf(Btf::from_sys_fs().ok().as_ref())
        .load(data)?;

    BpfLogger::init(&mut bpf)?;
    let program: &mut PerfEvent = bpf.program_mut("profile_cpu").unwrap().try_into()?;

    program.load()?;

    println!("starting {:?}", opt);

    // https://elixir.bootlin.com/linux/v4.2/source/include/uapi/linux/perf_event.h#L103
    const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

    let cpus = online_cpus()?;
    let nprocs = cpus.len();
    for cpu in cpus {
        program.attach(
            PerfTypeId::Software,
            PERF_COUNT_SW_CPU_CLOCK as u64,
            // CallingProcessAnyCpu
            PerfEventScope::AllProcessesOneCpu { cpu },
            // SamplePolicy::Period(1000000),
            SamplePolicy::Frequency(999),
        )?;
    }

    let mut stacks = Queue::<_, [u8; 28]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map("stack_traces")?)?;

    let symbols = SymbolLookup::new();

    let mut trace_count = std::collections::HashMap::<String, usize>::new();
    let mut samples = 0;

    let started = Instant::now();

    loop {
        if started.elapsed().as_millis() > opt.time as _ {
            break;
        }
        match stacks.pop(0) {
            Ok(v) => {
                let stack: StackInfo = unsafe { *v.as_ptr().cast() };
                let tgid = stack.tgid;
                let ktrace_id = stack.kernel_stack_id;
                let utrace_id = stack.user_stack_id;
                let stack_meta = StackMeta::from(stack);

                let key = if tgid == 0 {
                    "idle".to_string()
                } else {
                    format!("{} ({})", stack_meta.cmd, stack_meta.tgid)
                };

                if tgid == 0 {
                    let key = format!("idle;{} ({})", stack_meta.cmd, tgid);
                    let trace = trace_count.entry(key).or_insert(0);
                    *trace += 1;
                    continue;
                }

                samples += 1;

                let combined =
                    format_stack_trace(ktrace_id, utrace_id, &stack_meta, &stack_traces, &symbols);

                let key = combined
                    .iter()
                    .map(|s| s.fmt_symbol())
                    .collect::<Vec<_>>()
                    .join(";");
                let trace = trace_count.entry(key).or_insert(0);
                *trace += 1;

                // for x in combined {
                //     println!("{}", x.fmt_symbol())
                // }
                // println!("---------------");
            }
            _ => {
                // println!("--------------");
                // tokio::time::sleep(Duration::from_millis(5000)).await;
            }
        }
    }

    let mut out = Vec::new();
    for (k, v) in trace_count {
        out.push(format!("{} {}", k, v));
        samples += v;
    }

    out.sort();

    println!("Total: {}", samples);
    println!("***************************");
    let out = out.join("\n");

    if let Some(name) = opt.collapse {
        println!("writing to file: {}", name.display());
        std::fs::write(name, out).expect("Unable to write file");
    } else {
        println!("{}", out);
    }

    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    Ok(())
}

/// converts pointers from bpf to usable, symbol resolved stack information
fn format_stack_trace(
    ktrace_id: i32,
    utrace_id: i32,
    stack_meta: &StackMeta,
    stack_traces: &StackTraceMap<MapRef>,
    symbols: &SymbolLookup,
) -> Vec<StackFrameInfo> {
    let kernel_stacks = if ktrace_id > -1 {
        stack_traces
            .get(&(ktrace_id as u32), 0)
            .map(|mut trace| symbols.resolve_kernel_trace(&mut trace, stack_meta))
            .ok()
    } else {
        None
    };

    let mapper = ProcessMapper::new(stack_meta.tgid as _);
    if mapper.is_err() {
        println!("Couldn't read pid {}", stack_meta.tgid);
        return vec![StackFrameInfo::process_only(&stack_meta)];
    }
    let mapper = mapper.unwrap();

    let user_stacks = if utrace_id > -1 {
        stack_traces
            .get(&(utrace_id as u32), 0)
            .map(|trace| symbols.resolve_user_trace(&trace, &stack_meta, &mapper))
            .ok()
    } else {
        None
    };

    let mut combined = match (kernel_stacks, user_stacks) {
        (Some(kernel_stacks), None) => kernel_stacks,
        (None, Some(user_stacks)) => user_stacks,
        (Some(kernel_stacks), Some(user_stacks)) => kernel_stacks
            .into_iter()
            .chain(user_stacks.into_iter())
            .collect::<Vec<_>>(),
        _ => Default::default(),
    };

    let pid_info = StackFrameInfo::process_only(&stack_meta);
    combined.push(pid_info);
    combined.reverse();

    combined
}
