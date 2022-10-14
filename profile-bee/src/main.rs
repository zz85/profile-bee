use aya::maps::{HashMap, MapRef, Queue, StackTraceMap};
use aya::programs::{
    perf_event::{PerfEventScope, PerfTypeId, SamplePolicy},
    KProbe, PerfEvent,
};

use aya::{include_bytes_aligned, util::online_cpus, Bpf};
use aya::{BpfLoader, Btf, Pod};
use aya_log::BpfLogger;
use clap::Parser;
use inferno::flamegraph::{self, Options};
use log::info;
use profile_bee_common::StackInfo;
use tokio::signal;

use std::path::PathBuf;
use std::time::{Duration, Instant};

mod symbols;

use crate::symbols::{StackFrameInfo, StackMeta, SymbolFinder};

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
        .load(data)
        .map_err(|e| {
            println!("{:?}", e);
            e
        })?;

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
            SamplePolicy::Frequency(opt.frequency),
        )?;
    }

    let mut stacks = Queue::<_, [u8; 28]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map("stack_traces")?)?;
    let counts = HashMap::<_, [u8; 28], u64>::try_from(bpf.map("counts")?)?;

    let mut symbols = SymbolFinder::new();

    let mut trace_count = std::collections::HashMap::<String, usize>::new();
    let mut samples = 0;
    let mut queue_processed = 0;

    let started = Instant::now();

    /*
     */
    loop {
        if started.elapsed().as_millis() > opt.time as _ {
            break;
        }
        match stacks.pop(0) {
            Ok(v) => {
                let stack: StackInfo = unsafe { *v.as_ptr().cast() };
                let stack_meta = StackMeta::from(stack);

                queue_processed += 1;

                let combined = format_stack_trace(&stack, &stack_meta, &stack_traces, &mut symbols);

                let key = combined
                    .iter()
                    .map(|s| s.fmt_symbol())
                    .collect::<Vec<_>>()
                    .join(";");

                // user space counting
                let trace = trace_count.entry(key).or_insert(0);
                *trace += 1;

                // for x in combined {
                //     println!("{}", x.fmt_symbol())
                // }
                // println!("---------------");
            }
            _ => {
                // println!("--------------");
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        }
    }

    println!("Processed {} queue events", queue_processed);
    // let mut out = Vec::new();
    // for (k, v) in trace_count {
    //     out.push(format!("{} {}", k, v));
    //     samples += v;
    // }

    // out.sort();

    // println!("Sleep for {}", opt.time);
    // tokio::time::sleep(Duration::from_millis(opt.time as _)).await;
    println!("Processing stacks...");

    let mut out = Vec::new();
    for i in counts.iter() {
        if let Ok((key, value)) = i {
            let stack: StackInfo = unsafe { *key.as_ptr().cast() };

            let stack_meta = StackMeta::from(stack);

            samples += value;

            let combined = format_stack_trace(&stack, &stack_meta, &stack_traces, &mut symbols);

            let key = combined
                .iter()
                .map(|s| s.fmt_symbol())
                .collect::<Vec<_>>()
                .join(";");

            out.push(format!("{} {}", &key, &value));
        }
    }

    out.sort();

    println!("Total samples: {}", samples);

    if let Some(svg) = opt.svg {
        let _ = output_svg(
            &svg,
            &out,
            format!(
                "Flamegraph profile generated from profile-bee ({}ms @ {}hz)",
                opt.time, opt.frequency
            ),
        )
        .map_err(|e| {
            println!("Failed to write svg file {:?}", svg);
            e
        });
    }

    let out = out.join("\n");

    if let Some(name) = opt.collapse {
        println!("Writing to file: {}", name.display());
        std::fs::write(name, &out).expect("Unable to write stack collapsed file");
    } else {
        println!("***************************");
        println!("{}", out);
    }

    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    Ok(())
}

/// Creates a flamegraph svg file using the inferno-flamegraph lib
fn output_svg(path: &PathBuf, str: &[String], title: String) -> anyhow::Result<()> {
    let mut svg_opts = Options::default();
    svg_opts.title = title;
    let mut svg_file = std::io::BufWriter::with_capacity(1024 * 1024, std::fs::File::create(path)?);
    flamegraph::from_lines(&mut svg_opts, str.iter().map(|v| v.as_str()), &mut svg_file)?;

    Ok(())
}

/// converts pointers from bpf to usable, symbol resolved stack information
fn format_stack_trace(
    stack_info: &StackInfo,
    stack_meta: &StackMeta,
    stack_traces: &StackTraceMap<MapRef>,
    symbols: &mut SymbolFinder,
) -> Vec<StackFrameInfo> {
    let ktrace_id = stack_info.kernel_stack_id;
    let utrace_id = stack_info.user_stack_id;

    if stack_meta.tgid == 0 {
        let mut idle = StackFrameInfo::prepare(stack_meta);
        idle.symbol = Some("idle".into());
        let idle_cpu = StackFrameInfo::process_only(stack_meta);

        return vec![idle, idle_cpu];
    }

    let kernel_stacks = if ktrace_id > -1 {
        stack_traces
            .get(&(ktrace_id as u32), 0)
            .map(|mut trace| symbols.resolve_kernel_trace(&mut trace, stack_meta))
            .ok()
    } else {
        None
    };

    let user_stacks = if utrace_id > -1 {
        stack_traces
            .get(&(utrace_id as u32), 0)
            .map(|trace| symbols.resolve_user_trace(&trace, stack_meta))
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

    let pid_info = StackFrameInfo::process_only(stack_meta);
    combined.push(pid_info);
    combined.reverse();

    combined
}
