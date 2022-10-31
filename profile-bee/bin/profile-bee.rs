use aya::maps::{HashMap, Queue, StackTraceMap};
use aya::programs::{
    perf_event::{PerfEventScope, PerfTypeId, SamplePolicy},
    KProbe, PerfEvent,
};
use aya::programs::{TracePoint, UProbe};

use aya::{include_bytes_aligned, util::online_cpus, Bpf};
use aya::{BpfLoader, Btf};
use clap::Parser;
use inferno::flamegraph::{self, Options};
use log::info;
use profile_bee::format_stack_trace;
use profile_bee::html::{collapse_to_json, generate_html_file};
use profile_bee_common::StackInfo;
use tokio::signal;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use profile_bee::symbols::{FrameCount, SymbolFinder};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Opt {
    /// Filename to write in stackcollapse format
    #[arg(short, long)]
    collapse: Option<PathBuf>,

    /// Filename to generate flamegraph svg
    #[arg(short, long)]
    svg: Option<PathBuf>,

    /// Filename for generate html version of flamegraph
    #[arg(long)]
    html: Option<PathBuf>,

    /// Generate json data format in d3 flamegraph format
    #[arg(long)]
    json: Option<PathBuf>,

    /// Starts a http server to serve the html flamegraph result
    #[arg(long)]
    serve: bool,

    /// Avoid profiling idle cpu cycles
    #[arg(long)]
    skip_idle: bool,

    /// Time to run CPU profiling in milliseconds,
    #[arg(short, long, default_value_t = 10000)]
    time: usize,

    /// Frequency for sampling,
    #[arg(short, long, default_value_t = 99)]
    frequency: u64,

    /// function name to attached kprobe
    #[arg(long)]
    kprobe: Option<String>,

    /// function name to attached uprobe
    #[arg(long)]
    uprobe: Option<String>,

    /// function name to attached tracepoint eg.
    #[arg(long)]
    tracepoint: Option<String>,

    #[arg(long, default_value_t = false)]
    group_by_cpu: bool,

    #[arg(long, default_value_t = false)]
    no_dwarf: bool,

    /// PID to profile
    #[arg(short, long)]
    pid: Option<u32>,

    /// target CPU to profile
    #[arg(long)]
    cpu: Option<u32>,

    /// Profile this process
    #[arg(long, default_value_t = false)]
    self_profile: bool,
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

    // this might be useful for debugging, but definitely disable bpf logging for performance purposes
    // aya_log::BpfLogger::init(&mut bpf)?;

    use tokio::sync::broadcast;
    let (tx, rx) = broadcast::channel(16);

    if opt.serve {
        tokio::spawn(async {
            profile_bee::html::start_server(rx).await;
        });
    }

    println!("starting {:?}", opt);

    if let Some(kprobe) = &opt.kprobe {
        let program: &mut KProbe = bpf.program_mut("kprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(kprobe, 0)?;
    } else if let Some(uprobe) = &opt.uprobe {
        let program: &mut UProbe = bpf.program_mut("uprobe_profile").unwrap().try_into()?;
        program.load()?;
        program.attach(Some(uprobe), 0, "libc", None)?;
    } else if let Some(tracepoint) = &opt.tracepoint {
        let program: &mut TracePoint = bpf.program_mut("tracepoint_profile").unwrap().try_into()?;
        program.load()?;

        let mut split = tracepoint.split(':');
        let category = split.next().expect("category");
        let name = split.next().expect("name");

        program.attach(category, name)?;
    } else {
        let program: &mut PerfEvent = bpf.program_mut("profile_cpu").unwrap().try_into()?;

        program.load()?;

        // https://elixir.bootlin.com/linux/v4.2/source/include/uapi/linux/perf_event.h#L103
        const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

        if opt.self_profile {
            program.attach(
                PerfTypeId::Software,
                PERF_COUNT_SW_CPU_CLOCK as u64,
                PerfEventScope::CallingProcessAnyCpu,
                SamplePolicy::Frequency(opt.frequency),
            )?;
        } else if let Some(pid) = opt.pid {
            program.attach(
                PerfTypeId::Software,
                PERF_COUNT_SW_CPU_CLOCK as u64,
                PerfEventScope::OneProcessAnyCpu { pid },
                SamplePolicy::Frequency(opt.frequency),
            )?;
        } else if let Some(cpu) = opt.cpu {
            program.attach(
                PerfTypeId::Software,
                PERF_COUNT_SW_CPU_CLOCK as u64,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(opt.frequency),
            )?;
        } else {
            let cpus = online_cpus()?;
            let nprocs = cpus.len();
            eprintln!("CPUs: {}", nprocs);

            for cpu in cpus {
                program.attach(
                    PerfTypeId::Software,
                    PERF_COUNT_SW_CPU_CLOCK as u64,
                    PerfEventScope::AllProcessesOneCpu { cpu },
                    // SamplePolicy::Period(1000000),
                    SamplePolicy::Frequency(opt.frequency),
                )?;
            }
        }
    }

    const STACK_INFO_SIZE: usize = std::mem::size_of::<StackInfo>();
    let mut stacks = Queue::<_, [u8; STACK_INFO_SIZE]>::try_from(bpf.map_mut("STACKS")?)?;
    let stack_traces = StackTraceMap::try_from(bpf.map("stack_traces")?)?;
    let counts = HashMap::<_, [u8; STACK_INFO_SIZE], u64>::try_from(bpf.map("counts")?)?;

    let mut symbols = SymbolFinder::new(!opt.no_dwarf);

    // Local counting
    let mut trace_count = std::collections::HashMap::<StackInfo, usize>::new();
    let mut samples;
    let mut queue_processed = 0;

    loop {
        let started = Instant::now();

        // Clear counters
        trace_count.clear();
        samples = 0;

        // TODO clear for bpf maps
        // for (key, value) in counts.iter().flatten() {
        //     counts.remove(&fail);
        // }

        /*
         */
        loop {
            if started.elapsed().as_millis() > opt.time as _ {
                break;
            }
            match stacks.pop(0) {
                Ok(v) => {
                    let stack: StackInfo = unsafe { *v.as_ptr().cast() };
                    queue_processed += 1;

                    // user space counting
                    let trace = trace_count.entry(stack).or_insert(0);
                    *trace += 1;

                    if *trace == 1 {
                        let _combined = format_stack_trace(
                            &stack,
                            &stack_traces,
                            &mut symbols,
                            opt.group_by_cpu,
                        );
                    }
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            }
        }

        println!("Processed {} queue events", queue_processed);

        println!("Processing stacks...");

        let mut stacks = Vec::new();
        let local_counting = true;

        if local_counting {
            for (stack, value) in trace_count.iter() {
                let combined =
                    format_stack_trace(&stack, &stack_traces, &mut symbols, opt.group_by_cpu);

                samples += *value as u64;
                stacks.push(FrameCount {
                    frames: combined,
                    count: *value as u64,
                });
            }
        } else {
            // kernel counting
            for (key, value) in counts.iter().flatten() {
                let stack: StackInfo = unsafe { *key.as_ptr().cast() };

                samples += value;

                let combined =
                    format_stack_trace(&stack, &stack_traces, &mut symbols, opt.group_by_cpu);

                stacks.push(FrameCount {
                    frames: combined,
                    count: value,
                });
            }
        }

        // TODO stack processing can be expensive, so consider moving into a separate task
        // to avoid blocking the collection loop

        println!("Total samples: {}", samples);

        let mut out = stacks
            .into_iter()
            .map(|frames| {
                let key = frames
                    .frames
                    .iter()
                    .map(|s| s.fmt_symbol())
                    .collect::<Vec<_>>()
                    .join(";");
                let count = frames.count;
                format!("{} {}", &key, count)
            })
            .collect::<Vec<_>>();
        out.sort();

        if let Some(svg) = &opt.svg {
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

        if opt.html.is_some() || opt.json.is_some() || opt.serve {
            let json = collapse_to_json(&out.iter().map(|v| v.as_str()).collect::<Vec<_>>());

            if let Some(json_path) = &opt.json {
                std::fs::write(&json_path, &json).expect("Unable to write stack html file");
            }

            if let Some(html_path) = &opt.html {
                generate_html_file(html_path, &json);
            }

            let r = tx.send(json);
            println!("Sending {:?}", r);
        }

        let out = out.join("\n");

        if let Some(name) = &opt.collapse {
            println!("Writing to file: {}", name.display());
            std::fs::write(name, &out).expect("Unable to write stack collapsed file");
        } else {
            // println!("***************************");
            // println!("{}", out);
        }

        if !opt.serve {
            // only loop with serve mode
            break;
        }
    }

    println!("{}", symbols.process_cache.stats());

    // TODO fix this
    /*
    if opt.serve {
        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
        info!("Exiting...");
    }
    */

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
