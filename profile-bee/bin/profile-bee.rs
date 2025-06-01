use clap::Parser;
use inferno::flamegraph::{self, Options};
use profile_bee::ebpf::{setup_ebpf_profiler, setup_ring_buffer, ProfilerConfig};
use profile_bee::html::{collapse_to_json, generate_html_file};
use profile_bee::Profiler;
use profile_bee_common::{StackInfo, EVENT_TRACE_ALWAYS};
use tokio::task;

use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;

use profile_bee::symbols::FrameCount;

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

    /// method of passes events/traces to
    /// user space.
    /// 1 - always - all events
    /// 2 - new stack traces
    /// 3 - none
    #[arg(long, default_value_t = 2)]
    stream_mode: u8,
}

#[tokio::main]
async fn main() -> std::result::Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    use tokio::sync::broadcast;
    let (tx, rx) = broadcast::channel(16);

    if opt.serve {
        tokio::spawn(async {
            profile_bee::html::start_server(rx).await;
        });
    }

    println!("starting {:?}", opt);

    // Create eBPF profiler configuration from command line options
    let config = ProfilerConfig {
        skip_idle: opt.skip_idle,
        stream_mode: opt.stream_mode,
        frequency: opt.frequency,
        kprobe: opt.kprobe.clone(),
        uprobe: opt.uprobe.clone(),
        tracepoint: opt.tracepoint.clone(),
        pid: opt.pid,
        cpu: opt.cpu,
        self_profile: opt.self_profile,
    };

    // Setup eBPF profiler
    let mut ebpf_profiler = setup_ebpf_profiler(&config)?;

    let mut counts = ebpf_profiler.counts;
    let stack_traces = ebpf_profiler.stack_traces;

    let mut profiler = Profiler::new(); // !opt.no_dwarf

    // Local counting
    let mut trace_count = std::collections::HashMap::<StackInfo, usize>::new();
    let mut samples;
    let mut queue_processed = 0;

    let (perf_tx, perf_rx) = mpsc::channel();

    // use RingBuffer to send into mpsc channel
    task::spawn(async move {
        let ring_buf = setup_ring_buffer(&mut ebpf_profiler.bpf).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let stack: StackInfo = unsafe { *item.as_ptr().cast() };
                    let _ = perf_tx.send(stack);
                }
                Ok(())
            }) {
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(_would_block) => continue,
            }
        }
    });

    loop {
        let started = Instant::now();

        // Clear counters
        trace_count.clear();
        samples = 0;

        // clear "counts" hashmap
        let keys = counts.keys().flatten().collect::<Vec<_>>();
        for k in keys {
            let _ = counts.remove(&k);
            // let _ = counts.insert(k, 0, 0);
        }

        /* Perf mpsc RX loop */
        while let Ok(stack) = perf_rx.recv() {
            queue_processed += 1;

            // user space counting
            let trace = trace_count.entry(stack).or_insert(0);
            *trace += 1;

            if *trace == 1 {
                let _combined = profiler.get_stack(&stack, &stack_traces, opt.group_by_cpu);
            }

            if started.elapsed().as_millis() > opt.time as _ {
                break;
            }
        }

        println!("Processed {} queue events", queue_processed);

        println!("Processing stacks...");

        let mut stacks = Vec::new();
        let local_counting = opt.stream_mode == EVENT_TRACE_ALWAYS;

        if local_counting {
            for (stack, value) in trace_count.iter() {
                let combined = profiler.get_stack(&stack, &stack_traces, opt.group_by_cpu);

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

                let combined = profiler.get_stack(&stack, &stack_traces, opt.group_by_cpu);

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
                svg,
                &out,
                format!(
                    "Flamegraph profile generated from profile-bee ({}ms @ {}hz)",
                    opt.time, opt.frequency
                ),
            )
            .inspect_err(|e| {
                println!("Failed to write svg file {:?} - {:?}", e, svg);
            });
        }

        if opt.html.is_some() || opt.json.is_some() || opt.serve {
            let json = collapse_to_json(&out.iter().map(|v| v.as_str()).collect::<Vec<_>>());

            if let Some(json_path) = &opt.json {
                std::fs::write(json_path, &json).expect("Unable to write stack html file");
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
        }

        if !opt.serve {
            // only loop with serve mode
            break;
        }
    }

    profiler.print_stats();

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
