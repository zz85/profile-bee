use std::path::Path;
use std::path::PathBuf;

use profile_bee_common::StackInfo;

/// Container for stack frame information with count
///
/// Used to track how many times a particular stack trace appears
/// in the profile data for generating accurate flamegraphs.
pub struct FrameCount {
    pub frames: Vec<StackFrameInfo>,
    pub count: u64,
}

/// Struct to contain information about a userspace/kernel stack frame
///
/// Represents a single frame in a stack trace with information about its
/// memory address, associated binary, symbol name, and source location.
/// Used for generating human-readable stack traces in flamegraphs.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct StackFrameInfo {
    pub pid: usize,
    pub cmd: String,

    /// Physical memory address
    pub address: u64,
    /// Shared Object / Module
    pub object_path: Option<PathBuf>,

    /// Source file and location
    pub symbol: Option<String>,

    /// Source file and location
    pub source: Option<String>,

    pub cpu_id: Option<u32>,

    /// namespace
    pub ns: Option<u64>,
}

impl StackFrameInfo {
    /// Creates an empty/default StackFrameInfo
    pub fn prepare(meta: &StackInfo) -> Self {
        Self {
            pid: meta.tgid as usize,
            cmd: meta.get_cmd(),
            // "".to_string(), // don't really need meta.get_cmd(),
            ..Default::default()
        }
    }

    /// Creates an StackFrameInfo placeholder for process name
    pub fn process_only(meta: &StackInfo) -> Self {
        let cmd = meta.get_cmd();
        let with_pid = false;

        let sym = if with_pid {
            format!("{} ({})", cmd, meta.tgid)
        } else {
            cmd.to_owned()
        };

        Self {
            pid: meta.tgid as usize,
            cmd,
            symbol: Some(sym),
            ..Default::default()
        }
    }

    pub fn new(address: u64, object_path: Option<PathBuf>) -> Self {
        Self {
            address,
            object_path,
            ..Default::default()
        }
    }

    /// Physical memory address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Executable or library path. This can be empty if there is no associated object on the filesystem
    pub fn object_path(&self) -> Option<&Path> {
        self.object_path.as_deref()
    }

    pub fn fmt(&self) -> String {
        format!(
            "{:#x}\t{}\t{}\t{}",
            self.address(),
            self.cmd,
            self.fmt_object(),
            self.fmt_symbol()
        )
    }

    pub fn fmt_symbol(&self) -> String {
        format!(
            "{}{}",
            self.symbol.as_deref().unwrap_or(
                //"[unknown]"
                format!("{}+{:#x}", self.fmt_object(), self.address).as_str()
            ),
            self.fmt_source()
        )
    }

    pub fn fmt_object(&self) -> &str {
        self.object_path()
            .and_then(|v| v.file_name())
            .and_then(|v| v.to_str())
            .unwrap_or(&self.cmd)
    }

    fn fmt_shorter_source(&self, count: usize) -> Option<String> {
        StackFrameInfo::fmt_shorter(self.source.as_deref(), count)
    }

    /// instead of bla/meh/mah/test.c
    /// returns mah/test.c for example
    fn fmt_shorter(op: Option<&str>, count: usize) -> Option<String> {
        op.map(|v| {
            v.split('/')
                .rev()
                .take(count)
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .into_iter()
                .rev()
                .collect::<Vec<String>>()
                .join("/")
        })
    }

    pub fn fmt_source(&self) -> String {
        let short = self.fmt_shorter_source(4);

        if let Some(short) = short {
            format!(" ({})", short)
        } else {
            "".to_string()
        }
    }
}

pub trait StackInfoExt {
    fn get_cmd(&self) -> String;
    fn get_cpu_id(&self) -> Option<u32>;
}

impl StackInfoExt for StackInfo {
    fn get_cmd(&self) -> String {
        str_from_u8_nul_utf8(&self.cmd).unwrap().to_owned()
    }

    fn get_cpu_id(&self) -> Option<u32> {
        if self.cpu == u32::MAX {
            return None;
        }

        Some(self.cpu)
    }
}

pub fn str_from_u8_nul_utf8(utf8_src: &[u8]) -> core::result::Result<&str, std::str::Utf8Error> {
    let nul_range_end = utf8_src
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or(utf8_src.len()); // default to length if no `\0` present
    ::std::str::from_utf8(&utf8_src[0..nul_range_end])
}
