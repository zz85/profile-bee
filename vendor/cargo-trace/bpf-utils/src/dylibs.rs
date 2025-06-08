use crate::elf::{BuildId, Dwarf, Elf};
use crate::maps::AddressMap;
use addr2line::Location;
use anyhow::Result;
use cargo_subcommand::{CrateType, Subcommand};
use ptracer::{ContinueMode, Ptracer};
use std::path::Path;

pub struct Binary {
    pub start_addr: usize,
    pub end_addr: usize,
    pub elf: Elf,
    pub dwarf: Option<Dwarf>,
}

pub struct BinaryInfo {
    map: Vec<Binary>,
    ptracer: Ptracer,
}

impl BinaryInfo {
    pub fn from_cargo_subcommand(cmd: &Subcommand) -> Result<Self> {
        log::debug!("{:?}", cmd);
        let artifact = &cmd.artifacts()[0];
        let path = cmd
            .target_dir()
            .join(cmd.target().unwrap_or(""))
            .join(cmd.profile())
            .join(artifact.as_ref())
            .join(artifact.file_name(CrateType::Bin, cmd.target().unwrap_or("")));
        Self::new(&path, &[])
    }

    pub fn new(path: &Path, args: &[String]) -> Result<Self> {
        log::debug!("loading {}", path.display());
        let mut ptracer = Ptracer::spawn(&path, args)?;
        log::debug!("loaded program with pid {}", ptracer.pid());
        let address_map = AddressMap::load_pid(i32::from(ptracer.pid()) as u32)?;
        let load_addr = address_map[0].start_addr;
        let offset = Elf::open(&address_map[0].path)?
            .resolve_symbol("_start", 0)?
            .unwrap();
        ptracer.insert_breakpoint(load_addr + offset)?;
        ptracer.enable_breakpoint(load_addr + offset)?;
        ptracer.cont(ContinueMode::Default)?;
        ptracer.remove_breakpoint(load_addr + offset)?;
        let address_map = AddressMap::load_pid(i32::from(ptracer.pid()) as u32)?;
        let mut map = vec![];
        for entry in address_map.iter() {
            let elf = Elf::open(&entry.path)?;
            let dwarf = elf.dwarf().ok();
            map.push(Binary {
                start_addr: entry.start_addr,
                end_addr: entry.end_addr,
                elf,
                dwarf,
            });
        }
        Ok(Self { map, ptracer })
    }

    pub fn path(&self) -> &Path {
        self.map[0].elf.path()
    }

    pub fn build_id(&self) -> Result<BuildId> {
        Ok(self.map[0].elf.build_id()?)
    }

    pub fn elf(&self) -> &Elf {
        &self.map[0].elf
    }

    pub fn dwarf(&self) -> Option<&Dwarf> {
        self.map[0].dwarf.as_ref()
    }

    pub fn ptracer(&self) -> &Ptracer {
        &self.ptracer
    }

    pub fn pid(&self) -> u32 {
        i32::from(self.ptracer.pid()) as _
    }

    pub fn cont(&mut self) -> Result<()> {
        self.ptracer.cont(ContinueMode::Default)?;
        Ok(())
    }

    pub fn binary(&self, ip: usize) -> Option<&Binary> {
        let i = match self.map.binary_search_by_key(&ip, |entry| entry.start_addr) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let entry = &self.map[i];
        if ip < entry.start_addr || ip > entry.end_addr {
            None
        } else {
            Some(entry)
        }
    }

    pub fn resolve_symbol(&self, ip: usize) -> Result<Option<String>> {
        if let Some(entry) = self.binary(ip) {
            let offset = ip - entry.start_addr;
            if let Some(dwarf) = entry.dwarf.as_ref() {
                if let Some(frame) = dwarf.find_frames(offset)?.next()? {
                    if let Some(function) = frame.function {
                        return Ok(Some(function.demangle()?.to_string()));
                    }
                }
            }
            if let Some(symbol) = entry.elf.resolve_address(offset)? {
                return Ok(Some(symbol.to_owned()));
            }
        }
        Ok(None)
    }

    pub fn resolve_location(&self, ip: usize) -> Result<Option<Location<'_>>> {
        if let Some(entry) = self.binary(ip) {
            let offset = ip - entry.start_addr;
            if let Some(dwarf) = entry.dwarf.as_ref() {
                if let Some(frame) = dwarf.find_frames(offset)?.next()? {
                    if let Some(loc) = frame.location {
                        return Ok(Some(loc));
                    }
                }
            }
            return Ok(Some(Location {
                file: entry.elf.path().to_str(),
                line: None,
                column: None,
            }));
        }
        Ok(None)
    }

    pub fn print_frame(&self, i: usize, ip: usize) -> Result<()> {
        let symbol = self
            .resolve_symbol(ip)?
            .unwrap_or_else(|| format!("0x{:x}", ip));
        let location = self.resolve_location(ip)?;
        println!("{:4}: {}", i, symbol);
        if let Some(location) = location {
            if let Some(file) = location.file {
                print!("             at {}", file);
            }
            if let Some(line) = location.line {
                print!(":{}", line);
            }
            if let Some(col) = location.column {
                print!(":{}", col);
            }
            println!("");
        }
        Ok(())
    }
}

impl std::ops::Deref for BinaryInfo {
    type Target = [Binary];

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl std::fmt::Display for BinaryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for binary in &self.map {
            write!(
                f,
                "0x{:x}-0x{:x} {} {}",
                binary.start_addr,
                binary.end_addr,
                binary.elf.build_id().unwrap(),
                binary.elf.path().display()
            )?;
            if let Some(dwarf) = binary.dwarf.as_ref() {
                writeln!(f, " {}", dwarf.path().display())?;
            } else {
                writeln!(f, "")?;
            }
        }
        Ok(())
    }
}
