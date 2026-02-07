mod ehframe;
mod maps;

pub fn get_mappings(pid: usize) -> anyhow::Result<DwarfUnwindInfo> {
    let map = maps::AddressMap::load_pid(pid as _)?;

    tracing::info!("Address maps entries: {}", map.len());

    let mut total_entries = 0;
    let mut unwind = DwarfUnwindInfo::default();

    for entry in map.iter() {
        let path = entry.path.to_str().unwrap();
        let unwind_table = get_unwind_table(path).unwrap();

        tracing::info!(
            "Unwind table entries for {path}: {}",
            unwind_table.rows.len()
        );
        total_entries += unwind_table.rows.len();

        for row in unwind_table.rows.iter() {
            let addr = row.start_address;
            let absolute_addr = entry.start_addr <= addr && addr <= entry.end_addr;

            let addr = if absolute_addr {
                addr
            } else {
                entry.start_addr + addr
            };

            tracing::debug!(
                "abs: {absolute_addr}, addr: {addr} = {} + {}",
                entry.start_addr,
                row.start_address
            );

            // RSP instruction is to derive CFA offset, which later becomes RSP
            let rsp = row.rsp;
            let cfa_offset = match (rsp.op(), rsp.reg(), rsp.offset()) {
                (Op::Register, Some(Reg::Rsp), Some(offset)) => Some(offset),
                _ => None,
            };

            // RIP instruction is instruction from the stack
            let rip = row.rip;
            let rip_offset = match (rip.op(), rip.reg(), rip.offset()) {
                (Op::CfaOffset, None, Some(offset)) => Some(offset),
                // (Op::Register, Some(Reg::Rip), Some(offset)) => {
                //     tracing::info!("RIP register offset: {offset}");
                //     Some(offset)
                // }
                _ => None,
            };

            if let (Some(cfa_offset), Some(rip_offset)) = (cfa_offset, rip_offset) {
                unwind.deltas[unwind.len] = DwarfDelta {
                    addr: addr as _,
                    cfa_offset: cfa_offset as _,
                    rip_offset: rip_offset as _,
                };

                unwind.len += 1;
            }

            // println!("RSP instrustion {rsp:?}");
            // println!("RIP instrustion {rip:?}");
            // println!("CFA offset: {cfa_offset:?} RIP offset: {rip_offset:?}");
        }
    }

    tracing::info!("Total unwind table entries: {total_entries}");

    unwind.deltas[..total_entries].sort_unstable_by_key(|delta| delta.addr);

    Ok(unwind)
}

pub fn find_instruction(pid: usize, ip: u64, rsp: u64) -> anyhow::Result<()> {
    let map = maps::AddressMap::load_pid(pid as _)?;

    // println!("Address maps {:?}", map);

    let mut pc = vec![];
    let mut rip: Vec<Instruction> = vec![];
    let mut rsp: Vec<Instruction> = vec![];

    for entry in map[..].iter() {
        println!("entry: {entry:?}");
        let unwind_table = get_unwind_table(entry.path.to_str().unwrap()).unwrap();

        for row in unwind_table.rows.iter() {
            let addr = entry.start_addr + row.start_address;
            // let addr = row.start_address;
            // println!(
            //     "addr: {addr} = {} + {}",
            //     entry.start_addr, row.start_address
            // ); // :#x
            pc.push(addr as u64);
            rip.push(row.rip.into());
            rsp.push(row.rsp.into());
        }
    }

    println!("pc: {:?}", pc.len());

    let i = match pc.binary_search(&ip) {
        Ok(i) => i,
        Err(i) => i, // -1
    };
    if i >= pc.len() {
        println!("i: {i} too hight");
        anyhow::bail!("no unwind info found");
    }
    println!("i: {i} - {} {:x}", pc[i], pc[i]);
    let irip = rip[i];
    let irsp = rsp[i];

    println!("RSP instrustion {irsp:?}"); // RSP is to derive CFA, which later becomes RSP
    println!("RIP instrustion {irip:?}"); // RIP is instruction to be inserted to stack

    let rsp = 0;

    // rsp: Instruction { op: Register, reg: Some(Rsp), offset: Some(16) } },
    // rip: Instruction { op: CfaOffset, reg: None, offset: Some(-8) },

    // UnwindTableRow { start_address: 4195451, end_address: 4195453,
    // rsp: Instruction { op: Unimplemented, reg: None, offset: None } },
    // rip: Instruction { op: CfaOffset, reg: None, offset: Some(-8) },

    // no-fp
    // RSP instrustion Instruction { op: Register, reg: Some(Rsp), offset: Some(8) }
    // RIP instrustion Instruction { op: CfaOffset, reg: None, offset: Some(-8) }

    // read from memory
    let cfa = execute_instruction(&irsp, ip, rsp, 0).unwrap_or(0);
    let rip = execute_instruction(&irip, ip, rsp, cfa).unwrap_or_default();

    // let mut frame = ehframe::Frame::new(pid as _)?;

    Ok(())
}

fn execute_instruction(ins: &Instruction, rip: u64, rsp: u64, cfa: u64) -> Option<u64> {
    match (ins.op(), ins.reg(), ins.offset()) {
        (Op::CfaOffset, None, Some(offset)) => {
            // Some(unsafe { *((cfa as i64 + offset) as *const u64) })
            Some(0)
        }
        (Op::Register, Some(Reg::Rip), Some(offset)) => Some((rip as i64 + offset) as u64),
        (Op::Register, Some(Reg::Rsp), Some(offset)) => Some((rsp as i64 + offset) as u64),
        _ => None,
    }
}

/*
bpf version

fn execute_instruction(ins: &Instruction, rip: u64, rsp: u64, cfa: u64) -> Option<u64> {
    match ins.op {
        // Undefined
        1 => {
            let unsafe_ptr = (cfa as i64 + ins.offset as i64) as *const core::ffi::c_void;
            let mut res: u64 = 0;
            if unsafe { sys::bpf_probe_read(&mut res as *mut _ as *mut _, 8, unsafe_ptr) } == 0 {
                Some(res)
            } else {
                None
            }
        }
        // CFA
        2 => Some((rip as i64 + ins.offset as i64) as u64),
        // Register
        3 => Some((rsp as i64 + ins.offset as i64) as u64),
        // Unimplemented
        _ => None,
    }
}

 */

// TODO

/* Create UnWindMap

pub fn load() -> Result<Self> {
    let map = AddressMap::load_self()?;
    let mut pc = vec![];
    let mut rip = vec![];
    let mut rsp = vec![];
    for entry in map.iter() {
        let elf = Elf::open(&entry.path)?;
        let table = elf.unwind_table()?;
        for row in table.rows.iter() {
            let addr = entry.start_addr + row.start_address;
            pc.push(addr as u64);
            rip.push(row.rip.into());
            rsp.push(row.rsp.into());
        }
    }
    Ok(Self { pc, rip, rsp })
}

see bpf-backtrace/walk_stack

pub unsafe fn unwind_context(&mut self) -> bool {
        if self.rip == 0 {
            return false;
        }

        let i = self.map.binary_search(self.rip);
        let irip = self.map.rip[i];
        let irsp = self.map.rsp[i];

        let cfa = execute_instruction(&irsp, self.rip, self.rsp, 0).unwrap();
        let rip = execute_instruction(&irip, self.rip, self.rsp, cfa).unwrap_or_default();

        self.rip = rip;
        self.rsp = cfa;

        true
    }

*/

use blazesym::symbolize::cache::Elf;
use object::{Object, ObjectSection};
use profile_bee_common::{DwarfDelta, DwarfUnwindInfo};
use std::error::Error;
use std::fs;
use std::path::Path;

use ehframe::{Instruction, Op, Reg, UnwindTable};

/// Reads a file and displays the name of each section.
pub fn get_unwind_table(path: &str) -> Result<UnwindTable, Box<dyn Error>> {
    // tracing::info!("Loading file: {}", path);
    let binary_data = fs::read(path)?;
    let file = object::File::parse(&*binary_data)?;

    // for section in file.sections() {
    //     println!("{}", section.name()?);
    // }

    let unwind_tables = UnwindTable::parse(&file)?;
    // println!("Unwind tables: {:?}", unwind_tables);

    println!("Unwind tables: {:?}", unwind_tables.rows.len());
    Ok(unwind_tables)
}
