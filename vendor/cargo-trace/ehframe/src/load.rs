

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

*/


use object::{Object, ObjectSection};
use std::error::Error;
use std::fs;

use crate::UnwindTable;

/// Reads a file and displays the name of each section.
pub fn load(path: &str) -> Result<(), Box<dyn Error>> {
    // "path/to/binary"
    let binary_data = fs::read(path)?;
    let file = object::File::parse(&*binary_data)?;
    for section in file.sections() {
        println!("{}", section.name()?);
    }

    let unwind_tables = UnwindTable::parse(&file)?;
    println!("Unwind tables: {:?}", unwind_tables);

    Ok(())
}
