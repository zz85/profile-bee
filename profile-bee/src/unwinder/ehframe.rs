use anyhow::Result;
use gimli::{CfaRule, NativeEndian, RegisterRule, UnwindContext, UnwindSection};
use object::{Object, ObjectSection};

/// Dwarf instruction.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Instruction {
    op: Op,
    reg: Option<Reg>,
    offset: Option<i64>,
}

impl Instruction {
    pub fn unimpl() -> Self {
        Self {
            op: Op::Unimplemented,
            reg: None,
            offset: None,
        }
    }

    pub fn undef() -> Self {
        Self {
            op: Op::Undefined,
            reg: None,
            offset: None,
        }
    }

    pub fn cfa_offset(offset: i64) -> Self {
        Self {
            op: Op::CfaOffset,
            reg: None,
            offset: Some(offset),
        }
    }

    pub fn reg_offset(reg: Reg, offset: i64) -> Self {
        Self {
            op: Op::Register,
            reg: Some(reg),
            offset: Some(offset),
        }
    }

    #[inline(always)]
    pub fn op(&self) -> Op {
        self.op
    }

    #[inline(always)]
    pub fn reg(&self) -> Option<Reg> {
        self.reg
    }

    #[inline(always)]
    pub fn offset(&self) -> Option<i64> {
        self.offset
    }

    #[inline(always)]
    pub fn is_implemented(&self) -> bool {
        self.op != Op::Unimplemented
    }

    #[inline(always)]
    pub fn is_defined(&self) -> bool {
        self.op != Op::Unimplemented && self.op != Op::Undefined
    }
}

impl std::fmt::Display for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.op {
            Op::Unimplemented => write!(f, "unimpl"),
            Op::Undefined => write!(f, "undef"),
            Op::CfaOffset => {
                let offset = self.offset.unwrap();
                let op = if offset >= 0 { "+" } else { "" };
                write!(f, "cfa{}{}", op, offset)
            }
            Op::Register => {
                let reg = self.reg.unwrap();
                let offset = self.offset.unwrap();
                let op = if offset >= 0 { "+" } else { "" };
                write!(f, "{}{}{}", reg, op, offset)
            }
        }
    }
}

/// Dwarf operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Op {
    /// This type of register is not supported.
    Unimplemented = 0,
    /// Undefined register. The value will be defined at some
    /// later IP in the same DIE.
    Undefined = 1,
    /// Value stored at some offset from `CFA`.
    CfaOffset = 2,
    /// Value of a machine register plus offset.
    Register = 3,
}

/// Dwarf register.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Reg {
    Rip = libc::REG_RIP as u8,
    Rsp = libc::REG_RSP as u8,
}

impl Reg {
    fn from_gimli(reg: &gimli::Register) -> Option<Self> {
        Some(match *reg {
            gimli::X86_64::RA => Self::Rip,
            gimli::X86_64::RSP => Self::Rsp,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Rip => write!(f, "rip"),
            Self::Rsp => write!(f, "rsp"),
        }
    }
}

/// Row of a FDE.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnwindTableRow {
    /// Instruction pointer start range (inclusive).
    pub start_address: usize,
    /// Instruction pointer end range (exclusive).
    pub end_address: usize,
    /// Instruction to unwind `rip` register.
    pub rip: Instruction,
    /// Instruction to unwind `rsp` register.
    pub rsp: Instruction,
}

impl UnwindTableRow {
    pub fn parse(row: &gimli::UnwindTableRow<usize>, _encoding: gimli::Encoding) -> Result<Self> {
        Ok(Self {
            start_address: row.start_address() as _,
            end_address: row.end_address() as _,
            rip: match row.register(gimli::X86_64::RA) {
                RegisterRule::Undefined => Instruction::undef(),
                RegisterRule::Offset(offset) => Instruction::cfa_offset(offset),
                _ => {
                    tracing::debug!("unimpl rip {:?}", row.register(gimli::X86_64::RA));
                    Instruction::unimpl()
                }
            },
            rsp: match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => {
                    if let Some(reg) = Reg::from_gimli(&register) {
                        Instruction::reg_offset(reg, *offset)
                    } else {
                        tracing::debug!("unimpl rsp {:?}", row.cfa());
                        Instruction::unimpl()
                    }
                }
                _ => {
                    tracing::debug!("unimpl cfa {:?}", row.cfa());
                    Instruction::unimpl()
                }
            },
        })
    }
}

impl std::fmt::Display for UnwindTableRow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{:0>6x}-0x{:0>6x} {:8} {:8}",
            self.start_address,
            self.end_address,
            self.rip.to_string(),
            self.rsp.to_string(),
        )
    }
}

/// Unwind table.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UnwindTable {
    pub rows: Vec<UnwindTableRow>,
}

impl UnwindTable {
    pub fn parse<'a, O: Object<'a>>(file: &'a O) -> Result<Self> {
        let section = file.section_by_name(".eh_frame").unwrap();
        let data = section.uncompressed_data()?;
        let mut eh_frame = gimli::EhFrame::new(&data, NativeEndian);
        eh_frame.set_address_size(std::mem::size_of::<usize>() as _);

        let mut bases = gimli::BaseAddresses::default();
        if let Some(section) = file.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(section.address());
        }
        if let Some(section) = file.section_by_name(".eh_frame") {
            bases = bases.set_eh_frame(section.address());
        }
        if let Some(section) = file.section_by_name(".text") {
            bases = bases.set_text(section.address());
        }
        if let Some(section) = file.section_by_name(".got") {
            bases = bases.set_got(section.address());
        }

        let mut ctx = UnwindContext::new();
        let mut entries = eh_frame.entries(&bases);
        let mut rows = vec![];
        while let Some(entry) = entries.next()? {
            match entry {
                gimli::CieOrFde::Cie(_) => {}
                gimli::CieOrFde::Fde(partial) => {
                    let fde = partial.parse(|_, bases, o| eh_frame.cie_from_offset(bases, o))?;
                    let encoding = fde.cie().encoding();
                    let mut table = fde.rows(&eh_frame, &bases, &mut ctx)?;
                    while let Some(row) = table.next_row()? {
                        let unwind_row = UnwindTableRow::parse(row, encoding)?;
                        rows.push(unwind_row);
                    }
                }
            }
        }
        rows.sort_unstable_by_key(|row| row.start_address);
        Ok(Self { rows })
    }
}

impl std::fmt::Display for UnwindTable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "{:18} {:8} {:8}", "ip", "rip", "rsp",)?;
        for row in &self.rows {
            writeln!(f, "{}", row)?;
        }
        Ok(())
    }
}
