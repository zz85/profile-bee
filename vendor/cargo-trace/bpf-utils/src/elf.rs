use addr2line::{Context, FrameIter, Location};
use anyhow::Result;
use ehframe::UnwindTable;
use memmap::Mmap;
use object::elf::FileHeader64;
use object::read::elf::ElfFile;
use object::{NativeEndian, Object, ObjectSymbol};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Offset `{1}` out of range of `{1}`")]
pub struct OffsetOutOfRange(String, usize);

struct InnerElf {
    _file: File,
    _mmap: Mmap,
    obj: ElfFile<'static, FileHeader64<NativeEndian>>,
    path: PathBuf,
}

#[derive(Clone)]
pub struct Elf(Arc<InnerElf>);

impl Elf {
    pub fn open<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let mmap = unsafe { Mmap::map(&file) }?;
        let data: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };
        let obj = ElfFile::parse(data)?;
        Ok(Self(Arc::new(InnerElf {
            _file: file,
            _mmap: mmap,
            obj,
            path: path.as_ref().to_owned(),
        })))
    }

    pub fn path(&self) -> &Path {
        &self.0.path
    }

    pub fn dwarf(&self) -> Result<Dwarf> {
        if self.0.obj.has_debug_symbols() {
            return Dwarf::new(self.clone());
        }
        let debug_path =
            locate_dwarf::locate_debug_symbols(&self.0.obj, self.path())?.expect("debug_path");
        Dwarf::open(&debug_path)
    }

    pub fn build_id(&self) -> Result<BuildId> {
        Ok(BuildId::new(self.0.obj.build_id()?.unwrap()))
    }

    pub fn unwind_table(&self) -> Result<UnwindTable> {
        UnwindTable::parse(&self.0.obj)
    }

    // pub fn resolve_symbol(&self, symbol: &str, offset: usize) -> Result<Option<usize>> {
    //     for sym in self.0.obj.symbols() {
    //         if sym.name() == Ok(symbol) {
    //             if offset < sym.size() as usize {
    //                 return Ok(Some(sym.address() as usize + offset));
    //             } else {
    //                 return Err(OffsetOutOfRange(symbol.to_string(), offset).into());
    //             }
    //         }
    //     }
    //     Ok(None)
    // }

    // pub fn resolve_address(&self, address: usize) -> Result<Option<&str>> {
    //     for sym in self.0.obj.symbols() {
    //         if sym.address() <= address as u64 && sym.address() + sym.size() > address as u64 {
    //             return Ok(Some(sym.name()?));
    //         }
    //     }
    //     Ok(None)
    // }
}

pub struct Dwarf {
    elf: Elf,
    // ctx: Context<object::read::ReadRef<'static>>,
}

impl Dwarf {
    pub fn new(elf: Elf) -> Result<Self> {
        let load_section = |id: gimli::SectionId| -> Result<_> {
            let data = elf
                .0
                .obj
                .section_by_name(id.name())
                .map(|section| section.uncompressed_data().unwrap_or_default())
                .unwrap_or_default();
            Ok(gimli::EndianSlice::new(&data, gimli::NativeEndian))
        };

        let dwarf = gimli::Dwarf::load(&load_section)?;
        // let ctx = addr2line::Context::from_dwarf(dwarf)?;

        Ok(Self { elf
            // , ctx 
            })
    }

    pub fn open<T: AsRef<Path>>(path: T) -> Result<Self> {
        Self::new(Elf::open(path)?)
    }

    pub fn open_build_id(id: &[u8]) -> Result<Self> {
        let debug_path = locate_dwarf::locate_debug_build_id(id)?;
        Self::open(debug_path)
    }

    pub fn path(&self) -> &Path {
        self.elf.path()
    }

    // pub fn resolve_location(&self, address: usize) -> Result<Option<Location<'_>>> {
    //     Ok(self.ctx.find_location(address as _).unwrap())
    // }

    // pub fn find_frames(&self, probe: usize) -> Result<FrameIter<'_, object::read::ReadRef<'static>>> {
    //     Ok(self.ctx.find_frames(probe as _).unwrap())
    // }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BuildId([u8; 20]);

impl BuildId {
    pub fn new(build_id: &[u8]) -> Self {
        let mut array = [0; 20];
        array.copy_from_slice(build_id);
        Self(array)
    }
}

impl AsRef<[u8]> for BuildId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for BuildId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "../target/debug/examples/hello_world";

    #[test]
    fn test_elf() -> Result<()> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(PATH);
        let elf = Elf::open(&path)?;
        let address = elf.resolve_symbol("main", 0)?.unwrap();
        let symbol = elf.resolve_address(address)?.unwrap();
        assert_eq!(symbol, "main");
        println!("address of main: 0x{:x}", address);
        println!("build id: {}", elf.build_id()?);
        let dwarf = elf.dwarf()?;
        // let location = dwarf.resolve_location(0x5340)?.unwrap();
        // println!(
        //     "location: {:?}:{:?}:{:?}",
        //     location.file, location.line, location.column
        // );
        Ok(())
    }
}
