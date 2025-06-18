use anyhow::Result;
use std::collections::HashMap;
use std::ops::Deref;
use std::path::PathBuf;

use procmaps::Mappings;

#[derive(Debug)]
pub struct AddressMap {
    map: Vec<AddressEntry>,
}

impl std::fmt::Display for AddressMap {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for entry in &self.map {
            writeln!(f, "{}", entry)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AddressEntry {
    pub path: PathBuf,
    pub start_addr: usize,
    pub end_addr: usize,
}

impl std::fmt::Display for AddressEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "0x{:x}-0x{:x} {}",
            self.start_addr,
            self.end_addr,
            self.path.display()
        )
    }
}

impl AddressMap {
    pub fn load_pid(pid: u32) -> Result<Self> {
        let maps = Mappings::from_pid(pid as _)?;
        let maps = &*maps;

        let mut entries = HashMap::<PathBuf, (usize, usize)>::new();
        for map in maps {
            let procmaps::Path::MappedFile(path) = &map.pathname else {
                continue;
            };

            let filtered = map.perms.executable && map.perms.readable && !map.perms.writable;

            if !filtered {
                continue;
            }

            let entry = entries
                .entry(path.into())
                .or_insert((map.base, map.ceiling));
            entry.0 = usize::min(entry.0, map.base);
            entry.1 = usize::max(entry.1, map.ceiling);
        }

        let mut map: Vec<AddressEntry> = entries
            .into_iter()
            .map(|(path, (start, end))| AddressEntry {
                path,
                start_addr: start,
                end_addr: end,
            })
            .collect();
        map.sort_unstable_by_key(|entry| entry.start_addr);

        Ok(Self { map })
    }
}

impl Deref for AddressMap {
    type Target = [AddressEntry];

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maps() {
        let maps = AddressMap::load_pid(std::process::id()).unwrap();
        println!("{}", maps);
    }
}
