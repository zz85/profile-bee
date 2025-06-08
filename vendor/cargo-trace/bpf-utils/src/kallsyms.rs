use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KernelSymbol {
    symbol: String,
    address: usize,
}

pub struct KernelSymbolTable {
    symbols: Vec<KernelSymbol>,
}

impl KernelSymbolTable {
    pub fn load() -> Result<Self> {
        let mut f = BufReader::new(File::open("/proc/kallsyms")?);
        let mut symbols = Vec::with_capacity(200_000);
        let mut line = String::with_capacity(100);
        while f.read_line(&mut line)? > 0 {
            let mut iter = line.split(' ');
            let address = usize::from_str_radix(iter.next().unwrap(), 16)?;
            let symbol = iter.nth(1).unwrap().trim().to_string();
            symbols.push(KernelSymbol { symbol, address });
            line.clear();
        }
        symbols.shrink_to_fit();
        Ok(Self { symbols })
    }

    pub fn symbol(&self, address: usize) -> (&str, usize) {
        let i = match self
            .symbols
            .binary_search_by_key(&address, |ksym| ksym.address)
        {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let ksym = &self.symbols[i];
        let offset = address - ksym.address;
        (&ksym.symbol, offset)
    }
}
