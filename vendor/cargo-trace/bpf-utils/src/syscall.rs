use anyhow::Result;
use std::collections::BTreeMap;
use std::process::Command;

pub fn syscall_table() -> Result<BTreeMap<u32, String>> {
    let output = Command::new("ausyscall").arg("--dump").output()?;
    if !output.status.success() {
        anyhow::bail!("{}", std::str::from_utf8(&output.stderr)?);
    }
    let content = std::str::from_utf8(&output.stdout)?;
    let mut table = BTreeMap::new();
    for line in content.lines().skip(1) {
        let mut iter = line.split_whitespace();
        let num = iter
            .next()
            .ok_or_else(|| anyhow::format_err!("expected syscall number"))?;
        let syscall = iter
            .next()
            .ok_or_else(|| anyhow::format_err!("expected syscall name"))?;
        table.insert(num.parse()?, syscall.to_string());
    }
    Ok(table)
}
