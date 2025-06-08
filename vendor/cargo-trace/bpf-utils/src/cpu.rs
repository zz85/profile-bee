use anyhow::Result;

pub fn online_cpu_ids() -> Result<Vec<u32>> {
    let path = "/sys/devices/system/cpu/online";
    let content = std::fs::read_to_string(&path)?;
    Ok(content
        .trim()
        .split(',')
        .flat_map(|group| {
            let mut iter = group.split('-');
            let start = iter.next().unwrap().parse().unwrap();
            let end = iter.next().map(|i| i.parse().unwrap()).unwrap_or(start);
            start..=end
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_cpu_ids() {
        assert!(!online_cpu_ids().unwrap().is_empty());
    }
}
