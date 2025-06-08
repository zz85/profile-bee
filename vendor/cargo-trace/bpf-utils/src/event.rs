use anyhow::{bail, Result};
use std::process::Command;

#[derive(Debug)]
pub enum FieldFormat {
    Simple {
        signed: bool,
        size: usize,
    },
    Array {
        signed: bool,
        size: usize,
        len: usize,
    },
}

#[derive(Debug, Default)]
pub struct EventFormat {
    fields: Vec<(String, FieldFormat)>,
}

impl EventFormat {
    pub fn fields(&self) -> impl Iterator<Item = &(String, FieldFormat)> {
        self.fields.iter()
    }

    fn add_field(&mut self, name: String, format: FieldFormat) {
        self.fields.push((name, format));
    }
}

pub fn event_format(category: &str, name: &str) -> Result<EventFormat> {
    let events_dir = "/sys/kernel/debug/tracing/events";
    let output = Command::new("sudo")
        .arg("cat")
        .arg(format!("{}/{}/{}/format", events_dir, category, name))
        .output()?;
    if !output.status.success() {
        bail!("{}", std::str::from_utf8(&output.stderr)?);
    }
    let lines = std::str::from_utf8(&output.stdout)?.lines().skip(3);
    let mut event = EventFormat::default();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('\t') {
            break;
        }
        let mut cols = line.split('\t').skip(1);
        let (name, len) = parse_decl(cols.next())?;
        cols.next();
        let size: usize = parse_size(cols.next())?;
        let signed: bool = parse_signed(cols.next())?;
        let format = if let Some(len) = len {
            FieldFormat::Array {
                size: size / len,
                signed,
                len,
            }
        } else {
            FieldFormat::Simple { size, signed }
        };
        event.add_field(name.to_owned(), format);
    }
    Ok(event)
}

fn parse_decl(input: Option<&str>) -> Result<(&str, Option<usize>)> {
    if let Some(array) = parse_column(input)?.rsplit(' ').next() {
        let mut iter = array.split(|c| c == '[' || c == ']');
        let name = iter.next();
        let len = iter.next();
        match (name, len) {
            (Some(name), Some(len)) => return Ok((name, Some(len.parse()?))),
            (Some(name), None) => return Ok((name, None)),
            _ => {}
        }
    }
    bail!("parse error: {:?}", input);
}

fn parse_size(input: Option<&str>) -> Result<usize> {
    Ok(parse_column(input)?.parse()?)
}

fn parse_signed(input: Option<&str>) -> Result<bool> {
    match parse_column(input)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => bail!("parse error: {:?}", input),
    }
}

fn parse_column(input: Option<&str>) -> Result<&str> {
    if let Some(input) = input {
        if let Some(size) = input.split(|c| c == ':' || c == ';').nth(1) {
            return Ok(size);
        }
    }
    bail!("parse error: {:?}", input);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_syscalls_sys_enter() {
        event_format("raw_syscalls", "sys_enter").unwrap();
    }

    #[test]
    fn test_raw_syscalls_sys_exit() {
        event_format("raw_syscalls", "sys_exit").unwrap();
    }
}
