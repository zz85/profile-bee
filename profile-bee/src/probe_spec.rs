//! Probe specification parser for GDB-style uprobe targeting.
//!
//! Supports a unified spec syntax:
//!   malloc                        - auto-discover which library has it
//!   libc:malloc                   - explicit library prefix
//!   /usr/lib/libc.so.6:malloc     - explicit absolute path
//!   malloc+0x10                   - function + offset
//!   ret:malloc                    - uretprobe (return probe)
//!   file.c:42                     - source file + line number (needs DWARF)
//!   MyClass::method               - C++ mangled name matching
//!   pthread_*                     - glob pattern matching
//!   /regex_pattern/               - regex matching

use std::fmt;

use regex::Regex;

/// A parsed probe specification.
#[derive(Debug, Clone)]
pub enum ProbeSpec {
    /// Match by symbol name pattern (exact, glob, regex, or demangled).
    Symbol {
        /// Optional library constraint ("libc", "/usr/lib/foo.so", etc.).
        /// None means auto-discover across all loaded libraries.
        library: Option<String>,
        /// The pattern to match symbol names against.
        pattern: SymbolPattern,
        /// Byte offset within the matched function.
        offset: u64,
        /// Whether this is a return probe (uretprobe).
        is_ret: bool,
    },
    /// Match by source file and line number (requires DWARF debug info).
    SourceLocation {
        /// Source file name or path (e.g. "main.c", "src/lib.rs").
        file: String,
        /// Line number in the source file.
        line: u32,
        /// Whether this is a return probe (uretprobe).
        is_ret: bool,
    },
}

/// Pattern types for matching symbol names.
#[derive(Debug, Clone)]
pub enum SymbolPattern {
    /// Exact symbol name match (e.g. "malloc").
    Exact(String),
    /// Glob pattern match (e.g. "pthread_*", "sql_?uery").
    Glob(String),
    /// Regex match (e.g. "/^sql_.*query/").
    Regex(RegexWrapper),
    /// Demangled name match -- demangles each symbol and matches against this string.
    /// Triggered by C++ `::` separator (e.g. "MyClass::method", "std::vector::push_back").
    Demangled(String),
}

/// Wrapper around regex::Regex to implement Debug + Clone.
#[derive(Clone)]
pub struct RegexWrapper {
    pub regex: Regex,
    pub source: String,
}

impl fmt::Debug for RegexWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Regex({})", self.source)
    }
}

impl SymbolPattern {
    /// Test whether a raw (mangled) symbol name matches this pattern.
    pub fn matches(&self, symbol_name: &str) -> bool {
        match self {
            SymbolPattern::Exact(name) => symbol_name == name,
            SymbolPattern::Glob(pattern) => glob_match(pattern, symbol_name),
            SymbolPattern::Regex(rw) => rw.regex.is_match(symbol_name),
            // For demangled patterns, the caller should demangle first then call matches_demangled.
            SymbolPattern::Demangled(_) => false,
        }
    }

    /// Test whether a demangled symbol name matches this pattern.
    /// For Demangled patterns, checks if the demangled name contains the query.
    /// For other patterns, delegates to normal matching against the demangled name.
    pub fn matches_demangled(&self, demangled_name: &str) -> bool {
        match self {
            SymbolPattern::Demangled(query) => {
                // Support both exact match and substring match on demangled names.
                // e.g. "MyClass::method" matches "MyNamespace::MyClass::method(int)"
                demangled_name.contains(query.as_str())
            }
            // For non-demangled patterns, also try matching against the demangled form
            other => other.matches(demangled_name),
        }
    }

    /// Returns true if this is a single-match pattern (Exact), meaning it can
    /// potentially be resolved by Aya's built-in symbol resolution without
    /// scanning all ELFs ourselves.
    pub fn is_exact(&self) -> bool {
        matches!(self, SymbolPattern::Exact(_))
    }

    /// Return the pattern string for display purposes.
    pub fn display_str(&self) -> &str {
        match self {
            SymbolPattern::Exact(s) => s,
            SymbolPattern::Glob(s) => s,
            SymbolPattern::Regex(rw) => &rw.source,
            SymbolPattern::Demangled(s) => s,
        }
    }
}

/// Parse a probe specification string into a `ProbeSpec`.
///
/// Grammar:
///   spec          = ["ret:"] [library ":"] pattern ["+" offset]
///   spec          = ["ret:"] file ":" line_number
///   library       = absolute_path | library_name
///   pattern       = "/" regex "/" | glob_pattern | demangled_pattern | exact_name
///   offset        = hex_or_decimal_number
///
/// Examples:
///   "malloc"                      -> Symbol { library: None, pattern: Exact("malloc"), ... }
///   "libc:malloc"                 -> Symbol { library: Some("libc"), pattern: Exact("malloc"), ... }
///   "ret:malloc"                  -> Symbol { is_ret: true, ... }
///   "pthread_*"                   -> Symbol { pattern: Glob("pthread_*"), ... }
///   "/sql_.*query/"               -> Symbol { pattern: Regex(...), ... }
///   "std::vector::push_back"      -> Symbol { pattern: Demangled("std::vector::push_back"), ... }
///   "main.c:42"                   -> SourceLocation { file: "main.c", line: 42 }
///   "/usr/lib/libc.so.6:malloc"   -> Symbol { library: Some("/usr/lib/libc.so.6"), ... }
pub fn parse_probe_spec(input: &str) -> Result<ProbeSpec, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("empty probe specification".to_string());
    }

    // Step 1: Strip "ret:" prefix
    let (is_ret, rest) = if let Some(stripped) = input.strip_prefix("ret:") {
        (true, stripped)
    } else {
        (false, input)
    };

    // Step 2: Check for bare regex pattern /pattern/ (no library prefix).
    // We distinguish from absolute paths: absolute paths like /usr/lib/...
    // contain slashes within the regex_str portion, so try_parse_regex_symbol
    // will return None for those.
    if rest.starts_with('/') && !rest.contains(':') {
        if let Some((regex_wrapper, offset)) = try_parse_regex_symbol(rest)? {
            return Ok(ProbeSpec::Symbol {
                library: None,
                pattern: SymbolPattern::Regex(regex_wrapper),
                offset,
                is_ret,
            });
        }
        // If not a valid regex, fall through — it's an absolute path
    }

    // Step 3: Split on colon to detect library:symbol or file:line
    // But be careful: C++ demangled names contain "::" which is NOT a library separator.
    // Also, absolute paths start with "/" and contain colons only as library:symbol separator.
    let (library, symbol_part) = split_library_and_symbol(rest)?;

    // Step 4: Check if this is a source location (file:line where line is numeric)
    // This only applies when we got a colon split and the "symbol" part is purely numeric.
    if let Some(ref lib) = library {
        if let Ok(line) = symbol_part.parse::<u32>() {
            // Looks like file.c:42
            // Heuristic: if the "library" part looks like a source file
            // (has a file extension or is a relative path), treat as source location.
            if looks_like_source_file(lib) {
                return Ok(ProbeSpec::SourceLocation {
                    file: lib.clone(),
                    line,
                    is_ret,
                });
            }
        }
    }

    // Step 5: Check if symbol part is a regex /pattern/ (handles library:/regex/ case)
    if let Some(regex_result) = try_parse_regex_symbol(&symbol_part)? {
        let (regex_wrapper, offset) = regex_result;
        return Ok(ProbeSpec::Symbol {
            library,
            pattern: SymbolPattern::Regex(regex_wrapper),
            offset,
            is_ret,
        });
    }

    // Step 6: Parse offset from symbol part
    let (symbol_name, offset) = split_symbol_and_offset(&symbol_part)?;

    // Step 7: Determine pattern type
    let pattern = classify_pattern(&symbol_name);

    Ok(ProbeSpec::Symbol {
        library,
        pattern,
        offset,
        is_ret,
    })
}

/// Split a spec string into optional library prefix and symbol/pattern part.
///
/// Handles:
///   "malloc"                    -> (None, "malloc")
///   "libc:malloc"               -> (Some("libc"), "malloc")
///   "/usr/lib/libc.so.6:malloc" -> (Some("/usr/lib/libc.so.6"), "malloc")
///   "std::vector::push_back"    -> (None, "std::vector::push_back")  [C++ demangled]
///   "main.c:42"                 -> (Some("main.c"), "42")
fn split_library_and_symbol(s: &str) -> Result<(Option<String>, String), String> {
    // If it starts with "/" and doesn't end with "/", it could be an absolute path prefix.
    // Find the LAST ":" that isn't part of "::"
    // e.g. "/usr/lib/libc.so.6:malloc" -> split at the last ":"
    //      "std::vector::push_back"     -> no split (all colons are part of "::")

    // Simple approach: find all single-colon positions (not part of "::")
    let bytes = s.as_bytes();
    let mut single_colon_positions = Vec::new();

    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            // Check if this is part of "::"
            let is_double =
                (i + 1 < bytes.len() && bytes[i + 1] == b':') || (i > 0 && bytes[i - 1] == b':');
            if !is_double {
                single_colon_positions.push(i);
            } else {
                // Skip the next ':' if this is the first of a "::" pair
                if i + 1 < bytes.len() && bytes[i + 1] == b':' {
                    i += 1;
                }
            }
        }
        i += 1;
    }

    if single_colon_positions.is_empty() {
        // No library prefix
        Ok((None, s.to_string()))
    } else {
        // Use the LAST single colon as the separator.
        // This handles "/usr/lib/x86_64-linux-gnu/libc.so.6:malloc" correctly
        // even if there were somehow other colons in the path.
        let pos = *single_colon_positions.last().unwrap();
        let library = &s[..pos];
        let symbol = &s[pos + 1..];
        if symbol.is_empty() {
            return Err(format!("empty symbol after library prefix '{}'", library));
        }
        Ok((Some(library.to_string()), symbol.to_string()))
    }
}

/// Split "function_name+0x10" or "function_name+16" into (name, offset).
fn split_symbol_and_offset(s: &str) -> Result<(String, u64), String> {
    if let Some(plus_pos) = s.rfind('+') {
        let name = &s[..plus_pos];
        let offset_str = &s[plus_pos + 1..];

        // Guard: don't split on "+" inside C++ operator names like "operator+"
        if name.ends_with("operator") {
            return Ok((s.to_string(), 0));
        }

        let offset = if let Some(hex) = offset_str
            .strip_prefix("0x")
            .or_else(|| offset_str.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
                .map_err(|e| format!("invalid hex offset '{}': {}", offset_str, e))?
        } else {
            offset_str
                .parse::<u64>()
                .map_err(|e| format!("invalid offset '{}': {}", offset_str, e))?
        };

        Ok((name.to_string(), offset))
    } else {
        Ok((s.to_string(), 0))
    }
}

/// Parse optional "+offset" from the end of a string (used after regex patterns).
fn parse_trailing_offset(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    if let Some(rest) = s.strip_prefix('+') {
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
                .map_err(|e| format!("invalid hex offset '{}': {}", rest, e))
        } else {
            rest.parse::<u64>()
                .map_err(|e| format!("invalid offset '{}': {}", rest, e))
        }
    } else {
        Err(format!("unexpected trailing text: '{}'", s))
    }
}

/// Try to parse a symbol string as a `/regex/` pattern (with optional trailing +offset).
/// Returns `Some((RegexWrapper, offset))` if it matches, `None` if not regex syntax.
fn try_parse_regex_symbol(s: &str) -> Result<Option<(RegexWrapper, u64)>, String> {
    if !s.starts_with('/') || s.len() < 3 {
        return Ok(None);
    }

    // Find the closing '/' — must not be the first character
    let last_slash = match s[1..].rfind('/') {
        Some(pos) => pos + 1, // offset back into full string
        None => return Ok(None),
    };

    if last_slash == 0 {
        return Ok(None);
    }

    let regex_str = &s[1..last_slash];
    let after_regex = &s[last_slash + 1..];

    if regex_str.is_empty() {
        return Ok(None);
    }

    let offset = parse_trailing_offset(after_regex)?;

    let regex =
        Regex::new(regex_str).map_err(|e| format!("invalid regex '{}': {}", regex_str, e))?;

    Ok(Some((
        RegexWrapper {
            regex,
            source: regex_str.to_string(),
        },
        offset,
    )))
}

/// Classify a symbol name string into the appropriate SymbolPattern variant.
fn classify_pattern(name: &str) -> SymbolPattern {
    if name.contains("::") {
        // C++ or Rust demangled name
        SymbolPattern::Demangled(name.to_string())
    } else if name.contains('*') || name.contains('?') || name.contains('[') {
        // Glob pattern
        SymbolPattern::Glob(name.to_string())
    } else {
        // Exact match
        SymbolPattern::Exact(name.to_string())
    }
}

/// Heuristic: does this string look like a source file name?
fn looks_like_source_file(s: &str) -> bool {
    let extensions = [
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".rs", ".go", ".java", ".py", ".rb",
        ".js", ".ts", ".S", ".s", ".asm",
    ];
    extensions.iter().any(|ext| s.ends_with(ext))
}

/// Simple glob matching supporting `*`, `?`, and `[...]` character classes.
fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_recursive(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_recursive(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == b'?' {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'[' {
            // Character class
            if let Some((matched, end)) = match_char_class(&pattern[pi..], text[ti]) {
                if matched {
                    pi += end;
                    ti += 1;
                } else if star_pi != usize::MAX {
                    pi = star_pi + 1;
                    star_ti += 1;
                    ti = star_ti;
                } else {
                    return false;
                }
            } else {
                // Malformed character class, treat as literal
                if pattern[pi] == text[ti] {
                    pi += 1;
                    ti += 1;
                } else if star_pi != usize::MAX {
                    pi = star_pi + 1;
                    star_ti += 1;
                    ti = star_ti;
                } else {
                    return false;
                }
            }
        } else if pi < pattern.len() && pattern[pi] == text[ti] {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing *
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

/// Match a character class pattern like [abc], [a-z], [^abc].
/// Returns (matched, bytes_consumed_in_pattern) or None if malformed.
fn match_char_class(pattern: &[u8], ch: u8) -> Option<(bool, usize)> {
    if pattern.is_empty() || pattern[0] != b'[' {
        return None;
    }

    let mut i = 1;
    let negate = if i < pattern.len() && (pattern[i] == b'^' || pattern[i] == b'!') {
        i += 1;
        true
    } else {
        false
    };

    let mut matched = false;
    while i < pattern.len() && pattern[i] != b']' {
        if i + 2 < pattern.len() && pattern[i + 1] == b'-' {
            // Range like a-z
            if ch >= pattern[i] && ch <= pattern[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if ch == pattern[i] {
                matched = true;
            }
            i += 1;
        }
    }

    if i < pattern.len() && pattern[i] == b']' {
        Some((matched ^ negate, i + 1))
    } else {
        None // No closing bracket
    }
}

impl fmt::Display for ProbeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                if *is_ret {
                    write!(f, "ret:")?;
                }
                if let Some(lib) = library {
                    write!(f, "{}:", lib)?;
                }
                write!(f, "{}", pattern.display_str())?;
                if *offset > 0 {
                    write!(f, "+0x{:x}", offset)?;
                }
            }
            ProbeSpec::SourceLocation { file, line, is_ret } => {
                if *is_ret {
                    write!(f, "ret:")?;
                }
                write!(f, "{}:{}", file, line)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_symbol() {
        let spec = parse_probe_spec("malloc").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                assert!(library.is_none());
                assert!(matches!(pattern, SymbolPattern::Exact(ref s) if s == "malloc"));
                assert_eq!(offset, 0);
                assert!(!is_ret);
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_library_prefix() {
        let spec = parse_probe_spec("libc:malloc").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library, pattern, ..
            } => {
                assert_eq!(library, Some("libc".to_string()));
                assert!(matches!(pattern, SymbolPattern::Exact(ref s) if s == "malloc"));
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_absolute_path_prefix() {
        let spec = parse_probe_spec("/usr/lib/libc.so.6:malloc").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library, pattern, ..
            } => {
                assert_eq!(library, Some("/usr/lib/libc.so.6".to_string()));
                assert!(matches!(pattern, SymbolPattern::Exact(ref s) if s == "malloc"));
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_ret_prefix() {
        let spec = parse_probe_spec("ret:malloc").unwrap();
        match spec {
            ProbeSpec::Symbol { is_ret, .. } => {
                assert!(is_ret);
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_offset_decimal() {
        let spec = parse_probe_spec("malloc+16").unwrap();
        match spec {
            ProbeSpec::Symbol { offset, .. } => {
                assert_eq!(offset, 16);
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_offset_hex() {
        let spec = parse_probe_spec("malloc+0x10").unwrap();
        match spec {
            ProbeSpec::Symbol { offset, .. } => {
                assert_eq!(offset, 0x10);
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_glob_pattern() {
        let spec = parse_probe_spec("pthread_*").unwrap();
        match spec {
            ProbeSpec::Symbol { pattern, .. } => {
                assert!(matches!(pattern, SymbolPattern::Glob(ref s) if s == "pthread_*"));
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_regex_pattern() {
        let spec = parse_probe_spec("/^sql_.*query/").unwrap();
        match spec {
            ProbeSpec::Symbol { pattern, .. } => {
                assert!(matches!(pattern, SymbolPattern::Regex(_)));
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_demangled_pattern() {
        let spec = parse_probe_spec("std::vector::push_back").unwrap();
        match spec {
            ProbeSpec::Symbol { pattern, .. } => {
                assert!(
                    matches!(pattern, SymbolPattern::Demangled(ref s) if s == "std::vector::push_back")
                );
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_source_location() {
        let spec = parse_probe_spec("main.c:42").unwrap();
        match spec {
            ProbeSpec::SourceLocation { file, line, is_ret } => {
                assert_eq!(file, "main.c");
                assert_eq!(line, 42);
                assert!(!is_ret);
            }
            _ => panic!("expected SourceLocation"),
        }
    }

    #[test]
    fn test_source_location_with_ret() {
        let spec = parse_probe_spec("ret:main.c:42").unwrap();
        match spec {
            ProbeSpec::SourceLocation { file, line, is_ret } => {
                assert_eq!(file, "main.c");
                assert_eq!(line, 42);
                assert!(is_ret);
            }
            _ => panic!("expected SourceLocation"),
        }
    }

    #[test]
    fn test_combined_library_ret_offset() {
        let spec = parse_probe_spec("ret:libc:malloc+0x10").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                assert_eq!(library, Some("libc".to_string()));
                assert!(matches!(pattern, SymbolPattern::Exact(ref s) if s == "malloc"));
                assert_eq!(offset, 0x10);
                assert!(is_ret);
            }
            _ => panic!("expected Symbol"),
        }
    }

    #[test]
    fn test_glob_matching() {
        assert!(glob_match("pthread_*", "pthread_create"));
        assert!(glob_match("pthread_*", "pthread_mutex_lock"));
        assert!(!glob_match("pthread_*", "malloc"));
        assert!(glob_match("*alloc*", "malloc"));
        assert!(glob_match("*alloc*", "calloc"));
        assert!(glob_match("*alloc*", "realloc"));
        assert!(glob_match("sql_?uery", "sql_query"));
        assert!(!glob_match("sql_?uery", "sql_xquery"));
    }

    #[test]
    fn test_demangled_matching() {
        let pattern = SymbolPattern::Demangled("MyClass::method".to_string());
        assert!(pattern.matches_demangled("namespace::MyClass::method(int, float)"));
        assert!(pattern.matches_demangled("MyClass::method()"));
        assert!(!pattern.matches_demangled("OtherClass::method()"));
    }

    #[test]
    fn test_empty_spec() {
        assert!(parse_probe_spec("").is_err());
        assert!(parse_probe_spec("  ").is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(parse_probe_spec("malloc").unwrap().to_string(), "malloc");
        assert_eq!(
            parse_probe_spec("ret:libc:malloc+0x10")
                .unwrap()
                .to_string(),
            "ret:libc:malloc+0x10"
        );
        assert_eq!(
            parse_probe_spec("main.c:42").unwrap().to_string(),
            "main.c:42"
        );
    }

    #[test]
    fn test_regex_with_library_prefix() {
        let spec = parse_probe_spec("libc:/malloc.*/").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                is_ret,
            } => {
                assert_eq!(library, Some("libc".to_string()));
                assert!(matches!(pattern, SymbolPattern::Regex(ref rw) if rw.source == "malloc.*"));
                assert_eq!(offset, 0);
                assert!(!is_ret);
            }
            _ => panic!("expected Symbol with Regex pattern"),
        }
    }

    #[test]
    fn test_regex_with_library_prefix_and_offset() {
        let spec = parse_probe_spec("libc:/^mem.*/+0x10").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                offset,
                ..
            } => {
                assert_eq!(library, Some("libc".to_string()));
                assert!(matches!(pattern, SymbolPattern::Regex(ref rw) if rw.source == "^mem.*"));
                assert_eq!(offset, 0x10);
            }
            _ => panic!("expected Symbol with Regex pattern"),
        }
    }

    #[test]
    fn test_regex_with_ret_and_library() {
        let spec = parse_probe_spec("ret:libpthread:/pthread_.*/").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library,
                pattern,
                is_ret,
                ..
            } => {
                assert_eq!(library, Some("libpthread".to_string()));
                assert!(matches!(pattern, SymbolPattern::Regex(_)));
                assert!(is_ret);
            }
            _ => panic!("expected Symbol with Regex pattern"),
        }
    }

    #[test]
    fn test_absolute_path_not_confused_with_regex() {
        // /usr/lib/libc.so.6:malloc should NOT be parsed as regex
        let spec = parse_probe_spec("/usr/lib/libc.so.6:malloc").unwrap();
        match spec {
            ProbeSpec::Symbol {
                library, pattern, ..
            } => {
                assert_eq!(library, Some("/usr/lib/libc.so.6".to_string()));
                assert!(matches!(pattern, SymbolPattern::Exact(ref s) if s == "malloc"));
            }
            _ => panic!("expected Symbol with Exact pattern"),
        }
    }
}
