use crate::chrome::types::{ChromeFindings, ChromeSource};

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Pretty,
    Json,
}

pub fn render(findings: &ChromeFindings, fmt: Format) -> String {
    match fmt {
        Format::Pretty => render_pretty(findings),
        Format::Json => serde_json::to_string_pretty(findings).unwrap_or_else(|_| "{}".into()),
    }
}

fn render_pretty(f: &ChromeFindings) -> String {
    use std::collections::BTreeMap;
    type Key = (String, String, String); // (user, profile_name, browser)
    type Lists<'a> = (
        Vec<&'a crate::chrome::types::SavedPassword>,
        Vec<&'a crate::chrome::types::Cookie>,
        Vec<&'a crate::chrome::types::AutofillEntry>,
    );
    let mut groups: BTreeMap<Key, Lists> = BTreeMap::new();
    for p in &f.passwords {
        groups
            .entry((
                p.profile.user.clone(),
                p.profile.profile_name.clone(),
                format!("{}", p.profile.browser),
            ))
            .or_default()
            .0
            .push(p);
    }
    for c in &f.cookies {
        groups
            .entry((
                c.profile.user.clone(),
                c.profile.profile_name.clone(),
                format!("{}", c.profile.browser),
            ))
            .or_default()
            .1
            .push(c);
    }
    for a in &f.autofill {
        groups
            .entry((
                a.profile.user.clone(),
                a.profile.profile_name.clone(),
                format!("{}", a.profile.browser),
            ))
            .or_default()
            .2
            .push(a);
    }
    let mut out = String::new();
    for ((user, prof, browser), (pws, mut cks, afs)) in groups {
        out.push_str(&format!("[Chrome] {}/{} ({})\n", user, prof, browser));
        for p in pws {
            out.push_str(&format!(
                "  password  {}  {}  {}  [{}]\n",
                p.url,
                p.username,
                p.password,
                src_tag(&p.source)
            ));
        }
        cks.sort_by(|a, b| a.host.cmp(&b.host));
        for c in cks {
            out.push_str(&format!(
                "  cookie    {}  {}  {}  [{}]\n",
                c.host,
                c.name,
                truncate(&c.value, 32),
                src_tag(&c.source)
            ));
        }
        for a in afs {
            let kind = match a.kind {
                crate::chrome::types::AutofillKind::FormField => "form",
                crate::chrome::types::AutofillKind::CreditCard => "card",
                crate::chrome::types::AutofillKind::Address => "addr",
            };
            let fields: Vec<String> = a
                .fields
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            out.push_str(&format!(
                "  autofill  {}  {}  [{}]\n",
                kind,
                fields.join(" "),
                src_tag(&a.source)
            ));
        }
    }
    out
}

fn src_tag(s: &ChromeSource) -> String {
    match s {
        ChromeSource::Memory { pid, process } => format!("Memory pid={} {}", pid, process),
        ChromeSource::DiskDpapi => "DiskDpapi".into(),
        ChromeSource::DiskAbe => "DiskAbe".into(),
        ChromeSource::HybridMemKey { mk_guid } => format!("HybridMemKey {}", mk_guid),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chrome::types::*;

    fn sample() -> ChromeFindings {
        let profile = BrowserProfile {
            browser: Browser::Chrome,
            user: "alice".into(),
            profile_name: "Default".into(),
            path: "x".into(),
        };
        let mut f = ChromeFindings::default();
        f.passwords.push(SavedPassword {
            profile: profile.clone(),
            url: "https://t.example/".into(),
            username: "alice".into(),
            password: "p".into(),
            source: ChromeSource::DiskDpapi,
        });
        f.cookies.push(Cookie {
            profile: profile.clone(),
            host: ".t.example".into(),
            name: "SESSION".into(),
            value: "AbCdEf".into(),
            path: "/".into(),
            expires: None,
            http_only: false,
            secure: false,
            source: ChromeSource::DiskAbe,
        });
        f
    }

    #[test]
    fn renders_pretty() {
        let s = render(&sample(), Format::Pretty);
        assert!(s.contains("[Chrome] alice/Default (Chrome)"));
        assert!(s.contains("https://t.example/"));
        assert!(s.contains("DiskDpapi"));
        assert!(s.contains("DiskAbe"));
    }

    #[test]
    fn renders_json() {
        let s = render(&sample(), Format::Json);
        assert!(s.contains("\"passwords\""));
        assert!(s.contains("\"DiskDpapi\""));
        // Loose check that the cookies block is structured JSON, not the pretty format
        assert!(s.contains("\"SESSION\""));
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 32), "hello");
    }

    #[test]
    fn truncate_appends_ellipsis() {
        let long = "a".repeat(40);
        let t = truncate(&long, 32);
        assert!(t.ends_with('…'));
        assert_eq!(t.chars().count(), 33);
    }
}
