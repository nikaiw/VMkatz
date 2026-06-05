use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Opera,
    Vivaldi,
    Firefox,
}

impl fmt::Display for Browser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Browser::Chrome => "Chrome",
            Browser::Edge => "Edge",
            Browser::Brave => "Brave",
            Browser::Opera => "Opera",
            Browser::Vivaldi => "Vivaldi",
            Browser::Firefox => "Firefox",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone)]
pub enum ChromeSource {
    Memory { pid: u32, process: String },
    DiskDpapi,
    DiskAbe,
    HybridMemKey { mk_guid: String },
}

#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub browser: Browser,
    pub user: String,
    pub profile_name: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct SavedPassword {
    pub profile: BrowserProfile,
    pub url: String,
    pub username: String,
    pub password: String,
    pub source: ChromeSource,
}

#[derive(Debug, Clone)]
pub struct Cookie {
    pub profile: BrowserProfile,
    pub host: String,
    pub name: String,
    pub value: String,
    pub path: String,
    pub expires: Option<i64>,
    pub http_only: bool,
    pub secure: bool,
    pub source: ChromeSource,
}

#[derive(Debug, Clone)]
pub enum AutofillKind {
    FormField,
    CreditCard,
    Address,
}

#[derive(Debug, Clone)]
pub struct AutofillEntry {
    pub profile: BrowserProfile,
    pub kind: AutofillKind,
    pub fields: Vec<(String, String)>,
    pub source: ChromeSource,
}

#[derive(Debug, Default, Clone)]
pub struct ChromeFindings {
    pub passwords: Vec<SavedPassword>,
    pub cookies: Vec<Cookie>,
    pub autofill: Vec<AutofillEntry>,
}

impl ChromeFindings {
    pub fn is_empty(&self) -> bool {
        self.passwords.is_empty() && self.cookies.is_empty() && self.autofill.is_empty()
    }
}
