use std::fmt;

#[cfg(feature = "chrome")]
use serde::Serialize;

#[cfg_attr(feature = "chrome", derive(Serialize))]
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
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Brave => "Brave",
            Self::Opera => "Opera",
            Self::Vivaldi => "Vivaldi",
            Self::Firefox => "Firefox",
        };
        f.write_str(s)
    }
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Clone)]
pub enum ChromeSource {
    Memory { pid: u32, process: String },
    DiskDpapi,
    DiskAbe,
    HybridMemKey { mk_guid: String },
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct BrowserProfile {
    pub browser: Browser,
    pub user: String,
    pub profile_name: String,
    pub path: String,
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct SavedPassword {
    pub profile: BrowserProfile,
    pub url: String,
    pub username: String,
    pub password: String,
    pub source: ChromeSource,
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
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

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Clone)]
pub enum AutofillKind {
    FormField,
    CreditCard,
    Address,
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Clone)]
pub struct AutofillEntry {
    pub profile: BrowserProfile,
    pub kind: AutofillKind,
    pub fields: Vec<(String, String)>,
    pub source: ChromeSource,
}

#[cfg_attr(feature = "chrome", derive(Serialize))]
#[derive(Debug, Default, Clone)]
pub struct ChromeFindings {
    pub passwords: Vec<SavedPassword>,
    pub cookies: Vec<Cookie>,
    pub autofill: Vec<AutofillEntry>,
}

impl ChromeFindings {
    pub const fn is_empty(&self) -> bool {
        self.passwords.is_empty() && self.cookies.is_empty() && self.autofill.is_empty()
    }
}
