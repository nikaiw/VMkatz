use crate::chrome::util::b64_decode;
use crate::error::{Result, VmkatzError as Error};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct OsCrypt {
    encrypted_key: Option<String>,
    app_bound_encrypted_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LocalStateRaw {
    os_crypt: Option<OsCrypt>,
}

#[derive(Debug, Default, Clone)]
pub struct LocalState {
    /// Raw bytes after Base64 decode. Still wrapped: "DPAPI" prefix for v10/v11 key.
    pub encrypted_key: Option<Vec<u8>>,
    /// Raw bytes after Base64 decode. "APPB" prefix for app-bound (v20) key.
    pub app_bound_encrypted_key: Option<Vec<u8>>,
}

pub fn parse(json: &str) -> Result<LocalState> {
    let raw: LocalStateRaw =
        serde_json::from_str(json).map_err(|e| Error::Parse(format!("LocalState json: {}", e)))?;
    let mut out = LocalState::default();
    if let Some(oc) = raw.os_crypt {
        if let Some(s) = oc.encrypted_key {
            out.encrypted_key = b64_decode(&s);
        }
        if let Some(s) = oc.app_bound_encrypted_key {
            out.app_bound_encrypted_key = b64_decode(&s);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v10_key() {
        let key_bytes: Vec<u8> = b"DPAPIabc".to_vec();
        let enc = simple_b64(&key_bytes);
        let json = format!(r#"{{"os_crypt":{{"encrypted_key":"{}"}}}}"#, enc);
        let parsed = parse(&json).unwrap();
        assert_eq!(parsed.encrypted_key.as_deref(), Some(&key_bytes[..]));
    }

    #[test]
    fn parse_missing_os_crypt() {
        let parsed = parse(r#"{"unrelated":1}"#).unwrap();
        assert!(parsed.encrypted_key.is_none());
        assert!(parsed.app_bound_encrypted_key.is_none());
    }

    fn simple_b64(bytes: &[u8]) -> String {
        const TBL: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i + 3 <= bytes.len() {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
            out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 6) & 0x3F) as usize] as char);
            out.push(TBL[(n & 0x3F) as usize] as char);
            i += 3;
        }
        let rem = bytes.len() - i;
        if rem == 1 {
            let n = (bytes[i] as u32) << 16;
            out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
            out.push_str("==");
        } else if rem == 2 {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        out
    }
}
