//! Small self-contained utilities to avoid pulling in extra crates:
//! a standard Base64 codec and std-only UTC time formatting.

use anyhow::{bail, Result};

// ============================ Base64 (standard) ============================

const B64_TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard Base64 encode (with `=` padding).
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for c in chunks.by_ref() {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(B64_TBL[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_TBL[((n >> 12) & 0x3f) as usize] as char);
        out.push(B64_TBL[((n >> 6) & 0x3f) as usize] as char);
        out.push(B64_TBL[(n & 0x3f) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(B64_TBL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64_TBL[((n >> 12) & 0x3f) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out.push(B64_TBL[((n >> 18) & 0x3f) as usize] as char);
            out.push(B64_TBL[((n >> 12) & 0x3f) as usize] as char);
            out.push(B64_TBL[((n >> 6) & 0x3f) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Standard Base64 decode. Whitespace is ignored; length must be a multiple
/// of 4 after stripping whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !cleaned.len().is_multiple_of(4) {
        bail!("invalid base64 length");
    }
    let mut tbl = [255u8; 256];
    for (i, &c) in B64_TBL.iter().enumerate() {
        tbl[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks(4) {
        let (a, b, c, d) = (chunk[0], chunk[1], chunk[2], chunk[3]);
        let v = |x: u8| -> Result<u8> {
            let q = tbl[x as usize];
            if q == 255 {
                bail!("invalid base64 character");
            }
            Ok(q)
        };
        let av = v(a)?;
        let bv = v(b)?;
        let pad = |x: u8| x == b'=';
        let n = ((av as u32) << 18) | ((bv as u32) << 12);
        if pad(c) {
            out.push((n >> 16) as u8);
        } else {
            let cv = v(c)?;
            let n = n | ((cv as u32) << 6);
            if pad(d) {
                out.push((n >> 16) as u8);
                out.push(((n >> 8) & 0xff) as u8);
            } else {
                let dv = v(d)?;
                let n = n | (dv as u32);
                out.push((n >> 16) as u8);
                out.push(((n >> 8) & 0xff) as u8);
                out.push((n & 0xff) as u8);
            }
        }
    }
    Ok(out)
}

// ========================= UTC time formatting =========================

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (second precision, std-only).
pub fn now_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc(secs)
}

/// Current UTC time as `YYYYMMDD-HHMMSS` (for backup filenames).
pub fn now_stamp_compact() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_utc_compact(secs)
}

/// Convert a Unix epoch second count to `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_unix_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn format_unix_utc_compact(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// Civil time (UTC) from Unix seconds. Accurate for years 1970..~9999.
/// Uses Howard Hinnant's days-from-civil algorithm.
pub fn civil_from_unix(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = (y + if m <= 2 { 1 } else { 0 }) as u32;
    (y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"f",
            b"fo",
            b"foo",
            b"abcd",
            b"hello world!",
            &[0x00, 0xff, 0x10],
        ];
        for case in cases {
            let enc = base64_encode(case);
            let dec = base64_decode(&enc).unwrap();
            assert_eq!(dec.as_slice(), *case, "case: {:?}", case);
        }
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn base64_decode_rejects_bad_length() {
        assert!(base64_decode("abc").is_err()); // not multiple of 4
    }

    #[test]
    fn civil_dates() {
        // 2021-01-01T00:00:00Z == 1609459200
        let (y, m, d, h, mi, s) = civil_from_unix(1_609_459_200);
        assert_eq!((y, m, d, h, mi, s), (2021, 1, 1, 0, 0, 0));
        // 2000-03-01 is a known edge (leap handling).
        let (y, m, d, _, _, _) = civil_from_unix(951_868_800);
        assert_eq!((y, m, d), (2000, 3, 1));
    }
}
