//! Online update check: query GitHub Releases for the latest tag and compare
//! it to the running version. All best-effort and cached (1h) so it never
//! blocks or fails the `version` command.

/// Parse a version string (optionally `v`-prefixed) into (major, minor, patch).
/// Missing components default to 0; non-numeric parts are treated as 0.
fn parse_version(s: &str) -> (u64, u64, u64) {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// True if `remote` is strictly newer than `local` (semantic, per-component).
pub fn is_newer(remote: &str, local: &str) -> bool {
    let (ra, rb, rc) = parse_version(remote);
    let (la, lb, lc) = parse_version(local);
    (ra, rb, rc) > (la, lb, lc)
}

/// Query GitHub Releases for the latest tag (e.g. "v0.3.0"). Uses the
/// releases-page redirect (NOT the rate-limited API) so it survives heavy use.
/// Returns None on any failure (no network, no curl/wget, timeout).
fn fetch_latest_release_tag() -> Option<String> {
    let page = "https://github.com/oliveagle/dotvault/releases/latest";
    // `curl -o /dev/null -w '%{url_effective}'` follows the 302 redirect and
    // prints the final URL (.../releases/tag/vX.Y.Z) without consuming the API.
    let url = (|| {
        if let Ok(o) = std::process::Command::new("curl")
            .args([
                "-fsSL",
                "-o",
                "/dev/null",
                "-w",
                "%{url_effective}",
                "--max-time",
                "5",
                page,
            ])
            .output()
        {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
        // wget fallback: follow redirect, grep the tag out of the page.
        if let Ok(o) = std::process::Command::new("wget")
            .args(["-qO-", "--timeout=5", page])
            .output()
        {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
        None
    })()?;
    // Extract vX.Y.Z from the final URL or page body.
    extract_tag(&url)
}

/// Pull the first `vX.Y.Z` (with the releases/tag prefix) out of a URL/body.
fn extract_tag(s: &str) -> Option<String> {
    let needle = "releases/tag/";
    let at = s.find(needle)?;
    let after = &s[at + needle.len()..];
    // Tag chars: v, digits, dots.
    let end = after
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != 'v')
        .unwrap_or(after.len());
    let tag = &after[..end];
    if tag.starts_with('v') && tag.len() > 1 {
        Some(tag.to_string())
    } else {
        None
    }
}

/// Cached latest-tag lookup: reuses a result for 1 hour to avoid hitting the
/// GitHub API rate limit (60 req/h unauthenticated) on every `version` call.
pub fn cached_latest_release_tag() -> Option<String> {
    let cache_path = crate::vault::dotvault_home().ok()?.join(".latest_tag");
    if let Ok(meta) = std::fs::metadata(&cache_path) {
        if let Ok(mtime) = meta.modified() {
            if mtime.elapsed().ok()?.as_secs() < 3600 {
                if let Ok(cached) = std::fs::read_to_string(&cache_path) {
                    let tag = cached.trim().to_string();
                    if !tag.is_empty() {
                        return Some(tag);
                    }
                }
            }
        }
    }
    let tag = fetch_latest_release_tag()?;
    let _ = std::fs::write(&cache_path, tag.as_bytes());
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_semantic() {
        assert!(is_newer("v0.3.0", "0.2.0"));
        assert!(is_newer("0.2.1", "0.2.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.10.0", "0.9.0")); // numeric, not lexical
        assert!(!is_newer("v0.2.0", "0.2.0"));
        assert!(!is_newer("0.1.5", "0.2.0"));
        assert!(!is_newer("0.2.0", "0.2.1"));
        assert!(is_newer("0.3.0", "v0.2.0"));
    }

    #[test]
    fn parse_handles_garbage() {
        assert_eq!(parse_version("v1.2.3"), (1, 2, 3));
        assert_eq!(parse_version("2.0"), (2, 0, 0)); // missing patch
        assert_eq!(parse_version("x.y.z"), (0, 0, 0)); // non-numeric → 0
    }

    #[test]
    fn extract_tag_from_url() {
        assert_eq!(
            extract_tag("https://github.com/oliveagle/dotvault/releases/tag/v0.3.0"),
            Some("v0.3.0".to_string())
        );
        assert_eq!(
            extract_tag("...releases/tag/v1.2.3/extra"),
            Some("v1.2.3".to_string())
        );
        assert_eq!(extract_tag("https://example.com/no-tag-here"), None);
        assert_eq!(extract_tag(""), None);
    }
}
