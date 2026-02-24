//! Shared URL validation utilities for SSRF protection.
//!
//! This module consolidates URL validation logic used across multiple tools:
//! - `web_fetch`: HTTP/HTTPS GET requests with HTML-to-text conversion
//! - `http_request`: Generic HTTP client for API interactions
//! - `browser_open`: HTTPS-only URL opening in Brave Browser
//!
//! All tools enforce the same security constraints:
//! - Allowlist-only domains (with wildcard `*` and `*.domain.com` patterns)
//! - Block private/local hosts (localhost, RFC 1918, link-local, etc.)
//! - No userinfo in URLs
//! - No IPv6 literal hosts

/// Normalizes and deduplicates a list of allowed/blocked domains.
///
/// Each domain is normalized via [`normalize_domain`] before comparison.
/// The result is sorted and deduplicated.
pub fn normalize_allowed_domains(domains: Vec<String>) -> Vec<String> {
    let mut normalized = domains
        .into_iter()
        .filter_map(|d| normalize_domain(&d))
        .collect::<Vec<_>>();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

/// Normalizes a single domain string.
///
/// - Trims whitespace and converts to lowercase
/// - Strips `http://` or `https://` prefixes
/// - Strips path components (e.g., `/path` -> removed)
/// - Strips port numbers
/// - Strips leading/trailing dots
///
/// Returns `None` if the result is empty or contains whitespace.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let mut d = raw.trim().to_lowercase();
    if d.is_empty() {
        return None;
    }

    if let Some(stripped) = d.strip_prefix("https://") {
        d = stripped.to_string();
    } else if let Some(stripped) = d.strip_prefix("http://") {
        d = stripped.to_string();
    }

    if let Some((host, _)) = d.split_once('/') {
        d = host.to_string();
    }

    d = d.trim_start_matches('.').trim_end_matches('.').to_string();

    if let Some((host, _)) = d.split_once(':') {
        d = host.to_string();
    }

    if d.is_empty() || d.chars().any(char::is_whitespace) {
        return None;
    }

    Some(d)
}

/// URL scheme constraint for validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeConstraint {
    /// Only HTTPS URLs are allowed (e.g., browser_open)
    HttpsOnly,
    /// Both HTTP and HTTPS URLs are allowed (e.g., web_fetch, http_request)
    HttpOrHttps,
}

/// Validates a URL and extracts its host component.
///
/// # Arguments
/// * `raw_url` - The URL to validate
/// * `scheme_constraint` - Whether to require HTTPS only or allow both HTTP/HTTPS
///
/// # Errors
/// Returns an error if:
/// - URL is empty or contains whitespace
/// - URL scheme doesn't match the constraint
/// - URL contains userinfo (e.g., `user@host`)
/// - URL uses IPv6 literal notation (e.g., `[::1]`)
/// - URL doesn't have a valid host
pub fn extract_host(raw_url: &str, scheme_constraint: SchemeConstraint) -> anyhow::Result<String> {
    let url = raw_url.trim();

    if url.is_empty() {
        anyhow::bail!("URL cannot be empty");
    }

    if url.chars().any(char::is_whitespace) {
        anyhow::bail!("URL cannot contain whitespace");
    }

    let rest = match scheme_constraint {
        SchemeConstraint::HttpsOnly => url
            .strip_prefix("https://")
            .ok_or_else(|| anyhow::anyhow!("Only https:// URLs are allowed"))?,
        SchemeConstraint::HttpOrHttps => url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .ok_or_else(|| anyhow::anyhow!("Only http:// and https:// URLs are allowed"))?,
    };

    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid URL"))?;

    if authority.is_empty() {
        anyhow::bail!("URL must include a host");
    }

    if authority.contains('@') {
        anyhow::bail!("URL userinfo is not allowed");
    }

    if authority.starts_with('[') {
        anyhow::bail!("IPv6 hosts are not supported");
    }

    let host = authority
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('.')
        .to_lowercase();

    if host.is_empty() {
        anyhow::bail!("URL must include a valid host");
    }

    Ok(host)
}

/// Checks if a host matches any pattern in the allowlist.
///
/// Supports three pattern types:
/// - `*` - matches all hosts (but still subject to SSRF protection)
/// - `*.example.com` - matches the domain and all subdomains
/// - `example.com` - matches the exact domain and its subdomains
pub fn host_matches_allowlist(host: &str, allowed_domains: &[String]) -> bool {
    allowed_domains.iter().any(|pattern| {
        if pattern == "*" {
            return true;
        }
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".example.com"
            host.ends_with(suffix) || host == &pattern[2..]
        } else {
            host == pattern || host.ends_with(&format!(".{pattern}"))
        }
    })
}

/// Checks if a host is a private or local address that should be blocked for SSRF protection.
///
/// Blocks:
/// - `localhost` and `*.localhost`
/// - `*.local` TLD
/// - IPv4 loopback (127.0.0.0/8)
/// - IPv4 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - IPv4 link-local (169.254.0.0/16)
/// - IPv4 unspecified (0.0.0.0)
/// - IPv4 broadcast (255.255.255.255)
/// - IPv4 multicast (224.0.0.0/4)
/// - IPv4 shared address space (100.64.0.0/10, RFC 6598)
/// - IPv4 reserved (240.0.0.0/4)
/// - IPv4 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
/// - IPv4 benchmarking (198.18.0.0/15)
/// - IPv4 IETF assignments (192.0.0.0/24)
/// - IPv6 loopback (::1)
/// - IPv6 unspecified (::)
/// - IPv6 multicast (ff00::/8)
/// - IPv6 unique-local (fc00::/7)
/// - IPv6 link-local (fe80::/10)
/// - IPv6 documentation (2001:db8::/32)
/// - IPv4-mapped IPv6 addresses with private IPv4
pub fn is_private_or_local_host(host: &str) -> bool {
    // Strip brackets from IPv6 addresses like [::1]
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    // Normalize to lowercase for string comparisons
    let bare_lower = bare.to_lowercase();

    let has_local_tld = bare_lower
        .rsplit('.')
        .next()
        .is_some_and(|label| label == "local");

    if bare_lower == "localhost" || bare_lower.ends_with(".localhost") || has_local_tld {
        return true;
    }

    // Use original bare for IP parsing (case doesn't matter for IP addresses)
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => is_non_global_v4(v4),
            std::net::IpAddr::V6(v6) => is_non_global_v6(v6),
        };
    }

    false
}

/// Returns true if the IPv4 address is not globally routable.
pub fn is_non_global_v4(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    v4.is_loopback() // 127.0.0.0/8
        || v4.is_private() // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254.0.0/16
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
        || v4.is_multicast() // 224.0.0.0/4
        || (a == 100 && (64..=127).contains(&b)) // Shared address space (RFC 6598)
        || a >= 240 // Reserved (240.0.0.0/4, except broadcast)
        || (a == 192 && b == 0 && (c == 0 || c == 2)) // IETF assignments + TEST-NET-1
        || (a == 198 && b == 51) // Documentation (198.51.100.0/24)
        || (a == 203 && b == 0) // Documentation (203.0.113.0/24)
        || (a == 198 && (18..=19).contains(&b)) // Benchmarking (198.18.0.0/15)
}

/// Returns true if the IPv6 address is not globally routable.
pub fn is_non_global_v6(v6: std::net::Ipv6Addr) -> bool {
    let segs = v6.segments();
    v6.is_loopback() // ::1
        || v6.is_unspecified() // ::
        || v6.is_multicast() // ff00::/8
        || (segs[0] & 0xfe00) == 0xfc00 // Unique-local (fc00::/7)
        || (segs[0] & 0xffc0) == 0xfe80 // Link-local (fe80::/10)
        || (segs[0] == 0x2001 && segs[1] == 0x0db8) // Documentation (2001:db8::/32)
        || v6.to_ipv4_mapped().is_some_and(is_non_global_v4)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Domain normalization ─────────────────────────────────────

    #[test]
    fn normalize_domain_strips_scheme_path_and_case() {
        let got = normalize_domain("  HTTPS://Docs.Example.com/path ").unwrap();
        assert_eq!(got, "docs.example.com");
    }

    #[test]
    fn normalize_allowed_domains_deduplicates() {
        let got = normalize_allowed_domains(vec![
            "example.com".into(),
            "EXAMPLE.COM".into(),
            "https://example.com/".into(),
        ]);
        assert_eq!(got, vec!["example.com".to_string()]);
    }

    #[test]
    fn normalize_domain_strips_port() {
        let got = normalize_domain("example.com:8080").unwrap();
        assert_eq!(got, "example.com");
    }

    #[test]
    fn normalize_domain_strips_dots() {
        let got = normalize_domain(".example.com.").unwrap();
        assert_eq!(got, "example.com");
    }

    #[test]
    fn normalize_domain_rejects_empty() {
        assert!(normalize_domain("").is_none());
        assert!(normalize_domain("   ").is_none());
    }

    #[test]
    fn normalize_domain_rejects_whitespace() {
        assert!(normalize_domain("example .com").is_none());
    }

    // ── Host extraction ──────────────────────────────────────────

    #[test]
    fn extract_host_https_only() {
        let host = extract_host("https://example.com/path", SchemeConstraint::HttpsOnly).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_http_or_https() {
        let host_http =
            extract_host("http://example.com/path", SchemeConstraint::HttpOrHttps).unwrap();
        let host_https =
            extract_host("https://example.com/path", SchemeConstraint::HttpOrHttps).unwrap();
        assert_eq!(host_http, "example.com");
        assert_eq!(host_https, "example.com");
    }

    #[test]
    fn extract_host_rejects_http_when_https_only() {
        let err = extract_host("http://example.com", SchemeConstraint::HttpsOnly)
            .unwrap_err()
            .to_string();
        assert!(err.contains("https://"));
    }

    #[test]
    fn extract_host_rejects_empty_url() {
        let err = extract_host("", SchemeConstraint::HttpOrHttps)
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"));
    }

    #[test]
    fn extract_host_rejects_whitespace_url() {
        let err = extract_host(
            "https://example.com/hello world",
            SchemeConstraint::HttpsOnly,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("whitespace"));
    }

    #[test]
    fn extract_host_rejects_userinfo() {
        let err = extract_host("https://user@example.com", SchemeConstraint::HttpsOnly)
            .unwrap_err()
            .to_string();
        assert!(err.contains("userinfo"));
    }

    #[test]
    fn extract_host_rejects_ipv6() {
        let err = extract_host("https://[::1]:8080/path", SchemeConstraint::HttpsOnly)
            .unwrap_err()
            .to_string();
        assert!(err.contains("IPv6"));
    }

    #[test]
    fn extract_host_strips_port() {
        let host = extract_host("https://example.com:8080", SchemeConstraint::HttpsOnly).unwrap();
        assert_eq!(host, "example.com");
    }

    #[test]
    fn extract_host_lowercases() {
        let host = extract_host("https://EXAMPLE.COM", SchemeConstraint::HttpsOnly).unwrap();
        assert_eq!(host, "example.com");
    }

    // ── Allowlist matching ───────────────────────────────────────

    #[test]
    fn allowlist_matches_wildcard() {
        assert!(host_matches_allowlist("any.host", &["*".into()]));
    }

    #[test]
    fn allowlist_matches_exact_domain() {
        assert!(host_matches_allowlist(
            "example.com",
            &["example.com".into()]
        ));
        assert!(!host_matches_allowlist(
            "other.com",
            &["example.com".into()]
        ));
    }

    #[test]
    fn allowlist_matches_subdomain() {
        assert!(host_matches_allowlist(
            "api.example.com",
            &["example.com".into()]
        ));
        assert!(host_matches_allowlist(
            "deep.api.example.com",
            &["example.com".into()]
        ));
    }

    #[test]
    fn allowlist_matches_wildcard_pattern() {
        assert!(host_matches_allowlist(
            "example.com",
            &["*.example.com".into()]
        ));
        assert!(host_matches_allowlist(
            "api.example.com",
            &["*.example.com".into()]
        ));
        assert!(!host_matches_allowlist(
            "other.com",
            &["*.example.com".into()]
        ));
    }

    // ── SSRF protection ──────────────────────────────────────────

    #[test]
    fn ssrf_blocks_localhost() {
        assert!(is_private_or_local_host("localhost"));
        assert!(is_private_or_local_host("LOCALHOST"));
    }

    #[test]
    fn ssrf_blocks_localhost_subdomain() {
        assert!(is_private_or_local_host("evil.localhost"));
        assert!(is_private_or_local_host("a.b.localhost"));
    }

    #[test]
    fn ssrf_blocks_local_tld() {
        assert!(is_private_or_local_host("service.local"));
        assert!(is_private_or_local_host("host.local"));
    }

    #[test]
    fn ssrf_blocks_loopback_ipv4() {
        assert!(is_private_or_local_host("127.0.0.1"));
        assert!(is_private_or_local_host("127.0.0.2"));
        assert!(is_private_or_local_host("127.255.255.255"));
    }

    #[test]
    fn ssrf_blocks_rfc1918() {
        assert!(is_private_or_local_host("10.0.0.1"));
        assert!(is_private_or_local_host("172.16.0.1"));
        assert!(is_private_or_local_host("192.168.1.1"));
    }

    #[test]
    fn ssrf_blocks_link_local() {
        assert!(is_private_or_local_host("169.254.0.1"));
        assert!(is_private_or_local_host("169.254.255.255"));
    }

    #[test]
    fn ssrf_blocks_unspecified() {
        assert!(is_private_or_local_host("0.0.0.0"));
    }

    #[test]
    fn ssrf_blocks_broadcast() {
        assert!(is_private_or_local_host("255.255.255.255"));
    }

    #[test]
    fn ssrf_blocks_multicast_ipv4() {
        assert!(is_private_or_local_host("224.0.0.1"));
        assert!(is_private_or_local_host("239.255.255.255"));
    }

    #[test]
    fn ssrf_blocks_shared_address_space() {
        assert!(is_private_or_local_host("100.64.0.1"));
        assert!(is_private_or_local_host("100.127.255.255"));
    }

    #[test]
    fn ssrf_blocks_reserved_ipv4() {
        assert!(is_private_or_local_host("240.0.0.1"));
        assert!(is_private_or_local_host("250.1.2.3"));
    }

    #[test]
    fn ssrf_blocks_documentation_ranges() {
        assert!(is_private_or_local_host("192.0.2.1")); // TEST-NET-1
        assert!(is_private_or_local_host("198.51.100.1")); // TEST-NET-2
        assert!(is_private_or_local_host("203.0.113.1")); // TEST-NET-3
    }

    #[test]
    fn ssrf_blocks_benchmarking_range() {
        assert!(is_private_or_local_host("198.18.0.1"));
        assert!(is_private_or_local_host("198.19.255.255"));
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(is_private_or_local_host("::1"));
        assert!(is_private_or_local_host("[::1]"));
    }

    #[test]
    fn ssrf_blocks_ipv6_unspecified() {
        assert!(is_private_or_local_host("::"));
    }

    #[test]
    fn ssrf_blocks_ipv6_multicast() {
        assert!(is_private_or_local_host("ff02::1"));
    }

    #[test]
    fn ssrf_blocks_ipv6_link_local() {
        assert!(is_private_or_local_host("fe80::1"));
    }

    #[test]
    fn ssrf_blocks_ipv6_unique_local() {
        assert!(is_private_or_local_host("fd00::1"));
    }

    #[test]
    fn ssrf_blocks_ipv6_documentation() {
        assert!(is_private_or_local_host("2001:db8::1"));
    }

    #[test]
    fn ssrf_blocks_ipv4_mapped_ipv6() {
        assert!(is_private_or_local_host("::ffff:127.0.0.1"));
        assert!(is_private_or_local_host("::ffff:192.168.1.1"));
        assert!(is_private_or_local_host("::ffff:10.0.0.1"));
    }

    #[test]
    fn ssrf_allows_public_ipv4() {
        assert!(!is_private_or_local_host("8.8.8.8"));
        assert!(!is_private_or_local_host("1.1.1.1"));
        assert!(!is_private_or_local_host("93.184.216.34"));
    }

    #[test]
    fn ssrf_allows_public_ipv6() {
        assert!(!is_private_or_local_host("2607:f8b0:4004:800::200e"));
    }

    #[test]
    fn ssrf_allows_public_hostname() {
        assert!(!is_private_or_local_host("example.com"));
        assert!(!is_private_or_local_host("www.google.com"));
    }

    // Defense-in-depth: alternate IP notations should not bypass protection
    // Rust's IpAddr::parse() rejects these, so they fall through as hostnames.

    #[test]
    fn ssrf_octal_loopback_not_parsed_as_ip() {
        // 0177.0.0.1 is octal for 127.0.0.1 in some languages
        assert!(!is_private_or_local_host("0177.0.0.1"));
    }

    #[test]
    fn ssrf_hex_loopback_not_parsed_as_ip() {
        // 0x7f000001 is hex for 127.0.0.1 in some languages
        assert!(!is_private_or_local_host("0x7f000001"));
    }

    #[test]
    fn ssrf_decimal_loopback_not_parsed_as_ip() {
        // 2130706433 is decimal for 127.0.0.1 in some languages
        assert!(!is_private_or_local_host("2130706433"));
    }

    #[test]
    fn ssrf_zero_padded_loopback_not_parsed_as_ip() {
        // 127.000.000.001 uses zero-padded octets
        assert!(!is_private_or_local_host("127.000.000.001"));
    }
}
