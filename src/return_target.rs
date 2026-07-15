use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnTargetMode {
    DirectLogin,
    ProxyFallback,
}

/// Validate a browser return target through one security boundary.
///
/// Direct login accepts a same-origin absolute URL or root-relative target and
/// retains its historical normalization. Proxy fallback accepts only the raw
/// path/query already derived from Hyper's origin/absolute request target and
/// returns it byte-for-byte after the shared separator/control checks.
pub fn normalize_return_target(
    input: Option<&str>,
    public_base_url: &str,
    mode: ReturnTargetMode,
) -> Option<String> {
    let raw = match mode {
        ReturnTargetMode::DirectLogin => input
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("/"),
        ReturnTargetMode::ProxyFallback => input?,
    };
    if has_unsafe_bytes(raw) {
        return None;
    }

    match mode {
        ReturnTargetMode::ProxyFallback => {
            if !raw.starts_with('/') || raw.starts_with("//") || raw.contains('#') {
                return None;
            }
            Some(raw.to_string())
        }
        ReturnTargetMode::DirectLogin => {
            let public = Url::parse(public_base_url).ok()?;
            if raw.starts_with('/') && !raw.starts_with("//") {
                return public.join(raw).ok().map(|url| format_path(&url));
            }
            let parsed = Url::parse(raw).ok()?;
            if parsed.origin() != public.origin() {
                return None;
            }
            Some(format_path(&parsed))
        }
    }
}

fn has_unsafe_bytes(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' || byte < 0x20 || byte == 0x7f {
            return true;
        }
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return true;
            }
            let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) else {
                return true;
            };
            let Ok(decoded) = u8::from_str_radix(hex, 16) else {
                return true;
            };
            if decoded == b'\\' || decoded < 0x20 || decoded == 0x7f {
                return true;
            }
            index += 3;
            continue;
        }
        index += 1;
    }
    false
}

fn format_path(url: &Url) -> String {
    let mut out = url.path().to_string();
    if let Some(query) = url.query() {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = url.fragment() {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_and_proxy_modes_share_safety_but_preserve_their_contracts() {
        let public = "https://public.example";
        assert_eq!(
            normalize_return_target(
                Some("https://public.example/app?q=1#fragment"),
                public,
                ReturnTargetMode::DirectLogin,
            ),
            Some("/app?q=1#fragment".to_string())
        );
        assert_eq!(
            normalize_return_target(
                Some("/api?q=1&q=2&raw=%2F"),
                public,
                ReturnTargetMode::ProxyFallback,
            ),
            Some("/api?q=1&q=2&raw=%2F".to_string())
        );
        for unsafe_target in [
            "//evil.example/x",
            "/\\evil.example/x",
            "/%5cevil",
            "/%0d%0aheader",
            "/bad%",
        ] {
            assert_eq!(
                normalize_return_target(Some(unsafe_target), public, ReturnTargetMode::DirectLogin,),
                None
            );
            assert_eq!(
                normalize_return_target(
                    Some(unsafe_target),
                    public,
                    ReturnTargetMode::ProxyFallback,
                ),
                None
            );
        }
    }
}
