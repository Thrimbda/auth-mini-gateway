use std::collections::HashMap;

pub struct Request {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct Response {
    status: u16,
    content_type: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    pub fn new(
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        let (path, query) = parse_target(&target);
        Self {
            method,
            target,
            path,
            query,
            headers,
            body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl Response {
    pub fn empty(status: u16) -> Self {
        Self::new(status, "text/plain; charset=utf-8", Vec::new())
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::new(
            status,
            "text/plain; charset=utf-8",
            body.as_bytes().to_vec(),
        )
    }

    pub fn html(body: &str) -> Self {
        Self::new(200, "text/html; charset=utf-8", body.as_bytes().to_vec())
            .with_header("Cache-Control", "no-store")
            .with_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
    }

    pub fn json(status: u16, value: serde_json::Value) -> Self {
        Self::new(
            status,
            "application/json; charset=utf-8",
            value.to_string().into_bytes(),
        )
    }

    pub fn redirect(location: &str) -> Self {
        Self::empty(302)
            .with_header("Location", location)
            .with_header("Cache-Control", "no-store")
    }

    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        if is_safe_header_name(name) && is_safe_header_value(value) {
            self.headers.push((name.to_string(), value.to_string()));
        }
        self
    }

    pub fn with_cookie(self, cookie: String) -> Self {
        self.with_header("Set-Cookie", &cookie)
    }

    pub fn prepend_cookie(mut self, cookie: String) -> Self {
        if is_safe_header_value(&cookie) {
            self.headers.insert(0, ("Set-Cookie".to_string(), cookie));
        }
        self
    }

    pub(crate) fn into_parts(self) -> (u16, String, Vec<(String, String)>, Vec<u8>) {
        (self.status, self.content_type, self.headers, self.body)
    }

    #[cfg(test)]
    pub(crate) fn status(&self) -> u16 {
        self.status
    }

    #[cfg(test)]
    pub(crate) fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(key), Some(value)) = (url_decode(key), url_decode(value)) {
            params.insert(key, value);
        }
    }
    (path.to_string(), params)
}

pub fn url_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn is_safe_header_value(value: &str) -> bool {
    value.bytes().all(|byte| byte >= 0x20 && byte != 0x7f)
}

fn is_safe_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_values_reject_response_splitting_bytes() {
        assert!(is_safe_header_value("allowed@example.com"));
        assert!(!is_safe_header_value(
            "allowed@example.com\r\nX-Injected: yes"
        ));
        assert!(!is_safe_header_value("bad\u{7f}"));
    }
}
