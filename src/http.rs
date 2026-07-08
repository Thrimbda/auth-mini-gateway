use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

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
    pub fn read(stream: &mut TcpStream) -> io::Result<Self> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or("/").to_string();
        let mut headers = Vec::new();
        let mut content_length = 0usize;

        for _ in 0..100 {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line == "\r\n" || line == "\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid content-length")
                    })?;
                    if content_length > 64 * 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "body too large",
                        ));
                    }
                }
                headers.push((name, value));
            }
        }

        let mut body = vec![0; content_length];
        reader.read_exact(&mut body)?;

        let (path, query) = parse_target(&target);
        Ok(Self {
            method,
            target,
            path,
            query,
            headers,
            body,
        })
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

    pub fn write_to(self, stream: &mut TcpStream) -> io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason(self.status)
        )?;
        write!(stream, "Content-Length: {}\r\n", self.body.len())?;
        write!(stream, "Content-Type: {}\r\n", self.content_type)?;
        write!(stream, "Connection: close\r\n")?;
        for (name, value) in self.headers {
            if is_safe_header_name(&name) && is_safe_header_value(&value) {
                write!(stream, "{}: {}\r\n", name, value)?;
            }
        }
        write!(stream, "\r\n")?;
        stream.write_all(&self.body)
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

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
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
