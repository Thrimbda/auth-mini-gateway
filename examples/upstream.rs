use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use auth_mini_gateway::http::{Request, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha1::{Digest, Sha1};

static HITS: AtomicUsize = AtomicUsize::new(0);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "4000".to_string());
    let listener = TcpListener::bind(format!("{host}:{port}"))?;

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        thread::spawn(move || {
            let Ok(request) = Request::read(&mut stream) else {
                return;
            };
            if request.path == "/__hits" {
                let body = HITS.load(Ordering::SeqCst).to_string();
                let _ = Response::text(200, &body).write_to(&mut stream);
                return;
            }
            HITS.fetch_add(1, Ordering::SeqCst);
            if request.path == "/ws" && is_websocket(&request) {
                let _ = websocket(&request, &mut stream);
                return;
            }
            if request.path == "/slow" {
                let delay = env::var("SLOW_RESPONSE_MILLISECONDS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(3000);
                thread::sleep(Duration::from_millis(delay));
            }
            if request.path == "/upstream-500" {
                let _ = Response::text(500, "Upstream failure").write_to(&mut stream);
                return;
            }

            let user_id = request.header("X-Auth-Mini-User-Id").unwrap_or("");
            let email = request.header("X-Auth-Mini-Email").unwrap_or("");
            let body = format!("protected upstream\nuser_id={user_id}\nemail={email}\n");
            let _ = Response::text(200, &body).write_to(&mut stream);
        });
    }

    Ok(())
}

fn is_websocket(request: &Request) -> bool {
    request
        .header("Upgrade")
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn websocket(request: &Request, stream: &mut TcpStream) -> std::io::Result<()> {
    let Some(key) = request.header("Sec-WebSocket-Key") else {
        return Response::text(400, "Missing Sec-WebSocket-Key").write_to(stream);
    };
    let accept = websocket_accept(key);
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )?;

    loop {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).is_err() {
            return Ok(());
        }
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended)?;
            len = u16::from_be_bytes(extended) as usize;
        } else if len == 127 {
            return Ok(());
        }
        if len > 64 * 1024 {
            return Ok(());
        }

        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }

        match opcode {
            0x1 => write_frame(stream, 0x1, &payload)?,
            0x8 => return write_frame(stream, 0x8, &[]),
            0x9 => write_frame(stream, 0xA, &payload)?,
            _ => {}
        }
    }
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1.finalize())
}

fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut header = vec![0x80 | opcode];
    if payload.len() < 126 {
        header.push(payload.len() as u8);
    } else {
        header.push(126);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    stream.write_all(&header)?;
    stream.write_all(payload)
}
