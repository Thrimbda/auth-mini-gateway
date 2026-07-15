use std::convert::Infallible;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use auth_mini_gateway::proxy::{empty_body, full_body, GatewayBody};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use http::header::{CONNECTION, CONTENT_TYPE, UPGRADE};
use http::{HeaderValue, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

static HITS: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "4000".to_string());
    let listener = TcpListener::bind(format!("{host}:{port}")).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let connection = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service_fn(handle))
                .with_upgrades();
            let _ = connection.await;
        });
    }
}

async fn handle(mut request: Request<Incoming>) -> Result<Response<GatewayBody>, Infallible> {
    if request.uri().path() == "/__hits" {
        return Ok(text_response(200, HITS.load(Ordering::SeqCst).to_string()));
    }
    HITS.fetch_add(1, Ordering::SeqCst);
    if request.uri().path() == "/ws" && is_websocket(&request) {
        let Some(key) = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
        else {
            return Ok(text_response(400, "Missing Sec-WebSocket-Key"));
        };
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade.await {
                let _ = websocket_echo(TokioIo::new(upgraded)).await;
            }
        });
        let mut response = Response::new(empty_body());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        response
            .headers_mut()
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        response.headers_mut().insert(
            "sec-websocket-accept",
            HeaderValue::from_str(&websocket_accept(&key)).expect("valid accept"),
        );
        return Ok(response);
    }
    if request.uri().path() == "/slow" {
        let delay = env::var("SLOW_RESPONSE_MILLISECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(3000);
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
    if request.uri().path() == "/upstream-500" {
        return Ok(text_response(500, "Upstream failure"));
    }

    let user_id = request
        .headers()
        .get("x-auth-mini-user-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let email = request
        .headers()
        .get("x-auth-mini-email")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    Ok(text_response(
        200,
        format!("protected upstream\nuser_id={user_id}\nemail={email}\n"),
    ))
}

fn text_response(status: u16, body: impl Into<String>) -> Response<GatewayBody> {
    let mut response = Response::new(full_body(body.into()));
    *response.status_mut() = StatusCode::from_u16(status).expect("fixed status");
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn is_websocket(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
}

fn websocket_accept(key: &str) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(sha1.finalize())
}

async fn websocket_echo(stream: TokioIo<hyper::upgrade::Upgraded>) -> std::io::Result<()> {
    let mut stream = stream;
    loop {
        let mut header = [0u8; 2];
        if stream.read_exact(&mut header).await.is_err() {
            return Ok(());
        }
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await?;
            len = u16::from_be_bytes(extended) as usize;
        } else if len == 127 || len > 64 * 1024 {
            return Ok(());
        }
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;
        if masked {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        match opcode {
            0x1 => write_frame(&mut stream, 0x1, &payload).await?,
            0x8 => return write_frame(&mut stream, 0x8, &[]).await,
            0x9 => write_frame(&mut stream, 0xA, &payload).await?,
            _ => {}
        }
    }
}

async fn write_frame(
    stream: &mut TokioIo<hyper::upgrade::Upgraded>,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut header = vec![0x80 | opcode];
    if payload.len() < 126 {
        header.push(payload.len() as u8);
    } else {
        header.push(126);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    stream.write_all(&header).await?;
    stream.write_all(payload).await
}
