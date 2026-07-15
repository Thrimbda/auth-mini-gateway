use std::collections::HashSet;
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::Bytes;
use http::header::{
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::{self, SendRequest};
use hyper::upgrade::OnUpgrade;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use sha1::{Digest as _, Sha1};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tower_service::Service;

use crate::config::UpstreamBase;
use crate::http::is_safe_header_value;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type GatewayBody = UnsyncBoxBody<Bytes, BoxError>;

const POOL_CAPACITY: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ProxyIdentity {
    pub user_id: String,
    pub email: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WebSocketRequest {
    pub key: String,
    pub protocols: Vec<String>,
    pub extension_names: HashSet<String>,
}

#[derive(Debug)]
pub enum ProxyError {
    BadRequest,
    BadGateway,
    Internal,
}

type RequestBody = DropTrailers<Incoming>;
type Sender = SendRequest<RequestBody>;
type SenderPool = Arc<Mutex<Vec<Sender>>>;
type Connector = HttpsConnector<TcpConnector>;

#[derive(Clone)]
pub struct Proxy {
    upstream: UpstreamBase,
    connect_uri: Uri,
    connector: Connector,
    idle: SenderPool,
}

impl Proxy {
    pub fn new(upstream: UpstreamBase) -> Result<Self, BoxError> {
        Self::new_with_native_root_loader(upstream, || {
            let native = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(native.certs);
            if added == 0 {
                return Err("no native TLS roots available".into());
            }
            Ok(roots)
        })
    }

    fn new_with_native_root_loader<F>(
        upstream: UpstreamBase,
        load_native_roots: F,
    ) -> Result<Self, BoxError>
    where
        F: FnOnce() -> Result<RootCertStore, BoxError>,
    {
        if upstream.scheme == "http" {
            return Self::with_root_store(upstream, RootCertStore::empty());
        }
        let roots = load_native_roots()?;
        Self::with_root_store(upstream, roots)
    }

    pub fn with_root_store(upstream: UpstreamBase, roots: RootCertStore) -> Result<Self, BoxError> {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .wrap_connector(TcpConnector);
        let connect_uri = format!("{}://{}/", upstream.scheme, upstream.authority).parse()?;
        Ok(Self {
            upstream,
            connect_uri,
            connector,
            idle: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn forward(
        &self,
        mut request: Request<Incoming>,
        path_and_query: &str,
        peer: SocketAddr,
        public_proto: &str,
        identity: ProxyIdentity,
        renewal: Option<String>,
        close_downstream: bool,
        websocket: Option<WebSocketRequest>,
    ) -> Result<Response<GatewayBody>, ProxyError> {
        let downstream_upgrade = websocket.as_ref().map(|_| hyper::upgrade::on(&mut request));
        let upstream_path = compose_path(&self.upstream.path_prefix, path_and_query)?;
        *request.uri_mut() = upstream_path.parse().map_err(|_| ProxyError::Internal)?;
        *request.version_mut() = Version::HTTP_11;
        sanitize_request_headers(
            request.headers_mut(),
            peer,
            public_proto,
            &identity,
            websocket.is_some(),
        )?;

        let (parts, body) = request.into_parts();
        let upload = Arc::new(UploadState::default());
        let upstream_request =
            Request::from_parts(parts, DropTrailers::new(body, Arc::clone(&upload)));
        let (mut upstream_response, sender, upload_complete) =
            self.send_once(upstream_request, &upload).await?;

        if upstream_response.status() == StatusCode::SWITCHING_PROTOCOLS {
            let Some(metadata) = websocket.as_ref() else {
                return Err(ProxyError::BadGateway);
            };
            validate_websocket_response(&upstream_response, metadata)?;
            let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
            let response = sanitize_response_head(upstream_response, renewal.as_deref(), true)?;
            let (parts, _) = response.into_parts();
            let response = Response::from_parts(parts, empty_body());
            let downstream_upgrade = downstream_upgrade.ok_or(ProxyError::Internal)?;
            drop(sender);
            tokio::spawn(async move {
                bridge_upgrades(downstream_upgrade, upstream_upgrade).await;
            });
            return Ok(response);
        }

        let reusable = upstream_response.version() == Version::HTTP_11
            && !header_has_token(upstream_response.headers(), CONNECTION, "close")
            && upstream_response.status() != StatusCode::SWITCHING_PROTOCOLS
            && upload_complete;
        let response = sanitize_response_head(upstream_response, renewal.as_deref(), false)?;
        let (parts, body) = response.into_parts();
        let body = PooledResponseBody::new(body, sender, Arc::clone(&self.idle), reusable)
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync();
        let mut response = Response::from_parts(parts, body);
        if close_downstream || !upload_complete {
            response
                .headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }
        Ok(response)
    }

    async fn send_once(
        &self,
        request: Request<RequestBody>,
        upload: &UploadState,
    ) -> Result<(Response<Incoming>, Sender, bool), ProxyError> {
        let pooled = self.idle.lock().map_err(|_| ProxyError::Internal)?.pop();
        let mut sender = match pooled {
            Some(sender) => sender,
            None => self.connect().await?,
        };
        sender.ready().await.map_err(|_| ProxyError::BadGateway)?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| ProxyError::BadGateway)?;
        let upload_complete = upload.is_complete();
        if !upload_complete {
            upload.cancel();
        }
        Ok((response, sender, upload_complete))
    }

    async fn connect(&self) -> Result<Sender, ProxyError> {
        let mut connector = self.connector.clone();
        let io = timeout(CONNECT_TIMEOUT, connector.call(self.connect_uri.clone()))
            .await
            .map_err(|_| ProxyError::BadGateway)?
            .map_err(|_| ProxyError::BadGateway)?;
        let (sender, connection) = http1::handshake::<_, RequestBody>(io)
            .await
            .map_err(|_| ProxyError::BadGateway)?;
        tokio::spawn(async move {
            if connection.with_upgrades().await.is_err() {
                tracing::debug!(event = "upstream_connection", outcome = "closed");
            }
        });
        Ok(sender)
    }
}

pub fn full_body(bytes: impl Into<Bytes>) -> GatewayBody {
    Full::new(bytes.into())
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn empty_body() -> GatewayBody {
    Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

pub fn parse_connection_tokens(headers: &HeaderMap) -> Result<HashSet<HeaderName>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all(CONNECTION) {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                return Err(ProxyError::BadRequest);
            }
            names.insert(
                HeaderName::from_bytes(token.as_bytes()).map_err(|_| ProxyError::BadRequest)?,
            );
        }
    }
    Ok(names)
}

pub fn parse_websocket_request(
    request: &Request<Incoming>,
) -> Result<Option<WebSocketRequest>, ProxyError> {
    let upgrade_values: Vec<_> = request.headers().get_all(UPGRADE).iter().collect();
    let connection_tokens = parse_connection_tokens(request.headers())?;
    let has_upgrade_token = connection_tokens.contains(&UPGRADE);
    if !has_upgrade_token && upgrade_values.is_empty() {
        return Ok(None);
    }
    if !has_upgrade_token || upgrade_values.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    for required in [
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-version"),
    ] {
        if connection_tokens.contains(&required) {
            return Err(ProxyError::BadRequest);
        }
    }
    for optional in [
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
    ] {
        if request.headers().contains_key(&optional) && connection_tokens.contains(&optional) {
            return Err(ProxyError::BadRequest);
        }
    }
    if !upgrade_values[0]
        .to_str()
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ProxyError::BadRequest);
    }
    if request.method() != http::Method::GET
        || request.version() != Version::HTTP_11
        || !request.body().is_end_stream()
    {
        return Err(ProxyError::BadRequest);
    }
    let version = exactly_one(request.headers(), "sec-websocket-version")?;
    if version.as_bytes() != b"13" {
        return Err(ProxyError::BadRequest);
    }
    let key = exactly_one(request.headers(), "sec-websocket-key")?
        .to_str()
        .map_err(|_| ProxyError::BadRequest)?
        .trim()
        .to_string();
    let decoded = STANDARD
        .decode(key.as_bytes())
        .map_err(|_| ProxyError::BadRequest)?;
    if decoded.len() != 16 || STANDARD.encode(decoded) != key {
        return Err(ProxyError::BadRequest);
    }
    let protocols = parse_protocols(request.headers())?;
    let extension_names = parse_extensions(request.headers())?;
    Ok(Some(WebSocketRequest {
        key,
        protocols,
        extension_names,
    }))
}

fn compose_path(prefix: &str, path_and_query: &str) -> Result<String, ProxyError> {
    if !path_and_query.starts_with('/') {
        return Err(ProxyError::BadRequest);
    }
    Ok(format!("{prefix}{path_and_query}"))
}

fn sanitize_request_headers(
    headers: &mut HeaderMap,
    peer: SocketAddr,
    public_proto: &str,
    identity: &ProxyIdentity,
    websocket: bool,
) -> Result<(), ProxyError> {
    let hosts: Vec<_> = headers.get_all(HOST).iter().cloned().collect();
    if hosts.len() != 1 {
        return Err(ProxyError::BadRequest);
    }
    let external_host = hosts[0].clone();
    let nominated = parse_connection_tokens(headers)?;
    for name in nominated {
        headers.remove(name);
    }
    remove_fixed_hop_headers(headers);
    headers.remove(CONTENT_LENGTH);
    headers.remove(COOKIE);
    headers.remove(AUTHORIZATION);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove("forwarded");
    headers.remove("expect");
    remove_prefixed(headers, "x-auth-mini-");
    remove_prefixed(headers, "x-forwarded-");

    headers.insert(HOST, external_host.clone());
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&peer.ip().to_string()).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_str(public_proto).map_err(|_| ProxyError::Internal)?,
    );
    headers.insert("x-forwarded-host", external_host);
    headers.insert(
        "x-auth-mini-user-id",
        identity_header_value(&identity.user_id)?,
    );
    if let Some(email) = identity.email.as_deref() {
        headers.insert("x-auth-mini-email", identity_header_value(email)?);
    }
    if websocket {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    Ok(())
}

fn identity_header_value(value: &str) -> Result<HeaderValue, ProxyError> {
    if !is_safe_header_value(value) {
        return Err(ProxyError::Internal);
    }
    HeaderValue::from_bytes(value.as_bytes()).map_err(|_| ProxyError::Internal)
}

fn sanitize_response_head(
    response: Response<Incoming>,
    renewal: Option<&str>,
    websocket: bool,
) -> Result<Response<Incoming>, ProxyError> {
    let (mut parts, body) = response.into_parts();
    let nominated = parse_response_connection_tokens(&parts.headers)?;
    for name in nominated {
        parts.headers.remove(name);
    }
    remove_fixed_hop_headers(&mut parts.headers);
    parts.headers.remove(CONTENT_LENGTH);
    remove_prefixed(&mut parts.headers, "x-auth-mini-");
    filter_application_cookies(&mut parts.headers);
    if websocket {
        parts
            .headers
            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    if let Some(cookie) = renewal {
        parts.headers.append(
            SET_COOKIE,
            HeaderValue::from_str(cookie).map_err(|_| ProxyError::Internal)?,
        );
    }
    Ok(Response::from_parts(parts, body))
}

fn parse_response_connection_tokens(
    headers: &HeaderMap,
) -> Result<HashSet<HeaderName>, ProxyError> {
    parse_connection_tokens(headers).map_err(|_| ProxyError::BadGateway)
}

fn remove_fixed_hop_headers(headers: &mut HeaderMap) {
    for name in [
        CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn remove_prefixed(headers: &mut HeaderMap, prefix: &str) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(prefix))
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn filter_application_cookies(headers: &mut HeaderMap) {
    let values: Vec<_> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    headers.remove(SET_COOKIE);
    for value in values {
        if is_allowed_application_cookie(&value) {
            headers.append(SET_COOKIE, value);
        }
    }
}

fn is_allowed_application_cookie(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    let bytes = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|start| &bytes[start..])
        .unwrap_or_default();
    let pair = bytes.split(|byte| *byte == b';').next().unwrap_or_default();
    let Some(equal) = pair.iter().position(|byte| *byte == b'=') else {
        return false;
    };
    let name = &pair[..equal];
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return false;
    }
    name != b"amg_session" && name != b"amg_login_state"
}

fn validate_websocket_response(
    response: &Response<Incoming>,
    request: &WebSocketRequest,
) -> Result<(), ProxyError> {
    let connection = parse_response_connection_tokens(response.headers())?;
    if !connection.contains(&UPGRADE) {
        return Err(ProxyError::BadGateway);
    }
    if connection.contains(&HeaderName::from_static("sec-websocket-accept")) {
        return Err(ProxyError::BadGateway);
    }
    for selected in [
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-extensions"),
    ] {
        if response.headers().contains_key(&selected) && connection.contains(&selected) {
            return Err(ProxyError::BadGateway);
        }
    }
    let upgrades: Vec<_> = response.headers().get_all(UPGRADE).iter().collect();
    if upgrades.len() != 1
        || !upgrades[0]
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("websocket"))
    {
        return Err(ProxyError::BadGateway);
    }
    let accept = exactly_one(response.headers(), "sec-websocket-accept")
        .map_err(|_| ProxyError::BadGateway)?;
    if accept.as_bytes() != websocket_accept(&request.key).as_bytes() {
        return Err(ProxyError::BadGateway);
    }
    let selected: Vec<_> = response
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .collect();
    if selected.len() > 1 {
        return Err(ProxyError::BadGateway);
    }
    if let Some(selected) = selected.first() {
        let selected = selected.to_str().map_err(|_| ProxyError::BadGateway)?;
        if !request.protocols.iter().any(|offered| offered == selected) {
            return Err(ProxyError::BadGateway);
        }
    }
    let selected_extensions =
        parse_extensions(response.headers()).map_err(|_| ProxyError::BadGateway)?;
    if !selected_extensions.is_subset(&request.extension_names) {
        return Err(ProxyError::BadGateway);
    }
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    STANDARD.encode(digest.finalize())
}

fn parse_protocols(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut protocols = Vec::new();
    let mut seen = HashSet::new();
    for value in headers.get_all("sec-websocket-protocol") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for protocol in value.split(',') {
            let protocol = protocol.trim();
            if protocol.is_empty()
                || !protocol.bytes().all(is_token_byte)
                || !seen.insert(protocol.to_string())
            {
                return Err(ProxyError::BadRequest);
            }
            protocols.push(protocol.to_string());
        }
    }
    Ok(protocols)
}

fn parse_extensions(headers: &HeaderMap) -> Result<HashSet<String>, ProxyError> {
    let mut names = HashSet::new();
    for value in headers.get_all("sec-websocket-extensions") {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest)?;
        for extension in value.split(',') {
            let mut pieces = extension.split(';');
            let name = pieces.next().unwrap_or_default().trim();
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                return Err(ProxyError::BadRequest);
            }
            for parameter in pieces {
                let parameter = parameter.trim();
                if parameter.is_empty() {
                    return Err(ProxyError::BadRequest);
                }
                let (param_name, param_value) = parameter
                    .split_once('=')
                    .map_or((parameter, None), |(name, value)| {
                        (name.trim(), Some(value.trim()))
                    });
                if param_name.is_empty() || !param_name.bytes().all(is_token_byte) {
                    return Err(ProxyError::BadRequest);
                }
                if let Some(value) = param_value {
                    let valid = value.bytes().all(is_token_byte)
                        || (value.len() >= 2
                            && value.starts_with('"')
                            && value.ends_with('"')
                            && value[1..value.len() - 1]
                                .bytes()
                                .all(|byte| byte >= 0x20 && byte != 0x7f));
                    if !valid {
                        return Err(ProxyError::BadRequest);
                    }
                }
            }
            names.insert(name.to_ascii_lowercase());
        }
    }
    Ok(names)
}

fn exactly_one<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a HeaderValue, ProxyError> {
    let values: Vec<_> = headers.get_all(name).iter().collect();
    if values.len() == 1 {
        Ok(values[0])
    } else {
        Err(ProxyError::BadRequest)
    }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn is_token_byte(byte: u8) -> bool {
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
}

async fn bridge_upgrades(downstream: OnUpgrade, upstream: OnUpgrade) {
    let upgraded = tokio::try_join!(downstream, upstream);
    let Ok((downstream, upstream)) = upgraded else {
        tracing::info!(event = "websocket_tunnel", outcome = "upgrade_failed");
        return;
    };
    let mut downstream = TokioIo::new(downstream);
    let mut upstream = TokioIo::new(upstream);
    let outcome = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
    tracing::info!(
        event = "websocket_tunnel",
        outcome = if outcome.is_ok() {
            "closed"
        } else {
            "io_error"
        }
    );
}

#[derive(Default)]
struct UploadState {
    complete: AtomicBool,
    cancelled: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl UploadState {
    fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    fn mark_complete(&self) {
        self.complete.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            slot.take();
        }
    }

    fn cancel(&self) {
        if self.is_complete() {
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        if let Ok(mut slot) = self.waker.lock() {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn register(&self, waker: &Waker) {
        if let Ok(mut slot) = self.waker.lock() {
            if slot
                .as_ref()
                .is_none_or(|registered| !registered.will_wake(waker))
            {
                *slot = Some(waker.clone());
            }
        }
    }
}

struct DropTrailers<B> {
    inner: Option<B>,
    upload: Arc<UploadState>,
}

impl<B> DropTrailers<B> {
    fn new(inner: B, upload: Arc<UploadState>) -> Self
    where
        B: Body,
    {
        if inner.is_end_stream() {
            upload.mark_complete();
        }
        Self {
            inner: Some(inner),
            upload,
        }
    }
}

impl<B> Body for DropTrailers<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            if self.upload.is_cancelled() {
                self.inner.take();
                return Poll::Ready(None);
            }
            self.upload.register(context.waker());
            if self.upload.is_cancelled() {
                self.inner.take();
                return Poll::Ready(None);
            }
            let Some(inner) = self.inner.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(inner).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(Some(Ok(frame))) => {
                    if self.inner.as_ref().is_some_and(Body::is_end_stream) {
                        self.upload.mark_complete();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(None) => {
                    self.upload.mark_complete();
                    self.inner.take();
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.upload.is_cancelled() || self.inner.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

struct PooledResponseBody {
    inner: Incoming,
    sender: Option<Sender>,
    pool: SenderPool,
    reusable: bool,
    completed: bool,
}

impl PooledResponseBody {
    fn new(inner: Incoming, sender: Sender, pool: SenderPool, reusable: bool) -> Self {
        let mut body = Self {
            inner,
            sender: Some(sender),
            pool,
            reusable,
            completed: false,
        };
        if body.inner.is_end_stream() {
            body.complete();
        }
        body
    }

    fn complete(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        let Some(mut sender) = self.sender.take().filter(|_| self.reusable) else {
            return;
        };
        let pool = Arc::clone(&self.pool);
        tokio::spawn(async move {
            if sender.ready().await.is_ok() {
                if let Ok(mut idle) = pool.lock() {
                    if idle.len() < POOL_CAPACITY {
                        idle.push(sender);
                    }
                }
            }
        });
    }
}

impl Body for PooledResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match Pin::new(&mut self.inner).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                Poll::Ready(Some(Ok(frame))) => {
                    if self.inner.is_end_stream() {
                        self.complete();
                    }
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(None) => {
                    self.complete();
                    return Poll::Ready(None);
                }
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.inner.is_end_stream() {
            SizeHint::with_exact(0)
        } else {
            SizeHint::new()
        }
    }
}

#[derive(Clone)]
struct TcpConnector;

impl Service<Uri> for TcpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?
                .to_string();
            let port = uri.port_u16().unwrap_or_else(|| {
                if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            });
            let stream = TcpStream::connect((host.as_str(), port)).await?;
            stream.set_nodelay(true)?;
            Ok(TokioIo::new(stream))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_filter_is_exact_and_fail_closed() {
        for value in [
            "amg_session=x; Path=/",
            "amg_login_state=x",
            "amg_session =x",
            "no-equals",
        ] {
            assert!(!is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
        for value in ["amg_session2=x", "AMG_SESSION=x", "app=x; Path=/"] {
            assert!(is_allowed_application_cookie(
                &HeaderValue::from_str(value).expect("header")
            ));
        }
    }

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn http_upstream_initialization_does_not_load_native_tls_roots() {
        let upstream = UpstreamBase {
            scheme: "http".to_string(),
            authority: "127.0.0.1:4096".to_string(),
            path_prefix: String::new(),
        };
        let proxy = Proxy::new_with_native_root_loader(upstream, || {
            panic!("HTTP initialization must not load TLS roots")
        });
        assert!(proxy.is_ok());
    }

    #[test]
    fn https_upstream_initialization_requires_native_tls_roots() {
        let upstream = UpstreamBase {
            scheme: "https".to_string(),
            authority: "app.example".to_string(),
            path_prefix: String::new(),
        };
        let proxy = Proxy::new_with_native_root_loader(upstream, || {
            Err("test native roots unavailable".into())
        });
        assert!(proxy.is_err());
    }
}
