//! S3 only: bounded HTTP/2 forwarding, JWT admission and a Cedar per-user gate.
use anyhow::{Context, Result, ensure};
use authz_core::{Check, Resource, Verdict};
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream, server::SendResponse};
use http::{Request, Response, Uri};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use serde::Deserialize;
use std::{future::poll_fn, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const LIMIT: usize = 4 * 1024 * 1024;
const WINDOW: u32 = 65_535;
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const SERVICE: &str = "/spark.connect.SparkConnectService/";

#[derive(Clone)]
struct Gateway {
    tls: TlsConnector,
    jwks: Uri,
    decide: Uri,
    issuer: String,
    audiences: Vec<String>,
    key: String,
    lifecycle: Option<crate::lifecycle::Manager>,
}
#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
    #[serde(skip)]
    bearer: String,
    #[serde(default)]
    groups: Vec<String>,
}

fn https(value: &str) -> Result<Uri> {
    let uri: Uri = value.parse()?;
    ensure!(
        uri.scheme_str() == Some("https") && uri.host().is_some(),
        "HTTPS endpoint required"
    );
    ensure!(
        uri.authority().is_some_and(|a| !a.as_str().contains('@')),
        "userinfo refused"
    );
    Ok(uri)
}

impl Gateway {
    // Tiny HTTP/2 HTTPS client shared by JWKS and the existing Cedar API. No
    // redirects, ambient proxies, cookie jar or unverified credential transport.
    async fn call(&self, uri: &Uri, body: Option<Vec<u8>>) -> Result<Bytes> {
        let operation = async {
            let host = uri.host().context("missing host")?;
            let tcp = TcpStream::connect((host, uri.port_u16().unwrap_or(443))).await?;
            let io = self
                .tls
                .connect(ServerName::try_from(host.to_owned())?, tcp)
                .await?;
            let (mut client, connection) = h2::client::handshake(io).await?;
            let _driver = Driver(tokio::spawn(async move {
                let _ = connection.await;
            }));
            async {
                let mut request = Request::builder().uri(uri.clone());
                if body.is_some() {
                    request = request
                        .method("POST")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", self.key));
                }
                let (response, mut tx) = client.send_request(request.body(())?, body.is_none())?;
                if let Some(body) = body {
                    send(&mut tx, Bytes::from(body), true).await?;
                }
                let response = response.await?;
                ensure!(response.status() == 200, "upstream decision/JWKS status");
                collect(response.into_body(), LIMIT).await
            }
            .await
        };
        tokio::time::timeout(Duration::from_secs(5), operation).await?
    }

    async fn authenticate(&self, request: &Request<RecvStream>) -> std::result::Result<Claims, u8> {
        let token = request
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(16u8)?;
        let header = decode_header(token).map_err(|_| 16u8)?;
        if header.alg != Algorithm::RS256 {
            return Err(16);
        }
        let kid = header.kid.ok_or(16u8)?;
        // Fetch on each RPC in this spike: no stale-key cache or unknown-kid fallback.
        let jwks: JwkSet =
            serde_json::from_slice(&self.call(&self.jwks, None).await.map_err(|_| 14u8)?)
                .map_err(|_| 14u8)?;
        let jwk = jwks.find(&kid).ok_or(16u8)?;
        let key = DecodingKey::from_jwk(jwk).map_err(|_| 16u8)?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&self.audiences);
        validation.set_required_spec_claims(&["sub", "iss", "aud", "exp"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        let mut claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| 16u8)?
            .claims;
        if claims.sub.is_empty() {
            return Err(16);
        }
        claims.bearer = token.to_owned();
        Ok(claims)
    }

    async fn admitted(&self, claims: &Claims) -> std::result::Result<(), u8> {
        let check = Check {
            principal: format!("oidc~{}", claims.sub),
            groups: claims.groups.clone(),
            action: "execute_plan".into(),
            resource: Resource::new("Server", "sail"),
        };
        let bytes = self
            .call(
                &self.decide,
                Some(serde_json::to_vec(&vec![check]).map_err(|_| 14u8)?),
            )
            .await
            .map_err(|_| 14u8)?;
        let verdicts: Vec<Verdict> = serde_json::from_slice(&bytes).map_err(|_| 14u8)?;
        if verdicts.len() != 1 {
            return Err(14);
        }
        if !verdicts[0].allowed {
            return Err(7);
        }
        Ok(())
    }
}

async fn collect(mut stream: RecvStream, limit: usize) -> Result<Bytes> {
    let mut bytes = BytesMut::new();
    while let Some(data) = stream.data().await {
        let data = data?;
        ensure!(bytes.len() + data.len() <= limit, "message size limit");
        bytes.extend_from_slice(&data);
        stream.flow_control().release_capacity(data.len())?;
    }
    Ok(bytes.freeze())
}

async fn send(stream: &mut SendStream<Bytes>, mut data: Bytes, end: bool) -> Result<()> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("closed stream")??;
        let size = capacity.min(data.len());
        if size == 0 {
            continue;
        }
        let chunk = data.split_to(size);
        stream.send_data(chunk, end && data.is_empty())?;
    }
    Ok(())
}

fn refuse(mut respond: SendResponse<Bytes>, code: u8) -> Result<()> {
    respond.send_response(
        Response::builder()
            .header("content-type", "application/grpc")
            .header("grpc-status", code.to_string())
            .body(())?,
        true,
    )?;
    println!("{{\"event\":\"gateway_refused\",\"grpc_status\":{code}}}");
    Ok(())
}

// Decode only the protobuf envelope, preserving every plan byte. All supported
// unary methods have UserContext at field 2. Replace it, including duplicate
// occurrences and unknown extensions, with the verified JWT subject. Sail keys
// sessions by session_id alone, so this does not establish session ownership.
fn varint(input: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut result = 0;
    for shift in (0..70).step_by(7) {
        let b = *input.get(*cursor).context("truncated varint")?;
        *cursor += 1;
        ensure!(shift != 63 || b <= 1, "varint overflow");
        result |= u64::from(b & 127) << shift;
        if b < 128 {
            return Ok(result);
        }
    }
    anyhow::bail!("varint overflow")
}
fn put_varint(mut value: usize, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
fn identity_frame(frame: &[u8], subject: &str) -> Result<Bytes> {
    ensure!(
        frame.len() >= 5 && frame[0] == 0,
        "one uncompressed unary message required"
    );
    let length = u32::from_be_bytes(frame[1..5].try_into()?) as usize;
    ensure!(frame.len() == length + 5, "invalid unary frame");
    let input = &frame[5..];
    let mut output = vec![];
    let mut cursor = 0;
    while cursor < input.len() {
        let start = cursor;
        let tag = varint(input, &mut cursor)?;
        ensure!(tag >> 3 != 0, "invalid field number");
        match tag & 7 {
            0 => {
                varint(input, &mut cursor)?;
            }
            1 => cursor = cursor.checked_add(8).context("overflow")?,
            2 => {
                let len = usize::try_from(varint(input, &mut cursor)?)?;
                cursor = cursor.checked_add(len).context("overflow")?;
            }
            5 => cursor = cursor.checked_add(4).context("overflow")?,
            _ => anyhow::bail!("unsupported wire type"),
        }
        ensure!(cursor <= input.len(), "truncated field");
        if tag >> 3 != 2 {
            output.extend_from_slice(&input[start..cursor]);
        }
    }
    let mut context = vec![10];
    put_varint(subject.len(), &mut context);
    context.extend_from_slice(subject.as_bytes());
    context.push(18);
    put_varint(subject.len(), &mut context);
    context.extend_from_slice(subject.as_bytes());
    output.push(18);
    put_varint(context.len(), &mut output);
    output.extend_from_slice(&context);
    let mut result = vec![0];
    result.extend_from_slice(&u32::try_from(output.len())?.to_be_bytes());
    result.extend(output);
    Ok(result.into())
}

async fn forward(
    app: Gateway,
    request: Request<RecvStream>,
    respond: SendResponse<Bytes>,
) -> Result<()> {
    let claims = match app.authenticate(&request).await {
        Ok(claims) => claims,
        Err(code) => return refuse(respond, code),
    };
    if let Err(code) = app.admitted(&claims).await {
        return refuse(respond, code);
    }
    let method = request
        .uri()
        .path()
        .strip_prefix(SERVICE)
        .unwrap_or_default();
    if request.method() != "POST"
        || request.uri().query().is_some()
        || ![
            "ExecutePlan",
            "AnalyzePlan",
            "Config",
            "ReattachExecute",
            "ReleaseExecute",
            "ReleaseSession",
            "Interrupt",
            "FetchErrorDetails",
            "ArtifactStatuses",
        ]
        .contains(&method)
    {
        return refuse(respond, 12);
    }
    if request
        .headers()
        .get("grpc-encoding")
        .is_some_and(|h| h != "identity")
    {
        return refuse(respond, 12);
    }
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(Duration::from_secs(30), collect(body, LIMIT)).await {
        Ok(Ok(body)) => match identity_frame(&body, &claims.sub) {
            Ok(body) => body,
            Err(_) => return refuse(respond, 3),
        },
        _ => return refuse(respond, 8),
    };
    // Lease lasts through the entire stream, including downstream backpressure.
    // A caller-supplied session ID never selects another subject's instance.
    let _lease;
    let mut _child;
    trait Backend: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
    impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Backend for T {}
    let io: Box<dyn Backend> = if let Some(manager) = &app.lifecycle {
        _lease = match manager.acquire(&claims.sub, &claims.bearer).await {
            Ok(lease) => lease,
            Err(_) => return refuse(respond, 14),
        };
        _child = manager.connect(&_lease)?;
        Box::new(tokio::io::join(
            _child.stdout.take().context("relay stdout")?,
            _child.stdin.take().context("relay stdin")?,
        ))
    } else {
        match TcpStream::connect("127.0.0.1:50052").await {
            Ok(tcp) => Box::new(tcp),
            Err(_) => return refuse(respond, 14),
        }
    };
    let (mut client, connection) = h2::client::Builder::new()
        .initial_window_size(WINDOW)
        .initial_connection_window_size(WINDOW)
        .handshake(io)
        .await?;
    // Driving the connection is independent of send capacity on the TLS peer.
    // h2 can read and ACK control frames when this stream's DATA window is zero.
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    relay(&mut client, parts, body, respond).await
}

async fn relay(
    client: &mut h2::client::SendRequest<Bytes>,
    parts: http::request::Parts,
    body: Bytes,
    mut respond: SendResponse<Bytes>,
) -> Result<()> {
    // Allowlist transport metadata. Do not send JWTs or asserted identity headers to Sail.
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:50052{}", parts.uri.path()))
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    for name in ["grpc-timeout", "grpc-accept-encoding"] {
        if let Some(value) = parts.headers.get(name) {
            request = request.header(name, value);
        }
    }
    let (response, mut tx) = client.send_request(request.body(())?, false)?;
    send(&mut tx, body, true).await?;
    let response = response.await?;
    let (parts, mut rx) = response.into_parts();
    let end = rx.is_end_stream();
    let mut downstream = respond.send_response(Response::from_parts(parts, ()), end)?;
    if end {
        return Ok(());
    }
    while let Some(data) = rx.data().await {
        let data = data?;
        let len = data.len();
        // Release upstream DATA credit only after downstream accepts the bytes.
        let started = std::time::Instant::now();
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs_f64();
        send(&mut downstream, data, false).await?;
        if started.elapsed() >= Duration::from_secs(1) {
            println!(
                "{}",
                serde_json::json!({"event":"downstream_backpressure",
                "start_unix":unix, "duration_seconds":started.elapsed().as_secs_f64()})
            );
        }
        rx.flow_control().release_capacity(len)?;
    }
    if let Some(trailers) = rx.trailers().await? {
        downstream.send_trailers(trailers)?;
    } else {
        downstream.send_data(Bytes::new(), true)?;
    }
    Ok(())
}

pub async fn run() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        std::env::var("AUTHZ_TLS_CERT")?,
        std::env::var("AUTHZ_TLS_KEY")?,
    )
    .await?;
    let mut server = (*config.get_inner()).clone();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let mut roots = rustls::RootCertStore::empty();
    for certificate in
        CertificateDer::pem_slice_iter(&std::fs::read(std::env::var("AUTHZ_CA_FILE")?)?)
    {
        roots.add(certificate?)?;
    }
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let key = std::fs::read_to_string(std::env::var("AUTHZ_KEY_FILE")?)?
        .trim()
        .to_owned();
    ensure!(key.len() >= 32, "service credential too short");
    let app = Gateway {
        tls: TlsConnector::from(Arc::new(client)),
        jwks: https(&std::env::var("SAIL_JWKS_URL")?)?,
        decide: https(&format!(
            "{}/decide",
            std::env::var("AUTHZ_ENDPOINT")?.trim_end_matches('/')
        ))?,
        issuer: std::env::var("SAIL_ISSUER")?,
        audiences: std::env::var("SAIL_AUDIENCE")?
            .split(',')
            .map(str::to_owned)
            .collect(),
        key,
        lifecycle: crate::lifecycle::Manager::configured()?,
    };
    ensure!(
        !app.issuer.is_empty() && app.audiences.iter().all(|a| !a.is_empty()),
        "empty issuer/audience"
    );
    let listener =
        TcpListener::bind(std::env::var("AUTHZ_LISTEN").unwrap_or("0.0.0.0:50051".into())).await?;
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let connection = async {
                let io =
                    tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await??;
                ensure!(
                    io.get_ref().1.alpn_protocol() == Some(b"h2"),
                    "HTTP/2 required"
                );
                let mut connection = h2::server::Builder::new()
                    .initial_window_size(WINDOW)
                    .initial_connection_window_size(WINDOW)
                    .max_concurrent_streams(32)
                    .handshake(io)
                    .await?;
                while let Some(stream) = connection.accept().await {
                    let (request, respond) = stream?;
                    let app = app.clone();
                    tokio::spawn(async move {
                        if forward(app, request, respond).await.is_err() {
                            eprintln!("gateway stream failed");
                        }
                    });
                }
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if connection.is_err() {
                eprintln!("gateway connection closed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replaces_duplicate_untrusted_contexts_preserves_plan() -> Result<()> {
        let input = [0, 0, 0, 0, 12, 18, 1, 0, 26, 1, 42, 18, 1, 0, 10, 1, 7];
        let frame = identity_frame(&input, "sub")?;
        assert_eq!(&frame[5..11], &[26, 1, 42, 10, 1, 7]);
        assert_eq!(
            &frame[11..],
            &[18, 10, 10, 3, b's', b'u', b'b', 18, 3, b's', b'u', b'b']
        );
        assert!(identity_frame(&input[..10], "sub").is_err());
        let mut compressed = input;
        compressed[0] = 1;
        assert!(identity_frame(&compressed, "sub").is_err());
        Ok(())
    }
    #[tokio::test]
    async fn preserves_trailers_only_error_end_stream() -> Result<()> {
        let (backend_io, backend_server_io) = tokio::io::duplex(65_536);
        let _backend = Driver(tokio::spawn(async move {
            let mut server = h2::server::handshake(backend_server_io).await.unwrap();
            while let Some(request) = server.accept().await {
                let (_, mut respond) = request.unwrap();
                respond
                    .send_response(
                        Response::builder()
                            .header("content-type", "application/grpc")
                            .header("grpc-status", "3")
                            .body(())
                            .unwrap(),
                        true,
                    )
                    .unwrap();
            }
        }));
        let (upstream, connection) = h2::client::handshake(backend_io).await?;
        let _upstream = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let (client_io, server_io) = tokio::io::duplex(65_536);
        let _server = Driver(tokio::spawn(async move {
            let mut server = h2::server::handshake(server_io).await.unwrap();
            while let Some(request) = server.accept().await {
                let (request, respond) = request.unwrap();
                let mut upstream = upstream.clone();
                tokio::spawn(async move {
                    relay(
                        &mut upstream,
                        request.into_parts().0,
                        Bytes::from_static(&[0, 0, 0, 0, 0]),
                        respond,
                    )
                    .await
                    .unwrap();
                });
            }
        }));
        let (mut client, connection) = h2::client::handshake(client_io).await?;
        let _client = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let (response, _) = client.send_request(
            Request::builder()
                .uri("http://localhost/spark.connect.SparkConnectService/ExecutePlan")
                .body(())?,
            true,
        )?;
        let response = tokio::time::timeout(Duration::from_secs(3), response).await??;
        assert_eq!(response.headers()["grpc-status"], "3");
        assert!(
            response.body().is_end_stream(),
            "Trailers-only error must end in HEADERS"
        );
        Ok(())
    }
}
