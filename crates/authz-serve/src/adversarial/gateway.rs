//! Slice 4c adversarial review of the Sail gateway. Each test asserts the REQUIRED
//! secure behaviour against the real admission code: an in-process verified
//! TLS/HTTP2 JWKS + membership mock, real RS256 tokens and an unreachable audit
//! database. Test keys and certificates are generated per run with the openssl
//! CLI in a private temporary directory; nothing is committed.
//! Run with: cargo test -p authz-serve -- --ignored adversarial
use super::*;
use jsonwebtoken::{EncodingKey, Header, encode};
use rustls::pki_types::PrivateKeyDer;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use tokio::sync::oneshot;

const ISSUER: &str = "https://idp.s4c.test/auth/v1/";
const AUDIENCE: &str = "sail";
const KID: &str = "s4c-key";

struct Material {
    dir: PathBuf,
    jwt_private: Vec<u8>,
    jwt_public: Vec<u8>,
    other_private: Vec<u8>,
    modulus: Vec<u8>,
}
fn openssl(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl CLI is required for slice 4c gateway tests");
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
fn material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("s4c-gateway-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, cn) in [("ca", "s4c-ca"), ("rogue", "s4c-rogue")] {
            openssl(
                &dir,
                &[
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
                    &format!("{name}.key"), "-out", &format!("{name}.pem"), "-days", "1",
                    "-subj", &format!("/CN={cn}"),
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign",
                ],
            );
        }
        std::fs::write(
            dir.join("leaf.ext"),
            "basicConstraints=CA:FALSE\nsubjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
        )
        .unwrap();
        for ca in ["ca", "rogue"] {
            openssl(
                &dir,
                &[
                    "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
                    &format!("{ca}-leaf.key"), "-out", "leaf.csr", "-subj", "/CN=localhost",
                ],
            );
            openssl(
                &dir,
                &[
                    "x509", "-req", "-in", "leaf.csr", "-CA", &format!("{ca}.pem"), "-CAkey",
                    &format!("{ca}.key"), "-CAcreateserial", "-days", "1", "-extfile",
                    "leaf.ext", "-out", &format!("{ca}-leaf.pem"),
                ],
            );
        }
        for key in ["jwt", "other"] {
            openssl(
                &dir,
                &[
                    "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out",
                    &format!("{key}.pem"),
                ],
            );
        }
        openssl(&dir, &["pkey", "-in", "jwt.pem", "-pubout", "-out", "jwt.pub"]);
        let modulus = String::from_utf8(openssl(&dir, &["rsa", "-in", "jwt.pem", "-noout", "-modulus"]))
            .unwrap();
        let hex = modulus.trim().trim_start_matches("Modulus=");
        let modulus = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        Material {
            jwt_private: std::fs::read(dir.join("jwt.pem")).unwrap(),
            jwt_public: std::fs::read(dir.join("jwt.pub")).unwrap(),
            other_private: std::fs::read(dir.join("other.pem")).unwrap(),
            modulus,
            dir,
        }
    })
}
fn b64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}
fn jwks() -> Value {
    json!({"keys":[{"kty":"RSA","kid":KID,"alg":"RS256","use":"sig","n":b64(&material().modulus),"e":"AQAB"}]})
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn claims() -> Value {
    json!({"sub":"alice","iss":ISSUER,"aud":AUDIENCE,"exp":now()+300,"iat":now()})
}
fn sign(header: Header, claims: &Value, key: &[u8]) -> String {
    encode(&header, claims, &EncodingKey::from_rsa_pem(key).unwrap()).unwrap()
}
fn rs256(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    sign(header, claims, &material().jwt_private)
}

#[derive(Default)]
struct MockState {
    jwks_status: u16,
    jwks: Vec<u8>,
    groups: Vec<String>,
    jwks_calls: usize,
    groups_calls: usize,
}
type Shared = Arc<Mutex<MockState>>;

fn server_config(ca: &str) -> rustls::ServerConfig {
    let dir = &material().dir;
    let certs = CertificateDer::pem_file_iter(dir.join(format!("{ca}-leaf.pem")))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join(format!("{ca}-leaf.key"))).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}
/// Verified TLS/HTTP2 stand-in for Rauthy's JWKS and serve's /sail/groups.
async fn mock(ca: &str, state: Shared) -> u16 {
    let acceptor = TlsAcceptor::from(Arc::new(server_config(ca)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let state = state.clone();
                    tokio::spawn(async move {
                        let path = request.uri().path().to_owned();
                        let _ = collect(request.into_body(), LIMIT).await;
                        let (status, body) = {
                            let mut s = state.lock().unwrap();
                            if path == "/jwks" {
                                s.jwks_calls += 1;
                                (s.jwks_status, s.jwks.clone())
                            } else {
                                s.groups_calls += 1;
                                (200, serde_json::to_vec(&s.groups).unwrap())
                            }
                        };
                        let response = Response::builder().status(status).body(()).unwrap();
                        if let Ok(mut tx) = respond.send_response(response, false) {
                            let _ = tx.send_data(Bytes::from(body), true);
                        }
                    });
                }
            });
        }
    });
    port
}
fn unreachable_audit_db() -> Database {
    // Bind and drop: nothing listens here, so every audit attempt fails fast.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    Database(
        sqlx_postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy_with(
                sqlx_postgres::PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(port),
            ),
    )
}
struct Fixture {
    app: Gateway,
    state: Shared,
    sockets: PathBuf,
}
async fn fixture_with(ca: &str) -> Fixture {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let state: Shared = Arc::new(Mutex::new(MockState {
        jwks_status: 200,
        jwks: serde_json::to_vec(&jwks()).unwrap(),
        groups: vec!["team-a".into()],
        ..Default::default()
    }));
    let port = mock(ca, state.clone()).await;
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(material().dir.join("ca.pem")).unwrap() {
        roots.add(c.unwrap()).unwrap();
    }
    let mut client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let sockets = material().dir.join(format!("sockets-{}", uuid_like()));
    std::fs::create_dir_all(&sockets).unwrap();
    let teams = vec![
        Team {
            id: "a".into(),
            group: "team-a".into(),
            socket: sockets.join("a.sock"),
        },
        Team {
            id: "b".into(),
            group: "team-b".into(),
            socket: sockets.join("b.sock"),
        },
    ];
    validate_teams(&teams).unwrap();
    Fixture {
        app: Gateway {
            tls: TlsConnector::from(Arc::new(client)),
            jwks: https(&format!("https://localhost:{port}/jwks")).unwrap(),
            membership: https(&format!("https://localhost:{port}/sail/groups")).unwrap(),
            teams,
            db: unreachable_audit_db(),
            issuer: ISSUER.into(),
            audiences: vec![AUDIENCE.into()],
            key: "k".repeat(32),
        },
        state,
        sockets,
    }
}
async fn fixture() -> Fixture {
    fixture_with("ca").await
}
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    )
}

/// Present one HTTP/2 request to the real `authenticate` and return its result.
async fn authenticate_with(
    app: &Gateway,
    authorization: Option<&[u8]>,
) -> std::result::Result<String, u8> {
    let (client_io, server_io) = tokio::io::duplex(1 << 22);
    let (tx, rx) = oneshot::channel();
    let app = app.clone();
    let _server = Driver(tokio::spawn(async move {
        let mut server = h2::server::Builder::new()
            .max_header_list_size(16 << 20)
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        if let Some(Ok((request, mut respond))) = server.accept().await {
            let result = app.authenticate(&request).await.map(|c| c.sub);
            let _ = tx.send(result);
            let _ = respond.send_response(Response::builder().body(()).unwrap(), true);
        }
        while server.accept().await.is_some() {}
    }));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let _client = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = Request::builder()
        .method("POST")
        .uri("https://sail/spark.connect.SparkConnectService/ExecutePlan");
    if let Some(value) = authorization {
        request = request.header(
            "authorization",
            http::HeaderValue::from_bytes(value).unwrap(),
        );
    }
    let (_response, _) = client
        .send_request(request.body(()).unwrap(), true)
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("authenticate hung")
        .unwrap()
}
async fn token_result(app: &Gateway, token: &str) -> std::result::Result<String, u8> {
    authenticate_with(app, Some(format!("Bearer {token}").as_bytes())).await
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_jwt_valid_control_is_admitted() {
    let f = fixture().await;
    assert_eq!(
        token_result(&f.app, &rs256(&claims())).await,
        Ok("alice".into())
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_jwt_claim_validation_rejects_every_bad_claim() {
    let f = fixture().await;
    let mut cases: Vec<(&str, Value)> = vec![];
    let with = |k: &str, v: Value| {
        let mut c = claims();
        c[k] = v;
        c
    };
    let without = |k: &str| {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(k);
        c
    };
    cases.push(("expired", with("exp", json!(now() - 1))));
    cases.push(("exp_far_past", with("exp", json!(1))));
    cases.push(("exp_string", with("exp", json!((now() + 300).to_string()))));
    cases.push(("exp_negative", with("exp", json!(-1))));
    cases.push(("exp_missing", without("exp")));
    cases.push(("nbf_future", with("nbf", json!(now() + 120))));
    cases.push((
        "wrong_issuer",
        with("iss", json!("https://evil.test/auth/v1/")),
    ));
    cases.push((
        "issuer_without_slash",
        with("iss", json!(ISSUER.trim_end_matches('/'))),
    ));
    cases.push(("issuer_case", with("iss", json!(ISSUER.to_uppercase()))));
    cases.push(("issuer_missing", without("iss")));
    cases.push(("wrong_audience", with("aud", json!("lakekeeper"))));
    cases.push(("audience_prefix", with("aud", json!("sail-team-a"))));
    cases.push(("audience_case", with("aud", json!("SAIL"))));
    cases.push(("audience_missing", without("aud")));
    cases.push(("audience_empty_array", with("aud", json!([]))));
    cases.push(("subject_empty", with("sub", json!(""))));
    cases.push(("subject_missing", without("sub")));
    cases.push(("subject_number", with("sub", json!(7))));
    for (name, c) in cases {
        let result = token_result(&f.app, &rs256(&c)).await;
        assert_eq!(
            result,
            Err(16),
            "{name} was not rejected as UNAUTHENTICATED"
        );
    }
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_jwt_algorithm_confusion_and_key_selection_are_rejected() {
    let f = fixture().await;
    let m = material();
    let c = claims();
    let body = format!(
        "{}.{}",
        b64(br#"{"alg":"none","typ":"JWT","kid":"s4c-key"}"#),
        b64(&serde_json::to_vec(&c).unwrap())
    );
    let mut cases: Vec<(&str, String)> = vec![
        ("alg_none_empty_signature", format!("{body}.")),
        ("alg_none_no_signature", body.clone()),
    ];
    let valid = rs256(&c);
    let parts: Vec<&str> = valid.split('.').collect();
    // HS256 keyed with the public key (classic RS/HS swap), PEM and raw modulus.
    for (name, secret) in [
        ("hs256_public_pem", m.jwt_public.clone()),
        ("hs256_modulus", m.modulus.clone()),
    ] {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.into());
        cases.push((
            name,
            encode(&header, &c, &EncodingKey::from_secret(&secret)).unwrap(),
        ));
    }
    for (name, alg) in [
        ("rs384", Algorithm::RS384),
        ("rs512", Algorithm::RS512),
        ("ps256", Algorithm::PS256),
    ] {
        let mut header = Header::new(alg);
        header.kid = Some(KID.into());
        cases.push((name, sign(header, &c, &m.jwt_private)));
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    cases.push(("wrong_key_same_kid", sign(header, &c, &m.other_private)));
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("unknown".into());
    cases.push(("unknown_kid", sign(header, &c, &m.jwt_private)));
    cases.push((
        "missing_kid",
        sign(Header::new(Algorithm::RS256), &c, &m.jwt_private),
    ));
    // Payload swapped under a valid header/signature, and signature stripped.
    let mut bob = c.clone();
    bob["sub"] = json!("bob");
    let forged = b64(&serde_json::to_vec(&bob).unwrap());
    cases.push((
        "payload_swap",
        format!("{}.{}.{}", parts[0], forged, parts[2]),
    ));
    cases.push(("signature_stripped", format!("{}.{}.", parts[0], parts[1])));
    cases.push((
        "signature_truncated",
        format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            &parts[2][..parts[2].len() - 4]
        ),
    ));
    cases.push(("two_tokens", format!("{valid} {valid}")));
    cases.push(("extra_segment", format!("{valid}.e30")));
    cases.push(("garbage", "a.b.c".into()));
    cases.push(("empty", String::new()));
    cases.push((
        "oversize_1mib",
        format!("{}.{}.{}", parts[0], "A".repeat(1 << 20), parts[2]),
    ));
    for (name, token) in cases {
        let result = token_result(&f.app, &token).await;
        assert!(
            result == Err(16),
            "{name} was not rejected as UNAUTHENTICATED: {result:?}"
        );
    }
    // A JWKS that publishes a symmetric key under the token's kid must not
    // turn the public JWKS into an HMAC secret.
    f.state.lock().unwrap().jwks = serde_json::to_vec(&json!({"keys":[
        {"kty":"oct","kid":KID,"alg":"HS256","k":b64(b"public-knowledge")}]}))
    .unwrap();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.into());
    let hs = encode(&header, &c, &EncodingKey::from_secret(b"public-knowledge")).unwrap();
    assert_eq!(
        token_result(&f.app, &hs).await,
        Err(16),
        "oct JWK accepted for HS256"
    );
    let forged_rs = format!(
        "{}.{}.{}",
        b64(&serde_json::to_vec(&json!({"alg":"RS256","kid":KID})).unwrap()),
        b64(&serde_json::to_vec(&c).unwrap()),
        b64(b"not-a-signature")
    );
    assert_eq!(
        token_result(&f.app, &forged_rs).await,
        Err(16),
        "RS256 against an oct JWK accepted"
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_authorization_header_framing_is_strict() {
    let f = fixture().await;
    let token = rs256(&claims());
    for (name, value) in [
        ("missing", None),
        ("lowercase_scheme", Some(format!("bearer {token}"))),
        ("double_space", Some(format!("Bearer  {token}"))),
        ("basic_scheme", Some(format!("Basic {token}"))),
        ("no_scheme", Some(token.clone())),
        ("trailing_space", Some(format!("Bearer {token} "))),
        ("tab", Some(format!("Bearer\t{token}"))),
    ] {
        let result = authenticate_with(&f.app, value.as_deref().map(str::as_bytes)).await;
        assert_eq!(result, Err(16), "{name} accepted");
    }
    // Non-UTF-8/opaque header bytes are refused, not lossily decoded.
    let mut opaque = format!("Bearer {token}").into_bytes();
    opaque.push(0xff);
    assert_eq!(authenticate_with(&f.app, Some(&opaque)).await, Err(16));
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_jwks_failures_fail_closed() {
    let f = fixture().await;
    let token = rs256(&claims());
    for (name, status, body) in [
        ("http_500", 500, serde_json::to_vec(&jwks()).unwrap()),
        ("http_302", 302, serde_json::to_vec(&jwks()).unwrap()),
        ("malformed", 200, b"{not json".to_vec()),
        ("empty_set", 200, br#"{"keys":[]}"#.to_vec()),
        ("oversize", 200, {
            let mut v = serde_json::to_vec(&jwks()).unwrap();
            v.resize(LIMIT + 1, b' ');
            v
        }),
    ] {
        {
            let mut s = f.state.lock().unwrap();
            s.jwks_status = status;
            s.jwks = body;
        }
        let result = token_result(&f.app, &token).await;
        assert!(result.is_err(), "{name}: JWKS failure admitted the token");
    }
    // The JWKS endpoint presenting a certificate from an untrusted CA is refused.
    let rogue = fixture_with("rogue").await;
    assert_eq!(
        token_result(&rogue.app, &token).await,
        Err(14),
        "untrusted JWKS TLS accepted"
    );
    // JWKS unreachable.
    let mut down = fixture().await;
    down.app.jwks = https("https://localhost:1/jwks").unwrap();
    assert_eq!(token_result(&down.app, &token).await, Err(14));
}

fn unary_frame() -> Bytes {
    // ExecutePlanRequest{session_id:"s", user_context:{user_id:"bob"}}
    let message = [10, 1, b's', 18, 5, 10, 3, b'b', b'o', b'b'];
    let mut frame = vec![0, 0, 0, 0, message.len() as u8];
    frame.extend_from_slice(&message);
    Bytes::from(frame)
}
/// Drive the real `forward` for each request on ONE HTTP/2 connection.
async fn forward_on_one_connection(app: &Gateway, tokens: &[String]) -> Vec<String> {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let app = app.clone();
    let _server = Driver(tokio::spawn(async move {
        let mut server = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((request, respond))) = server.accept().await {
            let app = app.clone();
            tokio::spawn(async move {
                let _ = forward(app, request, respond).await;
            });
        }
    }));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let _client = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut statuses = vec![];
    for token in tokens {
        let request = Request::builder()
            .method("POST")
            .uri("https://sail/spark.connect.SparkConnectService/ExecutePlan")
            .header("content-type", "application/grpc")
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap();
        let (response, mut tx) = client.send_request(request, false).unwrap();
        tx.send_data(unary_frame(), true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(15), response)
            .await
            .expect("gateway hung")
            .unwrap();
        statuses.push(
            response
                .headers()
                .get("grpc-status")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_else(|| "none".into()),
        );
    }
    statuses
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_audit_outage_refuses_before_any_backend_connection() {
    let f = fixture().await;
    let a = UnixListener::bind(f.sockets.join("a.sock")).unwrap();
    let b = UnixListener::bind(f.sockets.join("b.sock")).unwrap();
    let token = rs256(&claims());
    // Valid token, exactly one team: only the durable audit is unavailable.
    let statuses = forward_on_one_connection(&f.app, &[token.clone(), token]).await;
    assert_eq!(
        statuses,
        ["14", "14"],
        "audit outage must refuse UNAVAILABLE"
    );
    for (name, listener) in [("a", a), ("b", b)] {
        let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "team {name} backend was contacted without a durable audit"
        );
    }
    // Per-RPC admission on a reused connection: membership is looked up again
    // for every stream (before and after body collection), JWKS for every stream.
    let s = f.state.lock().unwrap();
    assert!(
        s.groups_calls >= 4 && s.jwks_calls >= 2,
        "groups={} jwks={}",
        s.groups_calls,
        s.jwks_calls
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_membership_outage_or_ambiguity_never_reaches_a_backend() {
    let f = fixture().await;
    let a = UnixListener::bind(f.sockets.join("a.sock")).unwrap();
    let token = rs256(&claims());
    for groups in [
        vec![],
        vec!["team-a".to_string(), "team-b".to_string()],
        vec!["TEAM-A".to_string()],
        vec!["team-a ".to_string()],
    ] {
        f.state.lock().unwrap().groups = groups.clone();
        let statuses = forward_on_one_connection(&f.app, std::slice::from_ref(&token)).await;
        assert_ne!(statuses[0], "0", "{groups:?} admitted");
    }
    let mut down = fixture().await;
    down.app.membership = https("https://localhost:1/sail/groups").unwrap();
    assert_ne!(forward_on_one_connection(&down.app, &[token]).await[0], "0");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), a.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_relay_strips_credentials_and_identity_headers() {
    let (backend_io, backend_server_io) = tokio::io::duplex(65_536);
    let (seen_tx, seen_rx) = oneshot::channel();
    let _backend = Driver(tokio::spawn(async move {
        let mut server = h2::server::handshake(backend_server_io).await.unwrap();
        if let Some(Ok((request, mut respond))) = server.accept().await {
            let _ = seen_tx.send((request.uri().clone(), request.headers().clone()));
            let _ = respond.send_response(
                Response::builder()
                    .header("grpc-status", "0")
                    .body(())
                    .unwrap(),
                true,
            );
        }
        while server.accept().await.is_some() {}
    }));
    let (upstream, connection) = h2::client::handshake(backend_io).await.unwrap();
    let _upstream = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let (client_io, server_io) = tokio::io::duplex(65_536);
    let _server = Driver(tokio::spawn(async move {
        let mut server = h2::server::handshake(server_io).await.unwrap();
        if let Some(Ok((request, respond))) = server.accept().await {
            let mut upstream = upstream.clone();
            let _ = relay(
                &mut upstream,
                request.into_parts().0,
                unary_frame(),
                respond,
            )
            .await;
        }
        while server.accept().await.is_some() {}
    }));
    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
    let _client = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = Request::builder()
        .method("POST")
        .uri("https://sail/spark.connect.SparkConnectService/ExecutePlan")
        .header("content-type", "application/grpc+proto")
        .header("grpc-timeout", "5S");
    for (k, v) in [
        ("authorization", "Bearer secret-token"),
        ("proxy-authorization", "Basic eA=="),
        ("cookie", "session=1"),
        ("x-forwarded-for", "10.0.0.1"),
        ("x-forwarded-user", "oidc~operator"),
        ("x-spark-user", "admin"),
        ("x-user-id", "admin"),
        ("x-team", "b"),
        ("grpc-encoding", "gzip"),
        ("x-datopsis-team", "b"),
        ("user-agent", "spoof"),
    ] {
        request = request.header(k, v);
    }
    let (_response, _) = client
        .send_request(request.body(()).unwrap(), true)
        .unwrap();
    let (uri, headers) = tokio::time::timeout(Duration::from_secs(5), seen_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(uri.path(), "/spark.connect.SparkConnectService/ExecutePlan");
    let names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
    for name in &names {
        assert!(
            ["content-type", "te", "grpc-timeout", "grpc-accept-encoding"].contains(name),
            "backend received client header {name}"
        );
    }
    assert_eq!(headers["content-type"], "application/grpc");
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_identity_frame_rejects_smuggling_and_pins_subject() {
    let subject = "alice";
    let good = identity_frame(&unary_frame(), subject).unwrap();
    // Exactly one top-level UserContext, carrying the verified subject only.
    assert!(
        !good.windows(3).any(|w| w == b"bob"),
        "client user_context survived"
    );
    let tail = [
        18, 14, 10, 5, b'a', b'l', b'i', b'c', b'e', 18, 5, b'a', b'l', b'i', b'c', b'e',
    ];
    assert!(good.ends_with(&tail));
    let frame = |body: &[u8]| {
        let mut f = vec![0];
        f.extend_from_slice(&(body.len() as u32).to_be_bytes());
        f.extend_from_slice(body);
        f
    };
    // Every UserContext encoding (any wire type, repeated) is removed.
    let repeated = identity_frame(
        &frame(&[18, 1, 0, 16, 7, 21, 1, 2, 3, 4, 10, 1, b's']),
        subject,
    )
    .unwrap();
    assert_eq!(&repeated[5..8], &[10, 1, b's']);
    let mut rejected = vec![
        ("compressed", {
            let mut f = unary_frame().to_vec();
            f[0] = 1;
            f
        }),
        ("length_short", {
            let mut f = unary_frame().to_vec();
            f[4] += 1;
            f
        }),
        ("length_long", {
            let mut f = unary_frame().to_vec();
            f[4] -= 1;
            f
        }),
        ("two_messages", {
            let mut f = unary_frame().to_vec();
            f.extend_from_slice(&unary_frame());
            f
        }),
        ("start_group", frame(&[19, 20])),
        ("end_group", frame(&[20])),
        ("field_zero", frame(&[2, 0])),
        ("truncated_len", frame(&[26, 10, 1])),
        (
            "huge_len",
            frame(&[
                26, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
            ]),
        ),
        (
            "varint_overflow",
            frame(&[
                8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ]),
        ),
        ("truncated_fixed64", frame(&[9, 1, 2])),
        ("empty", vec![]),
    ];
    rejected.push(("header_only", vec![0, 0, 0, 0, 0, 0]));
    for (name, input) in rejected {
        assert!(identity_frame(&input, subject).is_err(), "{name} accepted");
    }
}

#[test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
fn adversarial_endpoint_and_team_configuration_is_fail_closed() {
    for bad in [
        "http://idp/jwks",
        "https://user@idp/jwks",
        "https://user:pw@idp/jwks",
        "https:///jwks",
        "/jwks",
        "HTTPS://",
        "file:///etc/passwd",
    ] {
        assert!(https(bad).is_err(), "{bad} accepted");
    }
    let team = |id: &str, group: &str, socket: &str| Team {
        id: id.into(),
        group: group.into(),
        socket: socket.into(),
    };
    for teams in [
        vec![],
        vec![team("a", "g", "relative/a.sock")],
        vec![team("a", "g", "/teams/../b/sail.sock")],
        vec![team("", "g", "/a.sock")],
        vec![team("a", "", "/a.sock")],
        vec![team("a", "g", "/a.sock"), team("b", "g", "/b.sock")],
        vec![team("a", "g", "/t/a.sock"), team("b", "h", "/t//a.sock")],
        vec![team("a", "g", "/t/a.sock"), team("b", "h", "/t/./a.sock")],
        vec![team("a", "g", "/a.sock"), team("a", "h", "/b.sock")],
    ] {
        assert!(
            validate_teams(&teams).is_err(),
            "accepted {:?}",
            teams.iter().map(|t| &t.socket).collect::<Vec<_>>()
        );
    }
    assert!(
        serde_json::from_value::<Vec<Team>>(
            json!([{"id":"a","group":"g","socket":"/a.sock","backend":"10.0.0.1:50052"}])
        )
        .is_err(),
        "unknown team fields must be refused"
    );
}
