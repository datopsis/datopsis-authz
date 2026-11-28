//! Slice 4c adversarial review of the serve role. Each test asserts the REQUIRED
//! secure behaviour; a failing test is a finding for owner triage.
//! Run with: cargo test -p authz-serve -- --ignored adversarial
//! Gateway and Trino wire tests live beside their modules (see gateway.rs/opa.rs).
use crate::*;
use axum::{extract::State as AxumState, http::Uri, response::IntoResponse};
use serde_json::json;
use std::sync::Mutex;

#[derive(Clone, Default)]
struct Idp {
    mode: Arc<Mutex<&'static str>>,
    groups: Arc<Mutex<Vec<String>>>,
    seen: Arc<Mutex<Vec<String>>>,
}
async fn idp_handler(AxumState(idp): AxumState<Idp>, uri: Uri) -> axum::response::Response {
    idp.seen.lock().unwrap().push(
        uri.path_and_query()
            .map(|p| p.to_string())
            .unwrap_or_default(),
    );
    let subject = uri
        .path()
        .strip_prefix("/auth/v1/users/")
        .map(percent_decode)
        .unwrap_or_default();
    let groups = idp.groups.lock().unwrap().clone();
    let mode = *idp.mode.lock().unwrap();
    match mode {
        "error" => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        "missing" => StatusCode::NOT_FOUND.into_response(),
        "disabled" => Json(json!({"id":subject,"enabled":false,"groups":groups})).into_response(),
        "other_id" => {
            Json(json!({"id":"someone-else","enabled":true,"groups":groups})).into_response()
        }
        "bad_groups" => Json(json!({"id":subject,"enabled":true,"groups":[1,2]})).into_response(),
        "list" => Json(json!([{"id":subject,"enabled":true,"groups":groups}])).into_response(),
        _ => Json(json!({"id":subject,"enabled":true,"groups":groups})).into_response(),
    }
}
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 3 <= bytes.len()
            && let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
async fn idp() -> (Idp, String) {
    let idp = Idp::default();
    *idp.mode.lock().unwrap() = "ok";
    *idp.groups.lock().unwrap() = vec!["readers".into()];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/auth/v1/users", listener.local_addr().unwrap());
    let router = Router::new().fallback(idp_handler).with_state(idp.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (idp, url)
}
fn live(url: &str, machines: &[&str]) -> Live {
    Live {
        // Plain HTTP only reaches the in-process mock; production construction
        // (HTTPS-only, private CA, no redirects) is exercised by the CI harness.
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap(),
        url: url.into(),
        key: "reader-key".into(),
        cache: Default::default(),
        machines: machines.iter().map(|s| s.to_string()).collect(),
        limit: Arc::new(tokio::sync::Semaphore::new(16)),
    }
}
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn unreachable_db() -> Database {
    Database(
        sqlx_postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy_with(
                sqlx_postgres::PgConnectOptions::new()
                    .host("127.0.0.1")
                    .port(closed_port()),
            ),
    )
}
fn bearer(key: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("authorization", format!("Bearer {key}").parse().unwrap());
    h
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_gateway_credential_cannot_administer_the_relationship_store() {
    // SAIL.md: the internet-facing gateway is configured with AUTHZ_KEY_FILE to
    // call /sail/groups. That credential must not also authorize grant/graph
    // administration (mutate, snapshot, permissions) or native decisions, as
    // the separate Trino decision-only key already guarantees for Trino.
    let gateway_key = "g".repeat(40);
    let app = App {
        key: gateway_key.clone(),
        trino_key: Some("t".repeat(40)),
        live: live(
            &format!("http://127.0.0.1:{}/auth/v1/users", closed_port()),
            &[],
        ),
        db: unreachable_db(),
    };
    let groups = sail_groups(
        AxumState(app.clone()),
        bearer(&gateway_key),
        Json("oidc~alice".into()),
    )
    .await;
    assert_ne!(
        groups.err(),
        Some(StatusCode::UNAUTHORIZED),
        "control: gateway credential must reach /sail/groups"
    );
    let mutation = Mutation::SetRegion {
        principal: "oidc~mallory".into(),
        region: "all".into(),
    };
    let mutate = mutate(AxumState(app.clone()), bearer(&gateway_key), Json(mutation)).await;
    let snapshot = snapshot(AxumState(app.clone()), bearer(&gateway_key))
        .await
        .err();
    assert_eq!(
        mutate.err(),
        Some(StatusCode::UNAUTHORIZED),
        "gateway credential authorized /mutate"
    );
    assert_eq!(
        snapshot,
        Some(StatusCode::UNAUTHORIZED),
        "gateway credential authorized /snapshot"
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_service_routes_reject_missing_and_malformed_credentials() {
    let key = "k".repeat(40);
    let app = App {
        key: key.clone(),
        trino_key: Some("t".repeat(40)),
        live: live(
            &format!("http://127.0.0.1:{}/auth/v1/users", closed_port()),
            &[],
        ),
        db: unreachable_db(),
    };
    let mut cases: Vec<HeaderMap> = vec![HeaderMap::new()];
    for value in [
        format!("bearer {key}"),
        format!("Bearer  {key}"),
        format!("Bearer {key} "),
        format!("Bearer {}", &key[..39]),
        format!("Bearer {key}x"),
        format!("Basic {key}"),
        key.clone(),
        format!("Bearer {}", "t".repeat(40)),
    ] {
        let mut h = HeaderMap::new();
        h.insert("authorization", value.parse().unwrap());
        cases.push(h);
    }
    for headers in cases {
        let shown = format!("{headers:?}").replace(&key, "<key>");
        assert_eq!(
            snapshot(AxumState(app.clone()), headers.clone())
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED),
            "{shown}"
        );
        let m = Mutation::Delete {
            resource: authz_core::Resource::new("Table", "t"),
        };
        assert_eq!(
            mutate(AxumState(app.clone()), headers.clone(), Json(m))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED),
            "{shown}"
        );
        assert_eq!(
            decide(AxumState(app.clone()), headers, Json(vec![]))
                .await
                .err(),
            Some(StatusCode::UNAUTHORIZED),
            "{shown}"
        );
    }
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_membership_lookup_cannot_escape_the_user_resource() {
    let (idp, url) = idp().await;
    let live = live(&url, &[]);
    let mut violations = vec![];
    for principal in [
        "oidc~",
        "oidc~.",
        "oidc~..",
        "oidc~../../admin",
        "oidc~a/../b",
        "oidc~a/b",
        "oidc~a?x=1",
        "oidc~a#frag",
        "oidc~%2e%2e",
        "oidc~a%2Fb",
        "oidc~ a",
        "oidc~a\nb",
        "oidc~\u{0}",
    ] {
        idp.seen.lock().unwrap().clear();
        let result = live.groups(principal).await;
        let subject = principal.strip_prefix("oidc~").unwrap();
        let seen = idp.seen.lock().unwrap().clone();
        for path in &seen {
            let segment = path.strip_prefix("/auth/v1/users/");
            if !segment.is_some_and(|s| {
                !s.is_empty()
                    && !s.contains('/')
                    && !s.contains('?')
                    && percent_decode(s) == subject
            }) {
                violations.push(format!("{principal:?} -> GET {path:?} -> {result:?}"));
            }
        }
        if seen.is_empty() && result.is_ok() {
            violations.push(format!("{principal:?} produced groups without a lookup"));
        }
    }
    assert!(
        violations.is_empty(),
        "lookups outside the principal's own user resource:
{}",
        violations.join(
            "
"
        )
    );
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_membership_errors_never_fall_back_to_cached_groups() {
    let (idp, url) = idp().await;
    let live = live(&url, &["oidc~machine"]);
    assert_eq!(
        live.groups("oidc~alice").await,
        Ok(Some(vec!["readers".to_string()]))
    );
    for mode in [
        "error",
        "missing",
        "disabled",
        "other_id",
        "bad_groups",
        "list",
    ] {
        *idp.mode.lock().unwrap() = mode;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let result = live.groups("oidc~alice").await;
        assert!(
            result.is_err(),
            "{mode}: stale or invalid membership returned {result:?}"
        );
    }
    // Unknown non-machine principals are refused; machine principals get no groups.
    *idp.mode.lock().unwrap() = "missing";
    assert_eq!(live.groups("oidc~machine").await, Ok(Some(vec![])));
    assert!(live.groups("oidc~unknown").await.is_err());
    // Non-OIDC principal namespaces never reach the IdP or obtain groups.
    *idp.mode.lock().unwrap() = "ok";
    idp.seen.lock().unwrap().clear();
    for p in ["kubernetes~alice", "alice", "", "OIDC~alice", " oidc~alice"] {
        assert!(live.groups(p).await.is_err(), "{p:?}");
    }
    assert!(idp.seen.lock().unwrap().is_empty());
}

#[tokio::test]
#[ignore = "slice 4c adversarial: run by the native CI step with --ignored"]
async fn adversarial_membership_revocation_and_cache_bounds() {
    let (idp, url) = idp().await;
    let live = live(&url, &[]);
    assert_eq!(
        live.groups("oidc~alice").await,
        Ok(Some(vec!["readers".to_string()]))
    );
    idp.groups.lock().unwrap().clear();
    tokio::time::sleep(Duration::from_millis(260)).await;
    assert_eq!(
        live.groups("oidc~alice").await,
        Ok(Some(vec![])),
        "revoked group survived the 250 ms bound"
    );
    // The cache never grows past its bound, whether entries are fresh or stale.
    for fresh in [true, false] {
        {
            let mut cache = live.cache.write().unwrap();
            cache.clear();
            let at = if fresh {
                Instant::now()
            } else {
                Instant::now() - Duration::from_secs(5)
            };
            for i in 0..10_000 {
                cache.insert(format!("oidc~filler-{i}"), (at, vec![]));
            }
        }
        let result = live.groups("oidc~new-user").await;
        assert!(result.is_ok());
        assert!(
            live.cache.read().unwrap().len() <= 10_000,
            "membership cache exceeded its bound"
        );
    }
    // A cache entry for one principal is never served to another.
    *idp.groups.lock().unwrap() = vec!["admins".into()];
    tokio::time::sleep(Duration::from_millis(260)).await;
    live.cache.write().unwrap().clear();
    assert_eq!(
        live.groups("oidc~admin").await,
        Ok(Some(vec!["admins".to_string()]))
    );
    idp.groups.lock().unwrap().clear();
    assert_eq!(live.groups("oidc~admin2").await, Ok(Some(vec![])));
}
