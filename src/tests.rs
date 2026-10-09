// Tests de integración del proxy. Levantan un backend eco en loopback y envían
// las peticiones al router real (`build_router`) con `oneshot`, sin abrir un
// puerto para rocky. El socket del cliente se simula con `MockConnectInfo`.

use crate::build_router;
use crate::config::{AppConfig, BanConfig, RouteConfig, RuleConfig};
use crate::state::AppState;
use axum::{
    body::{Body, Bytes},
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode},
    Json, Router,
};
use serde_json::{json, Map, Value};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

// Socket tipo Cloud Run (link-local). En modo plataforma rocky no lo usa para
// derivar la IP del cliente; en bare-metal solo importa si es proxy de confianza.
const CLOUD_RUN_SOCKET: &str = "169.254.1.1:4000";

// --- BACKEND ECO ---

/// Responde en JSON lo que recibió: método, uri (path + query), headers con
/// TODAS las líneas de cada nombre, y body.
async fn echo(req: Request<Body>) -> Json<Value> {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let mut headers = Map::new();
    for (name, value) in parts.headers.iter() {
        headers
            .entry(name.as_str())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap()
            .push(json!(String::from_utf8_lossy(value.as_bytes())));
    }
    Json(json!({
        "method": parts.method.as_str(),
        "uri": parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(""),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    }))
}

async fn spawn_echo_backend() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(echo)).await.unwrap();
    });
    addr
}

// --- ROCKY BAJO PRUEBA ---

struct Proxy {
    router: Router,
    state: Arc<AppState>,
    backend: SocketAddr,
}

struct Reply {
    status: StatusCode,
    body: Bytes,
}

impl Reply {
    /// Lo que recibió el backend eco (solo válido si la petición llegó hasta él).
    fn echoed(&self) -> Value {
        serde_json::from_slice(&self.body).expect("el backend eco responde JSON")
    }
}

/// Config apuntando a `backend`, sin whitelist global (el test que la necesita
/// la asigna después).
fn app_config(
    backend: SocketAddr,
    trusted_hops: Option<usize>,
    trusted_proxies: &[&str],
    routes: Vec<RouteConfig>,
) -> AppConfig {
    AppConfig {
        backend_url: format!("http://{}", backend),
        global_whitelist: vec![],
        trusted_proxies: trusted_proxies.iter().map(|s| s.to_string()).collect(),
        trusted_hops,
        routes,
    }
}

impl Proxy {
    /// Rocky delante de un backend eco. `socket` es la dirección TCP desde la que
    /// rocky ve conectar al cliente (el ingress, en producción).
    async fn new(
        socket: &str,
        trusted_hops: Option<usize>,
        trusted_proxies: &[&str],
        routes: Vec<RouteConfig>,
    ) -> Self {
        let backend = spawn_echo_backend().await;
        Self::start(backend, app_config(backend, trusted_hops, trusted_proxies, routes), socket)
    }

    fn start(backend: SocketAddr, config: AppConfig, socket: &str) -> Self {
        let state = AppState::new(config);
        let socket: SocketAddr = socket.parse().unwrap();
        // El router se clona por petición (oneshot lo consume) pero comparte el
        // mismo AppState, así que el rate limit persiste entre peticiones.
        let router = build_router(state.clone()).layer(MockConnectInfo(socket));
        Self { router, state, backend }
    }

    async fn send(&self, req: Request<Body>) -> Reply {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        Reply { status, body }
    }

    async fn status(&self, req: Request<Body>) -> StatusCode {
        self.send(req).await.status
    }
}

fn rule(identifiers: &[&str], limit: u32, window_secs: u64, ban_secs: u64) -> RuleConfig {
    RuleConfig {
        identifiers: identifiers.iter().map(|s| s.to_string()).collect(),
        limit,
        window_secs,
        on_limit_exceeded: BanConfig { duration_secs: ban_secs },
    }
}

fn route(path: &str, rules: Vec<RuleConfig>) -> RouteConfig {
    RouteConfig { path: path.to_string(), rules }
}

/// GET sin body. Un mismo nombre repetido en `headers` genera varias líneas.
fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::empty()).unwrap()
}

/// Ruta + regla por header Authorization usada por los tests de identidad.
async fn proxy_limiting_authorization(limit: u32, ban_secs: u64) -> Proxy {
    Proxy::new(
        CLOUD_RUN_SOCKET,
        Some(0),
        &[],
        vec![route("/api/web/**", vec![rule(&["header:authorization"], limit, 60, ban_secs)])],
    )
    .await
}

/// Rocky con una sola regla `ip` (limit 1, ventana 60 s) en todas las rutas.
async fn proxy_limiting_ip(ban_secs: u64) -> Proxy {
    Proxy::new(
        CLOUD_RUN_SOCKET,
        Some(0),
        &[],
        vec![route("/**", vec![rule(&["ip"], 1, 60, ban_secs)])],
    )
    .await
}

// --- IP DEL CLIENTE Y CABECERA X-FORWARDED-FOR ---

/// a. Regresión: un POST legítimo llega al backend igual que salió del cliente
/// (método, uri con query, body y headers propios), con el Host del backend y
/// X-Real-IP calculado.
#[tokio::test]
async fn passthrough_preserves_request() {
    let p = Proxy::new(
        CLOUD_RUN_SOCKET,
        Some(0),
        &[],
        vec![route("/api/**", vec![rule(&["ip"], 100, 60, 0)])],
    )
    .await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/x/y?a=1&b=two")
        .header("host", "cliente.example")
        .header("x-custom", "1")
        .header("x-forwarded-for", "203.0.113.5")
        .body(Body::from("hola"))
        .unwrap();
    let res = p.send(req).await;

    assert_eq!(res.status, StatusCode::OK);
    let echo = res.echoed();
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["uri"], "/api/x/y?a=1&b=two");
    assert_eq!(echo["body"], "hola");
    assert_eq!(echo["headers"]["x-custom"], json!(["1"]));
    assert_eq!(echo["headers"]["host"], json!([p.backend.to_string()]));
    assert_eq!(echo["headers"]["x-real-ip"], json!(["203.0.113.5"]));
}

/// b. Modo plataforma con socket "de confianza" (Cloud Run 169.254.x.x listado
/// en trusted_proxies): el backend recibe SOLO la IP calculada. La cadena que el
/// cliente puso a la izquierda del X-Forwarded-For no puede llegar al backend,
/// que toma la entrada left-most.
#[tokio::test]
async fn platform_mode_drops_client_supplied_xff_chain() {
    let p = Proxy::new(CLOUD_RUN_SOCKET, Some(0), &["169.254.0.0/16"], vec![]).await;

    let res = p
        .send(get("/v1/x", &[("x-forwarded-for", "198.51.100.9, 203.0.113.5")]))
        .await;

    assert_eq!(res.status, StatusCode::OK);
    let echo = res.echoed();
    assert_eq!(echo["headers"]["x-forwarded-for"], json!(["203.0.113.5"]));
    assert_eq!(echo["headers"]["x-real-ip"], json!(["203.0.113.5"]));
}

/// c. Regresión bare-metal: con el socket en trusted_proxies se conserva el
/// append de la IP calculada a la cadena X-Forwarded-For existente.
#[tokio::test]
async fn bare_metal_trusted_socket_appends_to_xff_chain() {
    let p = Proxy::new("10.0.0.1:4000", None, &["10.0.0.0/8"], vec![]).await;

    let res = p.send(get("/v1/x", &[("x-forwarded-for", "203.0.113.5")])).await;

    assert_eq!(res.status, StatusCode::OK);
    let echo = res.echoed();
    assert_eq!(echo["headers"]["x-forwarded-for"], json!(["203.0.113.5, 203.0.113.5"]));
    assert_eq!(echo["headers"]["x-real-ip"], json!(["203.0.113.5"]));
}

// --- IDENTIFICADOR header:authorization ---

/// d. Variantes de espacios y de mayúsculas del scheme son el mismo token para el
/// backend, así que deben compartir bucket (límite 3: la cuarta variante ya
/// excede).
#[tokio::test]
async fn authorization_whitespace_and_scheme_case_share_bucket() {
    let p = proxy_limiting_authorization(3, 0).await;

    for auth in ["Bearer tok", "Bearer  tok", "bearer\ttok"] {
        let status = p.status(get("/api/web/chat", &[("authorization", auth)])).await;
        assert_eq!(status, StatusCode::OK, "authorization {:?}", auth);
    }
    let status = p.status(get("/api/web/chat", &[("authorization", "BEARER tok")])).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

/// e. Regresión: tokens distintos siguen teniendo buckets distintos.
#[tokio::test]
async fn authorization_distinct_tokens_have_distinct_buckets() {
    let p = proxy_limiting_authorization(1, 0).await;

    let a = p.status(get("/api/web/chat", &[("authorization", "Bearer a")])).await;
    let b = p.status(get("/api/web/chat", &[("authorization", "Bearer b")])).await;
    let a_again = p.status(get("/api/web/chat", &[("authorization", "Bearer a")])).await;

    assert_eq!(a, StatusCode::OK);
    assert_eq!(b, StatusCode::OK);
    assert_eq!(a_again, StatusCode::TOO_MANY_REQUESTS);
}

/// f. El backend autentica con la PRIMERA línea de Authorization; una segunda
/// línea con basura no debe abrir un bucket nuevo.
#[tokio::test]
async fn extra_authorization_line_does_not_open_new_bucket() {
    let p = proxy_limiting_authorization(1, 0).await;

    let first = p.status(get("/api/web/chat", &[("authorization", "Bearer tok")])).await;
    let with_junk = p
        .status(get(
            "/api/web/chat",
            &[("authorization", "Bearer tok"), ("authorization", "junk-123")],
        ))
        .await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(with_junk, StatusCode::TOO_MANY_REQUESTS);
}

/// g1. Regresión: sin Authorization la regla se omite (preflight CORS), no se
/// convierte en un bucket global.
#[tokio::test]
async fn missing_authorization_skips_rule() {
    let p = proxy_limiting_authorization(1, 0).await;

    for _ in 0..2 {
        let status = p.status(get("/api/web/chat", &[])).await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// g2. Authorization vacío no identifica a nadie: se omite la regla igual que
/// si faltara, en vez de colapsar a todos los clientes en un bucket compartido.
#[tokio::test]
async fn empty_authorization_skips_rule() {
    let p = proxy_limiting_authorization(1, 0).await;

    for _ in 0..2 {
        let status = p.status(get("/api/web/chat", &[("authorization", "")])).await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// m. La key del rate limit lleva el header hasheado (16 hex), no el valor
/// crudo: un Authorization gigante no infla la memoria y el token no queda en
/// RAM. Se inspecciona la key guardada en ban_cache (ban > 0).
#[tokio::test]
async fn authorization_key_is_fixed_size_hash() {
    let p = proxy_limiting_authorization(1, 60).await;
    let auth = format!("Bearer {}", "S3cr3t".repeat(1000));

    let first = p.status(get("/api/web/chat", &[("authorization", &auth)])).await;
    let second = p.status(get("/api/web/chat", &[("authorization", &auth)])).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);

    p.state.ban_cache.run_pending_tasks().await;
    let keys: Vec<String> = p.state.ban_cache.iter().map(|(k, _)| k.to_string()).collect();
    assert_eq!(keys.len(), 1);
    let hash = keys[0]
        .strip_prefix("/api/web/**\0")
        .and_then(|k| k.strip_suffix('\0'))
        .unwrap_or("");
    assert!(
        hash.len() == 16 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "la key no lleva un hash de 16 hex (len={}): {}",
        keys[0].len(),
        keys[0].escape_debug().take(60).collect::<String>()
    );
}

// --- IDENTIFICADOR ip ---

/// h. IPv6 agrupado por /64: un atacante con un /64 no obtiene un bucket por
/// cada dirección. Otro /64 sí tiene bucket propio.
#[tokio::test]
async fn ipv6_same_64_shares_bucket() {
    let p = proxy_limiting_ip(0).await;

    let first = p.status(get("/v1/x", &[("x-forwarded-for", "2001:db8:1:2::a")])).await;
    let same_64 = p.status(get("/v1/x", &[("x-forwarded-for", "2001:db8:1:2:ffff::b")])).await;
    let other_64 = p.status(get("/v1/x", &[("x-forwarded-for", "2001:db8:1:3::a")])).await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(same_64, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(other_64, StatusCode::OK);
}

/// i. Regresión: IPv4 sigue siendo un bucket por dirección.
#[tokio::test]
async fn ipv4_has_one_bucket_per_address() {
    let p = proxy_limiting_ip(0).await;

    let first = p.status(get("/v1/x", &[("x-forwarded-for", "203.0.113.5")])).await;
    let same = p.status(get("/v1/x", &[("x-forwarded-for", "203.0.113.5")])).await;
    let other = p.status(get("/v1/x", &[("x-forwarded-for", "203.0.113.6")])).await;

    assert_eq!(first, StatusCode::OK);
    assert_eq!(same, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(other, StatusCode::OK);
}

/// j. Regresión: al exceder el límite se registra el baneo y las peticiones
/// siguientes de esa IP quedan bloqueadas.
#[tokio::test]
async fn exceeding_limit_registers_ban() {
    let p = proxy_limiting_ip(60).await;
    let req = || get("/v1/x", &[("x-forwarded-for", "203.0.113.5")]);

    assert_eq!(p.status(req()).await, StatusCode::OK);
    assert_eq!(p.status(req()).await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(p.status(req()).await, StatusCode::TOO_MANY_REQUESTS);

    // El 429 del tercero podría venir también del limiter: comprobamos que el
    // baneo quedó realmente en la caché.
    p.state.ban_cache.run_pending_tasks().await;
    assert_eq!(p.state.ban_cache.entry_count(), 1);
}

/// n. Regresión: la whitelist compara la IP COMPLETA, no el grupo /64 de la key.
/// Las IPs de la lista (exacta o por CIDR) nunca se limitan; otra IP del mismo
/// /64 que la whitelisted sí.
#[tokio::test]
async fn whitelist_matches_the_full_ip_not_the_64_group() {
    let backend = spawn_echo_backend().await;
    let mut config = app_config(
        backend,
        Some(0),
        &[],
        vec![route("/**", vec![rule(&["ip"], 1, 60, 0)])],
    );
    config.global_whitelist = vec!["2001:db8:1:2::a".to_string(), "198.51.100.0/24".to_string()];
    let p = Proxy::start(backend, config, CLOUD_RUN_SOCKET);
    let from = |ip: &str| get("/v1/x", &[("x-forwarded-for", ip)]);

    for ip in ["2001:db8:1:2::a", "198.51.100.7"] {
        for _ in 0..3 {
            assert_eq!(p.status(from(ip)).await, StatusCode::OK, "whitelisted {}", ip);
        }
    }
    assert_eq!(p.status(from("2001:db8:1:2::b")).await, StatusCode::OK);
    assert_eq!(p.status(from("2001:db8:1:2::b")).await, StatusCode::TOO_MANY_REQUESTS);
}

// --- PATH ---

/// k1. `%25` (doble codificación: `%252e` → `%2e` → `.`, `%252f` → `/`) y `;`
/// (el normalizador trunca cada segmento en `;`, así `..;` pasa a `..`) permiten
/// que las reglas se evalúen sobre un path distinto al del backend: se rechazan.
#[tokio::test]
async fn encoded_percent_or_semicolon_in_path_is_rejected() {
    let p = Proxy::new(CLOUD_RUN_SOCKET, Some(0), &[], vec![]).await;

    let mut not_rejected = Vec::new();
    for uri in [
        "/v1/cuenta/%252e%252e",
        "/v1/cuenta/%252f",
        "/v1/x;y",
        "/v1/x/..;/y",
        "/v1/x%3By",
        "/v1/x%3by",
    ] {
        if p.status(get(uri, &[])).await != StatusCode::BAD_REQUEST {
            not_rejected.push(uri);
        }
    }
    assert!(not_rejected.is_empty(), "paths sin rechazar con 400: {:?}", not_rejected);
}

/// k2. Regresión: codificación normal en el path (`%20`) y `%`/`;` en la QUERY
/// siguen pasando y se reenvían tal cual.
#[tokio::test]
async fn regular_encoding_and_query_specials_still_pass() {
    let p = Proxy::new(CLOUD_RUN_SOCKET, Some(0), &[], vec![]).await;

    for uri in ["/v1/a%20b", "/v1/x?a=%25&b=c;d"] {
        let res = p.send(get(uri, &[])).await;
        assert_eq!(res.status, StatusCode::OK, "uri {}", uri);
        assert_eq!(res.echoed()["uri"], uri);
    }
}

// --- LOGS ---

/// Writer que acumula lo que loggea `tracing` para inspeccionarlo en el test.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// l. Si el backend no responde, el warn! del error no debe incluir la URL
/// completa: la query puede llevar OTP o tokens.
#[tokio::test]
async fn backend_error_log_does_not_leak_query() {
    // Puerto cerrado: se reserva y se suelta, así que la conexión es rechazada.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let p = Proxy::start(closed, app_config(closed, Some(0), &[], vec![]), CLOUD_RUN_SOCKET);

    let logs = LogBuffer::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let status = p.status(get("/v1/login?otp=123456", &[])).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("Error conectando al backend"), "no se loggeó el error: {}", logged);
    assert!(!logged.contains("otp=123456"), "el log filtra la query: {}", logged);
}
