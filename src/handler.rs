use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, warn};

// Lista de cabeceras Hop-by-Hop que no deben cruzar el proxy ---
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

// Cabeceras que transportan la IP del cliente y son FALSIFICABLES por quien
// conecta directo al proxy. Las eliminamos antes de reenviar para que el
// backend no confíe en un valor spoofeado. NO incluimos x-forwarded-for ni
// x-real-ip: esos los gestiona la lógica de append más abajo (que ya decide
// según la confianza del socket si preserva la cadena o la reemplaza).
const CLIENT_IP_HEADERS: &[&str] = &[
    "forwarded",         // RFC 7239
    "x-client-ip",
    "true-client-ip",    // Akamai/Cloudflare Enterprise
    "cf-connecting-ip",  // Cloudflare
    "fastly-client-ip",  // Fastly
    "x-cluster-client-ip",
];

fn clean_client_ip_headers(headers: &mut HeaderMap) {
    for header in CLIENT_IP_HEADERS {
        headers.remove(*header);
    }
}

/// Extrae los tokens del header Connection que indican headers hop-by-hop
/// adicionales para esta conexión (RFC 7230 §6.1).
fn parse_connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_lowercase())
                .filter(|t| !t.is_empty() && !HOP_BY_HOP_HEADERS.contains(&t.as_str()))
                .collect()
        })
        .unwrap_or_default()
}

fn clean_hop_by_hop_headers(headers: &mut HeaderMap) {
    // Extraer tokens dinámicos del Connection header ANTES de removerlo
    let dynamic_tokens = parse_connection_tokens(headers);
    for header in HOP_BY_HOP_HEADERS {
        headers.remove(*header);
    }
    for token in dynamic_tokens {
        headers.remove(&token);
    }
}

// --- PROTECCIÓN CONTRA IP SPOOFING (Capa de Confianza) ---

/// Obtiene la IP real del cliente evitando suplantaciones en entornos con proxies (Cloud Run/GFE).
/// Solo confía en X-Forwarded-For/X-Real-IP cuando el socket viene de un proxy
/// explícitamente configurado en `trusted_proxies` (o loopback).
fn get_real_ip(headers: &HeaderMap, socket_addr: &SocketAddr, state: &AppState) -> IpAddr {
    let direct_ip = socket_addr.ip();

    // --- MODO PLATAFORMA (Cloud Run / LB gestionado) ---
    // No se puede enumerar el rango de IPs del ingress de Google, así que el
    // modelo por-socket no sirve. En su lugar contamos posiciones desde la
    // DERECHA del X-Forwarded-For: el ingress añade `trusted_hops` entradas
    // reales al final, de modo que la IP del cliente está en `len-1-hops`.
    // Todo lo que el cliente falsifique queda a la izquierda de esa posición y
    // se ignora → inmune a spoofing y a bypass de whitelist.
    if let Some(hops) = state.trusted_hops {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Contamos sobre los tokens crudos (no filtramos parseables) para no
            // desplazar la posición anclada a la derecha. Solo parseamos el target.
            let tokens: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
            if tokens.len() > hops {
                let candidate = tokens[tokens.len() - 1 - hops];
                if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
                    return ip;
                }
            }
        }
        // XFF ausente o más corto de lo esperado (petición que no cruzó el
        // ingress esperado): no confiamos en nada spoofeable, usamos el socket.
        return direct_ip;
    }

    // --- MODO BARE-METAL (trusted_proxies por IP de socket) ---
    // Si la conexión NO viene de un proxy de confianza configurado, la IP directa
    // es la real. Cualquier XFF/X-Real-IP que envíe el cliente es falsificable.
    if !state.is_proxy_trusted(&direct_ip) {
        return direct_ip;
    }

    // 1. Prioridad: X-Real-IP (Google Cloud LB suele sobreescribirla con la IP del cliente)
    if let Some(x_real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = x_real_ip.to_str() {
            let candidate = ip_str.trim();
            if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
                return ip;
            }
        }
    }

    // 2. Seguridad: X-Forwarded-For con Búsqueda Reversa de Confianza.
    // Recorremos de derecha a izquierda saltando las IPs que coinciden con
    // proxies configurados; la primera IP fuera de esa lista es el cliente.
    if let Some(x_forwarded) = headers.get("x-forwarded-for") {
        if let Ok(ip_str) = x_forwarded.to_str() {
            let real_ip = ip_str
                .split(',')
                .rev()
                .map(|s| s.trim())
                .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
                .find(|ip| !state.is_proxy_trusted(ip));

            if let Some(ip) = real_ip {
                return ip;
            }

            // Fallback: si todas las IPs parseables son proxies confiables,
            // devolvemos la IP directa en vez de un string sin validar.
        }
    }

    direct_ip
}

// --- CLAVES DE RATE LIMIT ---

/// Key del identificador `ip`. IPv4 (y IPv6 que mapea una IPv4) va completa; el
/// resto de IPv6 se agrupa por /64. Un cliente IPv6 recibe un /64 entero: con la
/// dirección completa rotaría de IP para obtener un bucket nuevo por petición.
/// Solo afecta a la key del rate limit; whitelist, headers y logs usan la IP completa.
fn rate_limit_ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
    }
}

/// Forma canónica del valor de un header usado como identificador, o `None` si
/// no identifica a nadie (vacío o solo espacios).
/// Se parte por espacios/tabs ASCII y se unen con un único espacio. En
/// `Authorization` además se pasa a minúsculas el esquema (RFC 7235 lo define
/// case-insensitive), solo si hay esquema + credencial; la credencial no se toca.
fn normalize_identity(header_name: &str, value: &[u8]) -> Option<Vec<u8>> {
    let parts: Vec<&[u8]> = value
        .split(|b| b.is_ascii_whitespace())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }

    let lower_scheme = parts.len() >= 2 && header_name.eq_ignore_ascii_case("authorization");
    let mut normalized = Vec::with_capacity(value.len());
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            normalized.push(b' ');
        }
        if i == 0 && lower_scheme {
            normalized.extend(part.to_ascii_lowercase());
        } else {
            normalized.extend_from_slice(part);
        }
    }
    Some(normalized)
}

pub async fn firewall_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, StatusCode> {
    // Desarmamos el request para tomar ownership sin clonar
    let (parts, body) = req.into_parts();
    let raw_path = parts.uri.path();

    // TRANSPARENCIA: reenviamos el path EXACTO del cliente (raw_path) al backend,
    // así que NO podemos reescribirlo para desambiguar. Por eso rechazamos slash
    // y backslash codificados (%2f/%5c): el firewall los decodifica para matchear
    // pero el backend puede tratarlos como literales dentro de un segmento, con lo
    // que ambos segmentan el path distinto → bypass de reglas. Rechazarlos elimina
    // la ambigüedad sin alterar el resto del tráfico legítimo.
    if raw_path.contains("%2f")
        || raw_path.contains("%2F")
        || raw_path.contains("%5c")
        || raw_path.contains("%5C")
    {
        return Ok((StatusCode::BAD_REQUEST, "Encoded slash/backslash in path").into_response());
    }

    // Rechazamos también `%25` (un `%` codificado) y `;` (crudo o como %3b/%3B).
    // Con `%252f`/`%252e` el decode iterativo de abajo produce `/` y `..`, y el
    // normalizador sacaría segmentos protegidos del path sobre el que evaluamos
    // las reglas; `..;` hace lo mismo porque truncamos cada segmento en `;`. El
    // backend (Spring StrictHttpFirewall) ya rechaza ambos, así que ninguna
    // petición legítima cambia de resultado. Solo se mira el path: en la query
    // `%25` y `;` son normales.
    if raw_path.contains("%25")
        || raw_path.contains(';')
        || raw_path.contains("%3b")
        || raw_path.contains("%3B")
    {
        return Ok((StatusCode::BAD_REQUEST, "Encoded percent or semicolon in path").into_response());
    }

    // Decodificamos URL ANTES de normalizar para que %2e%2e (..) y %2f (/)
    // se interpreten igual que lo hará el backend. Sin esto, el firewall
    // ve segmentos crudos y el backend ve la ruta resuelta → bypass.
    //
    // Decodificación ITERATIVA: un atacante puede doble-codificar (%252e → %2e
    // → .) para que el firewall vea bytes crudos mientras el backend, tras
    // decodificar dos veces, resuelva `..` o `/`. Decodificamos hasta que el
    // path se estabilice; así evaluamos las reglas sobre la forma que el backend
    // realmente resolverá. Si no estabiliza en unas pocas pasadas, el path está
    // anidado de forma sospechosa y lo rechazamos.
    const MAX_DECODE_PASSES: usize = 5;
    let mut decoded = raw_path.to_string();
    let mut stabilized = false;
    for _ in 0..MAX_DECODE_PASSES {
        let next = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8_lossy()
            .into_owned();
        if next == decoded {
            stabilized = true;
            break;
        }
        decoded = next;
    }
    if !stabilized {
        return Ok((StatusCode::BAD_REQUEST, "Path too deeply encoded").into_response());
    }
    let decoded_path: std::borrow::Cow<str> = std::borrow::Cow::Owned(decoded);
    // Si el path contiene bytes no-UTF8, decode_utf8_lossy los reemplaza con
    // U+FFFD. El backend interpreta esos bytes de forma diferente al firewall,
    // permitiendo eludir las reglas. Rechazamos estos paths de forma segura.
    if decoded_path.contains('\u{FFFD}') {
        return Ok((StatusCode::BAD_REQUEST, "Invalid UTF-8 in path").into_response());
    }
    // %00 decodifica a NULL válido UTF-8. El cache_key usa '\0' como separador
    // de campos, por lo que un null en el path puede colisionar campos. Además,
    // muchos backends tratan NULL como terminador de string (path traversal).
    if decoded_path.contains('\0') {
        return Ok((StatusCode::BAD_REQUEST, "Null byte in path").into_response());
    }
    // IIS/.NET interpretan '\' como separador de path. /admin\auth se resolvería
    // a /admin/auth en backend pero el firewall ve un solo segmento "admin\auth".
    // Normalizamos para que el matching coincida con la interpretación del backend.
    let decoded_path = if decoded_path.contains('\\') {
        std::borrow::Cow::Owned(decoded_path.replace('\\', "/"))
    } else {
        decoded_path
    };
    let clean_path = decoded_path.trim_start_matches('/');

    // Normalizamos el path ANTES de evaluar las reglas,
    // para evitar que solicitudes como `/foo/../login` salten las reglas de `/login`.
    // También truncamos cada segmento en `;` para prevenir bypass en backends
    // que procesan path params (Tomcat, Jetty, WSGI: /admin/auth;jsessionid=x).
    let normalized_path: String = clean_path
        .split('/')
        .fold(Vec::new(), |mut parts, segment| {
            let segment = segment.split(';').next().unwrap_or("");
            match segment {
                ".." => {
                    parts.pop();
                }
                "." | "" => {}
                s => parts.push(s),
            }
            parts
        })
        .join("/");

    let path_segments = crate::limiter::PathPattern::split_segments(&normalized_path);
    let query = parts.uri.query().unwrap_or("");
    let method = parts.method;
    let mut headers = parts.headers;
    let real_ip = get_real_ip(&headers, &socket_addr, &state);
    let client_ip = real_ip.to_string();

    // --- 1. LÓGICA DEL FIREWALL (Rate limiting y baneos) ---
    // Se evalúa ANTES de modificar headers para que header:X use valores originales del cliente
    let is_whitelisted = state.whitelist_ips.contains(&real_ip)
        || state.whitelist_nets.iter().any(|net| net.contains(&real_ip));

    if !is_whitelisted {
        for route in &state.routes {
            if route.pattern.matches(&path_segments) {
                for rule in &route.rules {
                    let mut full_cache_key = String::with_capacity(
                        route.path.len() + 1 + client_ip.len() + rule.config.identifiers.len() * 8,
                    );
                    full_cache_key.push_str(&route.path);
                    full_cache_key.push('\0');
                    let mut unresolved_identifier = false;
                    for id in &rule.config.identifiers {
                        if id == "*" {
                            full_cache_key.push_str("GLOBAL");
                        } else if id == "ip" {
                            full_cache_key.push_str(&rate_limit_ip_key(real_ip));
                        } else if let Some(header_name) = id.strip_prefix("header:") {
                            // Usamos SOLO la primera línea del header: el backend
                            // (Servlet/Spring, `getHeader`) también lee la primera, así
                            // que el bucket es el de la identidad con la que se autentica.
                            // Si concatenáramos todas las líneas, un atacante añadiría
                            // una segunda línea con basura para obtener un bucket nuevo
                            // mientras el backend lo sigue autenticando con la primera.
                            //
                            // El valor se normaliza (espacios y esquema de Authorization)
                            // para que variantes que el backend trata como el mismo token
                            // ("Bearer tok", "Bearer  tok", "bearer\ttok") compartan bucket.
                            //
                            // En la key va su hash (tamaño fijo), no el valor: así un
                            // atacante no infla la memoria con valores enormes únicos y
                            // los tokens no quedan guardados en RAM. La semilla es
                            // aleatoria por proceso: no puede fabricar colisiones.
                            match headers
                                .get(header_name)
                                .and_then(|v| normalize_identity(header_name, v.as_bytes()))
                            {
                                Some(identity) => {
                                    let hash = state.identity_hasher.hash_one(&identity[..]);
                                    full_cache_key.push_str(&format!("{:016x}", hash));
                                }
                                None => unresolved_identifier = true,
                            }
                        }
                        full_cache_key.push('\0');
                    }

                    // Si un identificador no se puede resolver, la key sale idéntica para
                    // todos los clientes y la regla deja de ser por cliente: se vuelve un
                    // bucket global que cualquiera puede saturar para denegar el servicio a
                    // todo el mundo. El caso real es el preflight CORS, que el navegador
                    // envía sin Authorization. Omitimos la regla; la ruta sigue cubierta por
                    // las reglas que se identifican por IP.
                    if unresolved_identifier {
                        continue;
                    }

                    if let Some(ban_duration) = state.ban_cache.get(&full_cache_key).await {
                        // No loggeamos full_cache_key: lleva el hash de headers sensibles
                        // (Authorization). Solo route + ip.
                        debug!(
                            "Bloqueado por baneo activo (duración: {:?}) ruta={} ip={}",
                            ban_duration, route.path, client_ip
                        );
                        return Ok((StatusCode::TOO_MANY_REQUESTS, "").into_response());
                    }

                    if rule.limiter.check_key(&full_cache_key).is_err() {
                        let ban_secs = rule.config.on_limit_exceeded.duration_secs;
                        debug!(
                            "Rate limit excedido ruta={} ip={}. Baneando por {}s",
                            route.path, client_ip, ban_secs
                        );

                        // ban_secs == 0 significa "sin baneo persistente": devolvemos 429
                        // para este request pero no insertamos en ban_cache.
                        if ban_secs > 0 {
                            state
                                .ban_cache
                                .insert(full_cache_key, Duration::from_secs(ban_secs))
                                .await;
                        }

                        return Ok((StatusCode::TOO_MANY_REQUESTS, "").into_response());
                    }
                }
                // No break: se evalúan TODAS las rutas que matcheen
            }
        }
    }

    // --- 2. Preparación de headers para el proxy (DESPUÉS del rate limiting) ---
    clean_hop_by_hop_headers(&mut headers);
    // Eliminamos cabeceras de IP-cliente falsificables (Forwarded, True-Client-IP,
    // CF-Connecting-IP, etc.) para que el backend no confíe en un valor spoofeado.
    // x-forwarded-for / x-real-ip se reponen justo debajo con el valor calculado.
    clean_client_ip_headers(&mut headers);

    if let Ok(ip_val) = axum::http::HeaderValue::from_str(&client_ip) {
        // Solo appendeamos a la cadena existente en modo bare-metal (trusted_hops
        // None) cuando el socket viene de un proxy de confianza (red interna). Si
        // el cliente conectó directo desde internet, su X-Forwarded-For es
        // falsificable y debe descartarse: appendearlo permitiría spoofing (ej.
        // cliente envía "127.0.0.1" y backends que confían en left-most lo ven
        // como loopback).
        // En modo plataforma (trusted_hops Some) NUNCA appendeamos, aunque el
        // socket esté en trusted_proxies: el de Cloud Run es 169.254.x.x y la config
        // puede confiar en 169.254.0.0/16, con lo que el backend recibiría
        // "<spoofed>, <real>, <real>" y tomaría el left-most. Mandamos solo la IP
        // calculada.
        let new_forwarded = if state.trusted_hops.is_none()
            && state.is_proxy_trusted(&socket_addr.ip())
        {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|existing| format!("{}, {}", existing, client_ip))
                .and_then(|v| axum::http::HeaderValue::from_str(&v).ok())
                .unwrap_or_else(|| ip_val.clone())
        } else {
            ip_val.clone()
        };
        headers.insert("x-forwarded-for", new_forwarded);
        headers.insert("x-real-ip", ip_val);
    }

    if let Some(hv) = &state.backend_host_header {
        headers.insert("host", hv.clone());
    }

    let base_url = state.backend_url.trim_end_matches('/');

    // Reenviamos el path ORIGINAL (crudo) al backend, no el normalizado/decodificado,
    // para preservar la semántica que esperaba el cliente. La normalización solo
    // se usa para evaluar las reglas del firewall.
    let forward_path = raw_path.trim_start_matches('/');
    let mut backend_url = String::with_capacity(
        base_url.len()
            + 1
            + forward_path.len()
            + if query.is_empty() { 0 } else { 1 + query.len() },
    );
    backend_url.push_str(base_url);
    backend_url.push('/');
    backend_url.push_str(forward_path);
    if !query.is_empty() {
        backend_url.push('?');
        backend_url.push_str(query);
    }

    // MEJORA: Streaming puro de subida
    let req_body = reqwest::Body::wrap_stream(body.into_data_stream());

    let proxy_req = state
        .client
        .request(method, &backend_url)
        .headers(headers)
        .body(req_body);

    match proxy_req.send().await {
        Ok(res) => {
            let mut response_builder = Response::builder().status(res.status());

            // FIX 3: Filtramos cabeceras hop-by-hop del backend sin clonar,
            // incluyendo tokens dinámicos del header Connection (RFC 7230).
            let response_dynamic_tokens = parse_connection_tokens(res.headers());
            for (key, value) in res.headers().iter() {
                let key_str = key.as_str().to_lowercase();
                if !HOP_BY_HOP_HEADERS.contains(&key_str.as_str())
                    && !response_dynamic_tokens.contains(&key_str)
                {
                    response_builder = response_builder.header(key, value);
                }
            }

            // MEJORA: Streaming puro de bajada
            let stream = res.bytes_stream();
            let body = axum::body::Body::from_stream(stream);

            Ok(response_builder
                .body(body)
                .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "error building response").into_response()))
        }
        Err(e) => {
            // without_url: la URL incluye la query (puede llevar OTP o tokens)
            warn!("Error conectando al backend: {}", e.without_url());
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // --- rate_limit_ip_key ---

    #[test]
    fn ip_key_v4_is_unchanged() {
        assert_eq!(rate_limit_ip_key(ip("203.0.113.5")), "203.0.113.5");
        assert_eq!(rate_limit_ip_key(ip("0.0.0.0")), "0.0.0.0");
    }

    #[test]
    fn ip_key_v6_groups_by_64() {
        assert_eq!(rate_limit_ip_key(ip("2001:db8:1:2::a")), "2001:db8:1:2::/64");
        assert_eq!(rate_limit_ip_key(ip("2001:db8:1:2:ffff::b")), "2001:db8:1:2::/64");
    }

    #[test]
    fn ip_key_v6_other_64_differs() {
        assert_ne!(
            rate_limit_ip_key(ip("2001:db8:1:3::a")),
            rate_limit_ip_key(ip("2001:db8:1:2::a"))
        );
    }

    #[test]
    fn ip_key_v6_is_lowercase_without_leading_zeros() {
        assert_eq!(rate_limit_ip_key(ip("2001:0DB8:000A:00B::1")), "2001:db8:a:b::/64");
    }

    #[test]
    fn ip_key_v6_mapped_v4_uses_the_v4_key() {
        assert_eq!(rate_limit_ip_key(ip("::ffff:203.0.113.7")), "203.0.113.7");
        // Misma key que la IPv4 nativa: no hay un bucket aparte por forma de escritura
        assert_eq!(
            rate_limit_ip_key(ip("::ffff:203.0.113.7")),
            rate_limit_ip_key(ip("203.0.113.7"))
        );
    }

    #[test]
    fn ip_key_v6_loopback_is_not_mapped() {
        assert_eq!(rate_limit_ip_key(ip("::1")), "0:0:0:0::/64");
    }

    // --- normalize_identity ---

    #[test]
    fn identity_authorization_variants_are_equal() {
        let base = normalize_identity("authorization", b"Bearer tok");
        assert!(base.is_some());
        for variant in [
            &b"Bearer  tok"[..],
            b"Bearer \ttok",
            b"bearer tok",
            b"BEARER tok  ",
            b"  Bearer tok",
        ] {
            assert_eq!(
                normalize_identity("authorization", variant),
                base,
                "variante {:?}",
                String::from_utf8_lossy(variant)
            );
        }
    }

    #[test]
    fn identity_different_tokens_differ() {
        assert_ne!(
            normalize_identity("authorization", b"Bearer a"),
            normalize_identity("authorization", b"Bearer b")
        );
    }

    #[test]
    fn identity_only_the_scheme_is_case_insensitive() {
        assert_ne!(
            normalize_identity("authorization", b"Bearer Tok"),
            normalize_identity("authorization", b"Bearer tok")
        );
    }

    #[test]
    fn identity_authorization_name_is_matched_ignoring_case() {
        assert_eq!(
            normalize_identity("Authorization", b"BEARER tok"),
            normalize_identity("authorization", b"bearer tok")
        );
    }

    #[test]
    fn identity_authorization_single_part_keeps_case() {
        // Sin scheme + credencial no hay scheme que pasar a minúsculas
        assert_ne!(
            normalize_identity("authorization", b"TokenAbc"),
            normalize_identity("authorization", b"tokenabc")
        );
    }

    #[test]
    fn identity_empty_or_blank_is_none() {
        assert_eq!(normalize_identity("authorization", b""), None);
        assert_eq!(normalize_identity("authorization", b"  \t "), None);
        assert_eq!(normalize_identity("x-api-key", b""), None);
    }

    #[test]
    fn identity_other_headers_keep_first_word_case() {
        assert_ne!(
            normalize_identity("x-api-key", b"Key abc"),
            normalize_identity("x-api-key", b"key abc")
        );
        // La normalización de espacios sí aplica a cualquier header
        assert_eq!(
            normalize_identity("x-api-key", b"Key  abc"),
            normalize_identity("x-api-key", b"Key abc")
        );
    }

    #[test]
    fn identity_normalized_form_is_single_space_joined() {
        assert_eq!(
            normalize_identity("authorization", b" BEARER \t Tok\t").unwrap(),
            b"bearer Tok".to_vec()
        );
        assert_eq!(
            normalize_identity("authorization", b"Digest realm=x Nonce=Y").unwrap(),
            b"digest realm=x Nonce=Y".to_vec()
        );
        assert_eq!(normalize_identity("x-api-key", b" A  B ").unwrap(), b"A B".to_vec());
    }

    #[test]
    fn identity_non_ascii_bytes_are_not_skipped() {
        // Un valor fuera de ASCII visible sigue identificando al cliente (se
        // limita por su hash) en vez de saltarse la regla.
        assert!(normalize_identity("authorization", b"Bearer t\xffk").is_some());
    }
}
