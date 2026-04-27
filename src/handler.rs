use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
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
fn get_real_ip(headers: &HeaderMap, socket_addr: &SocketAddr, state: &AppState) -> String {
    let direct_ip = socket_addr.ip();

    // Si la conexión NO viene de un proxy de confianza configurado, la IP directa
    // es la real. Cualquier XFF/X-Real-IP que envíe el cliente es falsificable.
    if !state.is_proxy_trusted(&direct_ip) {
        return direct_ip.to_string();
    }

    // 1. Prioridad: X-Real-IP (Google Cloud LB suele sobreescribirla con la IP del cliente)
    if let Some(x_real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = x_real_ip.to_str() {
            let candidate = ip_str.trim();
            if candidate.parse::<std::net::IpAddr>().is_ok() {
                return candidate.to_string();
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
                return ip.to_string();
            }

            // Fallback: si todas las IPs parseables son proxies confiables,
            // devolvemos la IP directa en vez de un string sin validar.
        }
    }

    direct_ip.to_string()
}

pub async fn firewall_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, StatusCode> {
    // Desarmamos el request para tomar ownership sin clonar
    let (parts, body) = req.into_parts();
    let raw_path = parts.uri.path();

    // Decodificamos URL ANTES de normalizar para que %2e%2e (..) y %2f (/)
    // se interpreten igual que lo hará el backend. Sin esto, el firewall
    // ve segmentos crudos y el backend ve la ruta resuelta → bypass.
    let decoded_path = percent_encoding::percent_decode_str(raw_path)
        .decode_utf8_lossy();
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
    let client_ip = get_real_ip(&headers, &socket_addr, &state);

    // --- 1. LÓGICA DEL FIREWALL (Rate limiting y baneos) ---
    // Se evalúa ANTES de modificar headers para que header:X use valores originales del cliente
    let is_whitelisted = client_ip
        .parse::<std::net::IpAddr>()
        .map(|ip| {
            state.whitelist_ips.contains(&ip)
                || state.whitelist_nets.iter().any(|net| net.contains(&ip))
        })
        .unwrap_or(false);

    if !is_whitelisted {
        for route in &state.routes {
            if route.pattern.matches(&path_segments) {
                for rule in &route.rules {
                    let mut full_cache_key = String::with_capacity(
                        route.path.len() + 1 + client_ip.len() + rule.config.identifiers.len() * 8,
                    );
                    full_cache_key.push_str(&route.path);
                    full_cache_key.push('\0');
                    for id in &rule.config.identifiers {
                        if id == "*" {
                            full_cache_key.push_str("GLOBAL");
                        } else if id == "ip" {
                            full_cache_key.push_str(&client_ip);
                        } else if id.starts_with("header:") {
                            let header_name = id.trim_start_matches("header:");
                            if let Some(val) = headers.get(header_name) {
                                if let Ok(s) = val.to_str() {
                                    full_cache_key.push_str(s);
                                }
                            }
                        }
                        full_cache_key.push('\0');
                    }

                    if let Some(ban_duration) = state.ban_cache.get(&full_cache_key).await {
                        // No loggeamos full_cache_key: puede contener valores de headers
                        // sensibles (Authorization). Solo route + ip.
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

    if let Ok(ip_val) = axum::http::HeaderValue::from_str(&client_ip) {
        // Solo appendeamos a la cadena existente si el socket viene de un proxy
        // de confianza (Cloud Run/GFE, red interna). Si el cliente conectó directo
        // desde internet, su X-Forwarded-For es falsificable y debe descartarse:
        // appendearlo permitiría spoofing (ej. cliente envía "127.0.0.1" y backends
        // que confían en left-most lo ven como loopback).
        let new_forwarded = if state.is_proxy_trusted(&socket_addr.ip()) {
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
            warn!("Error conectando al backend: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
