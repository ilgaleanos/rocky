use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{info, warn};

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

fn clean_hop_by_hop_headers(headers: &mut HeaderMap) {
    for header in HOP_BY_HOP_HEADERS {
        headers.remove(*header);
    }
}

// --- PROTECCIÓN CONTRA IP SPOOFING (Capa de Confianza) ---

/// Determina si una IP pertenece a una red de confianza (infraestructura propia o de Google).
fn is_ip_trusted(ip: &std::net::IpAddr) -> bool {
    ip.is_loopback()
        || match ip {
            std::net::IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_link_local(),
            std::net::IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // unique-local
            }
        }
}

/// Obtiene la IP real del cliente evitando suplantaciones en entornos con proxies (Cloud Run/GFE).
fn get_real_ip(headers: &HeaderMap, socket_addr: &SocketAddr) -> String {
    let direct_ip = socket_addr.ip();

    // Si la conexión NO viene de un proxy interno, la IP directa es la real.
    if !is_ip_trusted(&direct_ip) {
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
    // Cloud Run/GCP añaden IPs al FINAL. El cliente real es el último que NO es de Google.
    if let Some(x_forwarded) = headers.get("x-forwarded-for") {
        if let Ok(ip_str) = x_forwarded.to_str() {
            let real_ip = ip_str
                .split(',')
                .rev()
                .map(|s| s.trim())
                .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
                .find(|ip| !is_ip_trusted(ip));

            if let Some(ip) = real_ip {
                return ip.to_string();
            }

            // Fallback: Si todos son internos, tomamos el extremo izquierdo.
            if let Some(first) = ip_str.split(',').next() {
                return first.trim().to_string();
            }
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

    // Normalizamos el path para el matching (limpieza de slash final)
    let match_path = if raw_path.len() > 1 && raw_path.ends_with('/') {
        &raw_path[..raw_path.len() - 1]
    } else {
        raw_path
    };
    let path_segments = crate::limiter::PathPattern::split_segments(match_path);
    let query = parts.uri.query().unwrap_or("");
    let method = parts.method;
    let mut headers = parts.headers;
    let client_ip = get_real_ip(&headers, &socket_addr);

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
                                full_cache_key.push_str(val.to_str().unwrap_or(""));
                            }
                        }
                        full_cache_key.push('\0');
                    }

                    if let Some(ban_duration) = state.ban_cache.get(&full_cache_key).await {
                        warn!(
                            "Bloqueado por baneo activo (configuración original: {:?}): {}",
                            ban_duration, full_cache_key
                        );
                        return Ok((StatusCode::TOO_MANY_REQUESTS, "").into_response());
                    }

                    if rule.limiter.check_key(&full_cache_key).is_err() {
                        let ban_secs = rule.config.on_limit_exceeded.duration_secs;
                        info!(
                            "Rate limit excedido para: {}. Baneando por {}s",
                            full_cache_key, ban_secs
                        );

                        let duration = if ban_secs > 0 {
                            Duration::from_secs(ban_secs)
                        } else {
                            Duration::from_secs(60 * 60 * 24 * 365 * 10)
                        };

                        state.ban_cache.insert(full_cache_key, duration).await;

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
        headers.insert("x-forwarded-for", ip_val.clone());
        headers.insert("x-real-ip", ip_val);
    }

    if let Some(hv) = &state.backend_host_header {
        headers.insert("host", hv.clone());
    }

    // --- 2. LÓGICA DEL PROXY REVERSO (Con Streaming y Fix de URL) ---

    // FIX 2: Evitamos la doble barra "/" limpiando el final de la URL del backend
    let base_url = state.backend_url.trim_end_matches('/');
    let clean_path = raw_path.trim_start_matches('/');

    // FIX SSRF: Normalizamos el path para evitar path traversal (/../)
    let normalized_path: String = clean_path
        .split('/')
        .fold(Vec::new(), |mut parts, segment| {
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

    let mut backend_url = String::with_capacity(
        base_url.len()
            + 1
            + normalized_path.len()
            + if query.is_empty() { 0 } else { 1 + query.len() },
    );
    backend_url.push_str(base_url);
    backend_url.push('/');
    backend_url.push_str(&normalized_path);
    if !query.is_empty() {
        backend_url.push('?');
        backend_url.push_str(query);
    }

    // MEJORA: Streaming puro de subida
    let req_body = reqwest::Body::wrap_stream(axum::body::Body::new(body).into_data_stream());

    let proxy_req = state
        .client
        .request(method, &backend_url)
        .headers(headers)
        .body(req_body);

    match proxy_req.send().await {
        Ok(res) => {
            let mut response_builder = Response::builder().status(res.status());

            // FIX 3: Filtramos cabeceras hop-by-hop del backend sin clonar
            for (key, value) in res.headers().iter() {
                if !HOP_BY_HOP_HEADERS.contains(&key.as_str()) {
                    response_builder = response_builder.header(key, value);
                }
            }

            // MEJORA: Streaming puro de bajada
            let stream = res.bytes_stream();
            let body = axum::body::Body::from_stream(stream);

            Ok(response_builder.body(body).unwrap())
        }
        Err(e) => {
            warn!("Error conectando al backend: {}", e);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}
