use crate::state::AppState;
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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

// Protección contra IP Spoofing
fn get_real_ip(headers: &HeaderMap, socket_addr: &SocketAddr) -> String {
    let direct_ip = socket_addr.ip();

    // Verificamos si la conexión directa viene de una red de confianza (loopback, privada o link-local).
    // GCP Cloud Run usa IPs de link-local (169.254.x.x) para sus proxies.
    // Si viene de Internet público, NO confiamos en los headers.
    let is_trusted_proxy = direct_ip.is_loopback()
        || match direct_ip {
            IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_link_local(),
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        };

    if is_trusted_proxy {
        if let Some(x_forwarded) = headers.get("x-forwarded-for") {
            if let Ok(ip_str) = x_forwarded.to_str() {
                if let Some(real_ip) = ip_str.split(',').next() {
                    let final_ip = real_ip.trim().to_string();
                    tracing::debug!(
                        "get_real_ip proxy (trusted {}): Obteniendo X-Forwarded-For => {}",
                        direct_ip,
                        final_ip
                    );
                    return final_ip;
                }
            }
        }
        if let Some(x_real_ip) = headers.get("x-real-ip") {
            if let Ok(ip_str) = x_real_ip.to_str() {
                let final_ip = ip_str.trim().to_string();
                tracing::debug!(
                    "get_real_ip proxy (trusted {}): Obteniendo X-Real-Ip => {}",
                    direct_ip,
                    final_ip
                );
                return final_ip;
            }
        }
    }

    // Si no es un proxy de confianza, devolvemos la IP de la conexión de red directa.
    let final_ip = direct_ip.to_string();
    tracing::debug!(
        "get_real_ip fallback: Usando direct_ip: {} porque el proxy no era de confianza ({:?})",
        final_ip,
        direct_ip
    );
    final_ip
}

pub async fn firewall_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, StatusCode> {
    // Desarmamos el request para tomar ownership sin clonar
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("");
    let method = parts.method;
    let mut headers = parts.headers;
    let client_ip = get_real_ip(&headers, &socket_addr);

    // --- 1. LÓGICA DEL FIREWALL (Rate limiting y baneos) ---
    // Se evalúa ANTES de modificar headers para que header:X use valores originales del cliente
    let is_whitelisted = client_ip
        .parse::<std::net::IpAddr>()
        .map(|ip| state.whitelist_ips.contains(&ip) || state.whitelist_nets.iter().any(|net| net.contains(&ip)))
        .unwrap_or(false);

    if !is_whitelisted {
        for rule in &state.rules {
            if path.starts_with(&rule.config.path_prefix) {
                let estimated_len = rule.config.path_prefix.len() + 1 + client_ip.len() + rule.config.identifiers.len() * 8;
                let mut full_cache_key = String::with_capacity(estimated_len);
                full_cache_key.push_str(&rule.config.path_prefix);
                full_cache_key.push('|');
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
                    full_cache_key.push('|');
                }

                if let Some(ban_duration) = state.ban_cache.get(&full_cache_key).await {
                    warn!("Bloqueado por cuarentena ({:?}s restantes): {}", ban_duration, full_cache_key);
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

                    state
                        .ban_cache
                        .insert(full_cache_key, duration)
                        .await;

                    return Ok((StatusCode::TOO_MANY_REQUESTS, "").into_response());
                }
                break;
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
    let clean_path = path.trim_start_matches('/');

    // FIX SSRF: Normalizamos el path para evitar path traversal (/../)
    let normalized_path: String = clean_path
        .split('/')
        .fold(Vec::new(), |mut parts, segment| {
            match segment {
                ".." => { parts.pop(); }
                "." | "" => {}
                s => parts.push(s),
            }
            parts
        })
        .join("/");

    let backend_url = if query.is_empty() {
        format!("{}/{}", base_url, normalized_path)
    } else {
        format!("{}/{}?{}", base_url, normalized_path, query)
    };

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
