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

    // Verificamos si la conexión directa viene de una red de confianza (loopback o privada).
    // Si viene de Internet público, NO confiamos en los headers.
    let is_trusted_proxy = direct_ip.is_loopback()
        || match direct_ip {
            IpAddr::V4(ipv4) => ipv4.is_private(),
            IpAddr::V6(_) => false,
        };

    if is_trusted_proxy {
        if let Some(x_forwarded) = headers.get("x-forwarded-for") {
            if let Ok(ip_str) = x_forwarded.to_str() {
                if let Some(real_ip) = ip_str.split(',').next() {
                    return real_ip.trim().to_string();
                }
            }
        }
        if let Some(x_real_ip) = headers.get("x-real-ip") {
            if let Ok(ip_str) = x_real_ip.to_str() {
                return ip_str.trim().to_string();
            }
        }
    }

    // Si no es un proxy de confianza, devolvemos la IP de la conexión de red directa.
    direct_ip.to_string()
}

pub async fn firewall_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(socket_addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Response, StatusCode> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("");

    let method = req.method().clone();
    let mut headers = req.headers().clone();
    let client_ip = get_real_ip(&headers, &socket_addr);

    // FIX 3: Limpiamos cabeceras de red antes de enviarlas al backend
    clean_hop_by_hop_headers(&mut headers);

    // Inyectamos adecuadamente la IP real del cliente al backend
    if let Ok(ip_val) = axum::http::HeaderValue::from_str(&client_ip) {
        headers.insert("x-forwarded-for", ip_val.clone());
        headers.insert("x-real-ip", ip_val);
    }

    // --- 1. LÓGICA DEL FIREWALL (Rate limiting y baneos) ---
    if !state.whitelist.contains(&client_ip) {
        for rule in &state.rules {
            if path.starts_with(&rule.config.path_prefix) {
                let mut cache_key = String::new();
                for id in &rule.config.identifiers {
                    if id == "*" {
                        cache_key.push_str("GLOBAL");
                    } else if id == "ip" {
                        cache_key.push_str(&client_ip);
                    } else if id.starts_with("header:") {
                        let header_name = id.trim_start_matches("header:");
                        if let Some(val) = headers.get(header_name) {
                            cache_key.push_str(val.to_str().unwrap_or(""));
                        }
                    }
                    cache_key.push('|');
                }

                let full_cache_key = format!("{}|{}", rule.config.path_prefix, cache_key);

                if state.ban_cache.contains_key(&full_cache_key) {
                    warn!("Bloqueado por cuarentena: {}", full_cache_key);
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
                        .insert(full_cache_key.clone(), duration)
                        .await;

                    return Ok((StatusCode::TOO_MANY_REQUESTS, "").into_response());
                }
                break;
            }
        }
    }

    // --- 2. LÓGICA DEL PROXY REVERSO (Con Streaming y Fix de URL) ---

    // FIX 2: Evitamos la doble barra "/" limpiando el final de la URL del backend
    let base_url = state.backend_url.trim_end_matches('/');
    let clean_path = path.trim_start_matches('/');
    let backend_url = if query.is_empty() {
        format!("{}/{}", base_url, clean_path)
    } else {
        format!("{}/{}?{}", base_url, clean_path, query)
    };

    // MEJORA: Streaming puro de subida
    let req_body = reqwest::Body::wrap_stream(req.into_body().into_data_stream());

    let proxy_req = state
        .client
        .request(method, &backend_url)
        .headers(headers)
        .body(req_body);

    match proxy_req.send().await {
        Ok(res) => {
            let mut response_builder = Response::builder().status(res.status());

            // FIX 3: Limpiamos cabeceras de red del backend antes de dárselas al cliente
            let mut res_headers = res.headers().clone();
            clean_hop_by_hop_headers(&mut res_headers);

            for (key, value) in res_headers.iter() {
                response_builder = response_builder.header(key, value);
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
