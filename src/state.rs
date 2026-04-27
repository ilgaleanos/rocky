use crate::config::AppConfig;
use crate::limiter::ActiveRoute;
use ipnet::IpNet;
use moka::future::Cache;
use moka::Expiry;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// --- ESTRUCTURA PARA EL MANEJO DE EXPIRACIÓN DE BANEOS ---
pub struct BanExpiry;

impl Expiry<String, Duration> for BanExpiry {
    fn expire_after_create(&self, _k: &String, v: &Duration, _c: Instant) -> Option<Duration> {
        Some(*v)
    }

    fn expire_after_update(
        &self,
        _k: &String,
        v: &Duration,
        _u: Instant,
        _d: Option<Duration>,
    ) -> Option<Duration> {
        Some(*v)
    }

    // Configuración específica para moka v0.12.x
    fn expire_after_read(
        &self,
        _key: &String,
        _value: &Duration,
        _read_at: Instant,
        duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        duration_until_expiry
    }
}

// --- ESTADO GLOBAL DE LA APLICACIÓN ---
pub struct AppState {
    pub backend_url: String,
    pub backend_host_header: Option<axum::http::HeaderValue>,
    pub whitelist_ips: HashSet<IpAddr>,
    pub whitelist_nets: Vec<IpNet>,
    pub trusted_proxy_ips: HashSet<IpAddr>,
    pub trusted_proxy_nets: Vec<IpNet>,
    pub routes: Vec<ActiveRoute>,
    pub ban_cache: Cache<String, Duration>,
    pub client: reqwest::Client,
}

impl AppState {
    /// Indica si una IP corresponde a un proxy de confianza configurado.
    /// Loopback siempre se considera trusted (health checks locales / sidecars).
    pub fn is_proxy_trusted(&self, ip: &IpAddr) -> bool {
        ip.is_loopback()
            || self.trusted_proxy_ips.contains(ip)
            || self.trusted_proxy_nets.iter().any(|n| n.contains(ip))
    }
}

impl AppState {
    pub fn new(config: AppConfig) -> Arc<Self> {
        // 1. CONSTRUCCIÓN DE RUTAS ACTIVAS
        // Todas las rutas que matcheen se evalúan, no se necesita ordenar por especificidad.
        let mut active_routes = Vec::new();
        for route_config in config.routes {
            match ActiveRoute::new(route_config) {
                Ok(route) => active_routes.push(route),
                Err(e) => {
                    tracing::error!("❌ Error en configuración de ruta: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // 2. CACHÉ DE BANEOS: Usamos Moka con la política de expiración personalizada.
        // Capacidad alta para mitigar eviction attack: un atacante que rota valores
        // de header (ej. tokens Authorization únicos) llenaría el cache y podría
        // evictar baneos legítimos. Moka usa TinyLFU, que es resistente a scan
        // attacks (priorizando entradas frecuentemente accedidas), pero la cota
        // máxima sigue importando bajo presión sostenida. ~500k ≈ 50-100 MB.
        let ban_cache: Cache<String, Duration> = Cache::builder()
            .max_capacity(500_000)
            .expire_after(BanExpiry)
            .build();

        // 3. WHITELIST: IPs exactas en HashSet (O(1)), rangos CIDR en Vec.
        let mut whitelist_ips = HashSet::new();
        let mut whitelist_nets = Vec::new();
        for ip_str in config.global_whitelist {
            if ip_str.contains('/') {
                match ip_str.parse::<IpNet>() {
                    Ok(net) => whitelist_nets.push(net),
                    Err(e) => tracing::warn!("⚠️ CIDR inválido en whitelist '{}': {}", ip_str, e),
                }
            } else {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip) => { whitelist_ips.insert(ip); }
                    Err(e) => tracing::warn!("⚠️ IP inválida en whitelist '{}': {}", ip_str, e),
                }
            }
        }

        // 3.b TRUSTED PROXIES: lista explícita de proxies cuya cadena XFF/X-Real-IP
        // es confiable. Sin esto, atacantes desde redes privadas pueden falsificar
        // su IP. Loopback se asume trusted aparte (manejado en is_proxy_trusted).
        let mut trusted_proxy_ips = HashSet::new();
        let mut trusted_proxy_nets = Vec::new();
        for ip_str in &config.trusted_proxies {
            if ip_str.contains('/') {
                match ip_str.parse::<IpNet>() {
                    Ok(net) => trusted_proxy_nets.push(net),
                    Err(e) => tracing::warn!("⚠️ CIDR inválido en trusted_proxies '{}': {}", ip_str, e),
                }
            } else {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip) => { trusted_proxy_ips.insert(ip); }
                    Err(e) => tracing::warn!("⚠️ IP inválida en trusted_proxies '{}': {}", ip_str, e),
                }
            }
        }
        if config.trusted_proxies.is_empty() {
            tracing::warn!(
                "⚠️ trusted_proxies vacío: se ignorarán todos los X-Forwarded-For/X-Real-IP. \
                 Si estás detrás de un LB, los clientes aparecerán como la IP del LB."
            );
        }

        // 4. CLIENTE HTTP PROFESIONAL: Configuración con Timeouts y Pool de conexiones.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10)) // No esperar más de 10s para conectar.
            .timeout(Duration::from_secs(3600)) // Timeout total por request (incluye respuesta completa).
            .pool_idle_timeout(Duration::from_secs(90)) // Reutilizar conexiones para bajar latencia.
            .tcp_nodelay(true) // Optimizar para baja latencia (desactiva algoritmo de Nagle).
            .danger_accept_invalid_certs(false) // Mantener seguridad SSL estricta.
            .build()
            .expect("No se pudo inicializar el cliente HTTP");

        // Pre-parseo del Host header del backend (evita parsear la URL en cada request)
        let backend_host_header = url::Url::parse(&config.backend_url)
            .ok()
            .and_then(|u| {
                u.host_str().map(|host| {
                    if let Some(port) = u.port() {
                        format!("{}:{}", host, port)
                    } else {
                        host.to_string()
                    }
                })
            })
            .and_then(|h| axum::http::HeaderValue::from_str(&h).ok());

        // Si no se pudo derivar el Host del backend, no arrancamos:
        // el Host del cliente se reenviaría al backend, permitiendo SSRF/
        // routing hijack en backends con vhost. Mejor fallar al inicio.
        let backend_host_header = match backend_host_header {
            Some(h) => h,
            None => {
                tracing::error!(
                    "❌ No se pudo derivar Host header de backend_url '{}'. \
                     Verifica que la URL sea válida (ej. http://backend:8080)",
                    config.backend_url
                );
                std::process::exit(1);
            }
        };

        Arc::new(Self {
            backend_url: config.backend_url,
            backend_host_header: Some(backend_host_header),
            whitelist_ips,
            whitelist_nets,
            trusted_proxy_ips,
            trusted_proxy_nets,
            routes: active_routes,
            ban_cache,
            client,
        })
    }
}
