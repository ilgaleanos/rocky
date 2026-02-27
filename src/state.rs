use crate::config::AppConfig;
use crate::limiter::ActiveRule;
use ipnet::IpNet;
use moka::future::Cache;
use moka::Expiry;
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
    pub whitelist: Vec<IpNet>,
    pub rules: Vec<ActiveRule>,
    pub ban_cache: Cache<String, Duration>,
    pub client: reqwest::Client,
}

impl AppState {
    pub fn new(mut config: AppConfig) -> Arc<Self> {
        // 1. ORDENAMIENTO DE REGLAS: Priorizamos las rutas más específicas (más largas)
        // para que "/api/login" se evalúe antes que "/".
        config
            .rules
            .sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

        let mut active_rules = Vec::new();
        for rule_config in config.rules {
            active_rules.push(ActiveRule::new(rule_config).unwrap());
        }

        // 2. CACHÉ DE BANEOS: Usamos Moka con la política de expiración personalizada.
        let ban_cache: Cache<String, Duration> = Cache::builder().expire_after(BanExpiry).build();

        // 3. WHITELIST: Convertimos el array a subredes (IpNet).
        let mut whitelist = Vec::new();
        for ip_str in config.global_whitelist {
            if ip_str.contains('/') {
                match ip_str.parse::<IpNet>() {
                    Ok(net) => whitelist.push(net),
                    Err(e) => tracing::warn!("⚠️ CIDR inválido en whitelist '{}': {}", ip_str, e),
                }
            } else {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip) => whitelist.push(IpNet::from(ip)),
                    Err(e) => tracing::warn!("⚠️ IP inválida en whitelist '{}': {}", ip_str, e),
                }
            }
        }

        // 4. CLIENTE HTTP PROFESIONAL: Configuración con Timeouts y Pool de conexiones.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10)) // No esperar más de 10s para conectar.
            .pool_idle_timeout(Duration::from_secs(90)) // Reutilizar conexiones para bajar latencia.
            .tcp_nodelay(true) // Optimizar para baja latencia (desactiva algoritmo de Nagle).
            .danger_accept_invalid_certs(false) // Mantener seguridad SSL estricta.
            .build()
            .expect("No se pudo inicializar el cliente HTTP");

        Arc::new(Self {
            backend_url: config.backend_url,
            whitelist,
            rules: active_rules,
            ban_cache,
            client,
        })
    }
}
