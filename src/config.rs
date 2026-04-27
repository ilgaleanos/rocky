use serde::Deserialize;
use std::fs;
use tracing::info;

#[derive(Deserialize, Clone, Debug)]
pub struct BanConfig {
    pub duration_secs: u64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RuleConfig {
    pub identifiers: Vec<String>,
    pub limit: u32,
    pub window_secs: u64,
    pub on_limit_exceeded: BanConfig,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RouteConfig {
    pub path: String,
    pub rules: Vec<RuleConfig>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct AppConfig {
    pub backend_url: String,
    pub global_whitelist: Vec<String>,
    /// IPs/CIDRs de proxies de confianza. Solo los headers X-Forwarded-For y
    /// X-Real-IP de conexiones que vengan desde estas IPs son considerados
    /// confiables. Loopback siempre se considera trusted (health checks).
    /// Si está vacío, se ignoran TODOS los headers de IP del cliente.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    pub routes: Vec<RouteConfig>,
}

// Cotas defensivas: evitan que un config.json malicioso/erróneo asigne
// memoria masiva (DashMap interno de governor) o ventanas imposibles.
const MAX_LIMIT: u32 = 1_000_000;
const MAX_WINDOW_SECS: u64 = 60 * 60 * 24 * 30; // 30 días
const MAX_BAN_SECS: u64 = 60 * 60 * 24 * 365; // 1 año

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Cargando configuración desde: {}", path);
        let contents = fs::read_to_string(path)?;
        let config: AppConfig = serde_json::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for route in &self.routes {
            for rule in &route.rules {
                if rule.limit == 0 || rule.limit > MAX_LIMIT {
                    return Err(format!(
                        "ruta '{}': limit={} fuera de rango (1..={})",
                        route.path, rule.limit, MAX_LIMIT
                    ));
                }
                if rule.window_secs == 0 || rule.window_secs > MAX_WINDOW_SECS {
                    return Err(format!(
                        "ruta '{}': window_secs={} fuera de rango (1..={})",
                        route.path, rule.window_secs, MAX_WINDOW_SECS
                    ));
                }
                if rule.on_limit_exceeded.duration_secs > MAX_BAN_SECS {
                    return Err(format!(
                        "ruta '{}': duration_secs={} excede máximo {}",
                        route.path, rule.on_limit_exceeded.duration_secs, MAX_BAN_SECS
                    ));
                }
            }
        }
        Ok(())
    }
}
