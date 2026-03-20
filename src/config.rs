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
    pub routes: Vec<RouteConfig>,
}

impl AppConfig {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        info!("Cargando configuración desde: {}", path);
        let contents = fs::read_to_string(path)?;
        let config: AppConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }
}
