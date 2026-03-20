use crate::config::{RouteConfig, RuleConfig};
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::time::Duration;

/// Alias para el limitador de Governor que usa llaves (Strings) dinámicas.
pub type DynKeyLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

// --- PATH PATTERN MATCHING ---

/// Patrón compilado para matching de rutas.
pub enum PathPattern {
    /// Match exacto: "/admin/auth" solo matchea "/admin/auth"
    Exact(Vec<String>),
    /// Comodín de un nivel: "/api/*" matchea "/api/foo" pero no "/api/foo/bar"
    SingleWild(Vec<String>),
    /// Comodín recursivo: "/api/**" matchea "/api/foo" y "/api/foo/bar/baz"
    GlobWild(Vec<String>),
}

impl PathPattern {
    pub fn compile(path: &str) -> Self {
        if path == "/**" {
            PathPattern::GlobWild(Vec::new())
        } else if path.ends_with("/**") {
            let prefix = path.trim_end_matches("/**");
            let segments = prefix.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
            PathPattern::GlobWild(segments)
        } else if path.ends_with("/*") {
            let prefix = path.trim_end_matches("/*");
            let segments = prefix.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
            PathPattern::SingleWild(segments)
        } else {
            let segments = path.split('/').filter(|s| !s.is_empty()).map(String::from).collect();
            PathPattern::Exact(segments)
        }
    }

    pub fn matches(&self, segments: &[&str]) -> bool {
        match self {
            PathPattern::Exact(pat_segments) => {
                segments.len() == pat_segments.len()
                    && pat_segments.iter().zip(segments.iter()).all(|(p, r)| p == *r)
            }
            PathPattern::SingleWild(prefix_segments) => {
                segments.len() == prefix_segments.len() + 1
                    && prefix_segments.iter().zip(segments.iter()).all(|(p, r)| p == *r)
            }
            PathPattern::GlobWild(prefix_segments) => {
                if prefix_segments.is_empty() {
                    return true;
                }
                segments.len() >= prefix_segments.len()
                    && prefix_segments.iter().zip(segments.iter()).all(|(p, r)| p == *r)
            }
        }
    }

    /// Divide un path en segmentos. Llamar una sola vez por request.
    pub fn split_segments(path: &str) -> Vec<&str> {
        path.split('/').filter(|s| !s.is_empty()).collect()
    }
}

// --- ACTIVE RULE (un limitador individual) ---

pub struct ActiveRule {
    pub config: RuleConfig,
    pub limiter: DynKeyLimiter,
}

impl ActiveRule {
    pub fn new(config: RuleConfig, route_path: &str) -> Result<Self, String> {
        let quota = Quota::with_period(Duration::from_secs(config.window_secs))
            .ok_or_else(|| {
                format!(
                    "El periodo de la ventana ({}s) es inválido para la ruta '{}'",
                    config.window_secs, route_path
                )
            })?
            .allow_burst(NonZeroU32::new(config.limit).ok_or_else(|| {
                format!(
                    "El límite ({}) debe ser mayor a 0 para la ruta '{}'",
                    config.limit, route_path
                )
            })?);

        let limiter = RateLimiter::dashmap(quota);
        Ok(Self { config, limiter })
    }
}

// --- ACTIVE ROUTE (una ruta con su patrón y múltiples reglas) ---

pub struct ActiveRoute {
    pub path: String,
    pub pattern: PathPattern,
    pub rules: Vec<ActiveRule>,
}

impl ActiveRoute {
    pub fn new(config: RouteConfig) -> Result<Self, String> {
        let pattern = PathPattern::compile(&config.path);
        let mut rules = Vec::new();
        for rule_config in config.rules {
            rules.push(ActiveRule::new(rule_config, &config.path)?);
        }
        Ok(Self {
            path: config.path,
            pattern,
            rules,
        })
    }
}
