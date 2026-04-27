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
    pub fn compile(path: &str) -> Result<Self, String> {
        // Rechazar wildcards en medio del patrón. Solo se permiten al final:
        // /api/auth/*  (un nivel)  o  /api/auth/**  (recursivo) o /** (todo)
        if path.contains('*')
            && !path.ends_with("/*")
            && !path.ends_with("/**")
            && path != "/**"
        {
            return Err(format!(
                "Patrón '{}' inválido: los wildcards solo se admiten al final como /* o /**",
                path
            ));
        }

        if path == "/**" {
            Ok(PathPattern::GlobWild(Vec::new()))
        } else if path.ends_with("/**") {
            let prefix = path.trim_end_matches("/**");
            let segments = prefix
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            Ok(PathPattern::GlobWild(segments))
        } else if path.ends_with("/*") {
            let prefix = path.trim_end_matches("/*");
            let segments = prefix
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            Ok(PathPattern::SingleWild(segments))
        } else {
            let segments = path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            Ok(PathPattern::Exact(segments))
        }
    }

    pub fn matches(&self, segments: &[&str]) -> bool {
        match self {
            PathPattern::Exact(pat_segments) => {
                segments.len() == pat_segments.len()
                    && pat_segments
                        .iter()
                        .zip(segments.iter())
                        .all(|(p, r)| p == *r)
            }
            PathPattern::SingleWild(prefix_segments) => {
                segments.len() == prefix_segments.len() + 1
                    && prefix_segments
                        .iter()
                        .zip(segments.iter())
                        .all(|(p, r)| p == *r)
            }
            PathPattern::GlobWild(prefix_segments) => {
                if prefix_segments.is_empty() {
                    return true;
                }
                segments.len() >= prefix_segments.len()
                    && prefix_segments
                        .iter()
                        .zip(segments.iter())
                        .all(|(p, r)| p == *r)
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
        let burst = NonZeroU32::new(config.limit).ok_or_else(|| {
            format!(
                "El límite ({}) debe ser mayor a 0 para la ruta '{}'",
                config.limit, route_path
            )
        })?;

        // Governor recarga tokens a un ritmo constante. Para permitir `limit`
        // peticiones distribuidas en `window_secs`, el tiempo entre recargas debe ser:
        // window_secs / limit
        let total_nanos = (config.window_secs as u128) * 1_000_000_000u128;
        let interval_nanos = total_nanos / (config.limit as u128);
        if interval_nanos == 0 || interval_nanos > u64::MAX as u128 {
            return Err(format!(
                "Configuración inválida en ruta '{}': window_secs={} limit={} produce intervalo fuera de rango",
                route_path, config.window_secs, config.limit
            ));
        }
        let interval_nanos = interval_nanos as u64;

        let quota = Quota::with_period(Duration::from_nanos(interval_nanos))
            .ok_or_else(|| {
                format!(
                    "El periodo de la ventana ({}s) o límite resultante es inválido para la ruta '{}'",
                    config.window_secs, route_path
                )
            })?
            .allow_burst(burst);

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
        let pattern = PathPattern::compile(&config.path)?;
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
