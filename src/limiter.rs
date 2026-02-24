use crate::config::RuleConfig;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::time::Duration;

/// Alias para el limitador de Governor que usa llaves (Strings) dinámicas.
pub type DynKeyLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Combina la configuración de una regla con su instancia de limitador.
pub struct ActiveRule {
    pub config: RuleConfig,
    pub limiter: DynKeyLimiter,
}

impl ActiveRule {
    /// Construye una nueva regla activa inicializando el limitador Token Bucket.
    pub fn new(config: RuleConfig) -> Result<Self, String> {
        let quota = Quota::with_period(Duration::from_secs(config.window_secs))
            .ok_or_else(|| {
                format!(
                    "El periodo de la ventana ({}s) es inválido para la ruta '{}'",
                    config.window_secs, config.path_prefix
                )
            })?
            .allow_burst(NonZeroU32::new(config.limit).ok_or_else(|| {
                format!(
                    "El límite ({}) es inválido (debe ser mayor a 0) para la ruta '{}'",
                    config.limit, config.path_prefix
                )
            })?);

        let limiter = RateLimiter::dashmap(quota);

        Ok(Self { config, limiter })
    }
}
