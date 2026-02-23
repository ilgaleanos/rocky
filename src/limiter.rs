use crate::config::RuleConfig;
use governor::{
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
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
    pub fn new(config: RuleConfig) -> Self {
        let quota = Quota::with_period(Duration::from_secs(config.window_secs))
            .expect("El periodo de la ventana debe ser válido")
            .allow_burst(NonZeroU32::new(config.limit).expect("El límite debe ser mayor a 0"));

        let limiter = RateLimiter::dashmap(quota);

        Self { config, limiter }
    }
}
