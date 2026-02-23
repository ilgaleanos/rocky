mod config;
mod handler;
mod limiter;
mod state;

use crate::config::AppConfig;
use crate::handler::firewall_handler;
use crate::state::AppState;
use axum::{http::StatusCode, routing::get, Router};
use std::net::SocketAddr;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

#[tokio::main]
async fn main() {
    // 1. INICIALIZACIÓN DE LOGS
    tracing_subscriber::fmt::init();

    info!("🚀 Iniciando Firewall de Alto Rendimiento...");

    // 2. CARGA DE CONFIGURACIÓN
    let config = AppConfig::load("config.json").unwrap_or_else(|_| {
        info!("⚠️ No se encontró config.json, usando configuración por defecto.");
        AppConfig::default_mock()
    });

    info!("🎯 Backend objetivo: {}", config.backend_url);
    info!("📜 Reglas cargadas: {}", config.rules.len());

    // 3. ESTADO COMPARTIDO
    let state = AppState::new(config);

    // 4. ENRUTADOR
    let app = Router::new()
        .route("/health", get(|| async { (StatusCode::OK, "OK") }))
        .fallback(firewall_handler)
        .with_state(state)
        .layer(TraceLayer::new_for_http()) // Genera logs automáticos con tiempos de respuesta
        .layer(CatchPanicLayer::new()); // Evita que un error inesperado tire el servidor

    let port = 8080;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("🛡️  Servidor listo en {}", addr);

    // 5. APAGADO (Graceful Shutdown)
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();

    info!("🛑 Firewall apagado correctamente.");
}

/// Función que espera una señal de terminación (Ctrl+C o SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Fallo al instalar manejador de Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Fallo al instalar manejador de señal de terminación")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
