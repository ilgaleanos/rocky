# 🪨 Rocky: High-Performance Firewall & Reverse Proxy

**Rocky** es un firewall de aplicación web (WAF) y proxy reverso ultrarrápido escrito en Rust. Diseñado para proteger servicios backend (como APIs, servidores web o bases de datos) contra abusos, ataques de denegación de servicio (DDoS) y tráfico malicioso, consumiendo una cantidad mínima de recursos de CPU y RAM.

## ✨ Características Principales

* 🚀 **Streaming Bidireccional (Baja Huella de Memoria):** Los cuerpos de las peticiones y respuestas se transmiten mediante *streams* asíncronos. Puede procesar subidas o descargas de varios Gigabytes usando apenas unos pocos Megabytes de RAM.
* 🛡️ **Rate Limiting Dinámico en Cascada:** Define múltiples límites (por IP, por token de autorización o globales) que se evalúan simultáneamente. Utiliza el algoritmo *Token Bucket* de altísimo rendimiento (`governor`).
* 🛑 **Cuarentena Automática (Auto-Ban):** Los atacantes que exceden los límites son bloqueados instantáneamente en la capa de red utilizando una memoria caché en RAM (`moka`) de acceso casi instantáneo.
* 🕵️ **Protección contra IP Spoofing:** Detecta inteligentemente si está detrás de un balanceador de carga confiable (analizando redes locales y loopbacks) antes de confiar en cabeceras como `X-Forwarded-For`.
* 🧹 **Cumplimiento estricto de HTTP:** Limpieza automática de cabeceras *Hop-by-Hop* para evitar vulnerabilidades de desincronización de peticiones.
* 🩺 **Preparado para Producción:** Incluye *Graceful Shutdown*, endpoints de *Health Check* (`/health`), timeouts estrictos para evitar bloqueos del backend, y trazabilidad completa (`tower-http`).

---

## 🚀 Inicio Rápido

### Requisitos Previos

* [Rust](https://www.rust-lang.org/tools/install) (Edición 2021 o superior)

### Instalación y Ejecución

1. Clona este repositorio y navega a la carpeta del proyecto.
2. Asegúrate de tener tu archivo `config.json` en la raíz (o configura las reglas a tu medida).
3. Compila y ejecuta el proxy:

```bash
cargo run --release

```

Por defecto, Rocky escuchará el tráfico entrante en `0.0.0.0:3000` y lo redirigirá a tu backend.

---

## ⚙️ Configuración (`config.json`)

Toda la lógica de protección se define en un archivo JSON fácil de leer.

```json
{
    "backend_url": "http://127.0.0.1:8080",
    "global_whitelist": ["127.0.0.1", "10.0.0.5"],
    "rules": [
        {
            "path_prefix": "/api/login",
            "identifiers": ["ip"],
            "limit": 5,
            "window_secs": 60,
            "on_limit_exceeded": { "duration_secs": 900 } 
        },
        {
            "path_prefix": "/",
            "identifiers": ["header:authorization"],
            "limit": 100,
            "window_secs": 1,
            "on_limit_exceeded": { "duration_secs": 5 }
        }
    ]
}

```

### Entendiendo las Reglas:

* `backend_url`: La dirección de tu servidor real que deseas proteger.
* `global_whitelist`: Lista de direcciones IP que saltarán **todas** las reglas del firewall (ideal para administradores o webhooks internos).
* `path_prefix`: La ruta que activa la regla. Las reglas más largas/específicas se evalúan primero.
* `identifiers`:
* `"ip"`: El límite se aplica de forma individual a cada dirección IP del cliente.
* `"header:nombre"`: El límite se aplica a un valor específico de una cabecera HTTP (ej. `header:authorization` para limitar por API Key).
* `"*"`: Un límite global para todo el servidor.


* `on_limit_exceeded.duration_secs`: Si el límite se rompe, ¿cuántos segundos permanecerá el atacante bloqueado devolviendo un error HTTP 403/429?

---

## 🏗️ Arquitectura Interna

1. **Axum & Tokio:** Manejan miles de conexiones concurrentes en hilos asíncronos.
2. **State (Estado Compartido):** Un `Arc<AppState>` mantiene las conexiones HTTP (pool de `reqwest`), la caché de cuarentena (`moka`), y los limitadores de estado configurados listos para acceso en O(1).
3. **Cascading Handler:** A diferencia de los firewalls básicos, si múltiples reglas coinciden con la petición de un usuario, el usuario debe superar las restricciones de **todas** ellas para que la petición alcance el backend.

---

## ⚖️ Licencia

Este proyecto se distribuye bajo la licencia MIT. Eres libre de usarlo, modificarlo y distribuirlo en entornos comerciales y privados.