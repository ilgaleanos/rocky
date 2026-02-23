# --- Etapa 1: Compilación (Builder) ---
# Usamos la versión de Rust basada en Alpine que ya incluye las herramientas para musl
# --- Etapa 1: Compilación (Builder) ---
FROM rust:alpine AS builder

# Agregamos openssl-libs-static
RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

# Le decimos a la librería sys de Rust que compile OpenSSL de forma estática
ENV OPENSSL_STATIC=1

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config.json ./

RUN cargo build --release

# --- Etapa 2: Imagen de Ejecución (Runtime) ---
# Usamos la imagen base de Alpine, que pesa solo ~5 MB
FROM alpine:latest

# Añadimos los certificados raíz para que reqwest pueda hacer peticiones HTTPS sin fallar
RUN apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*

WORKDIR /app

# Copiamos el binario compilado (asegúrate de que el nombre coincida con el de tu Cargo.toml)
# Si tu package name es "rocky-nova", el binario suele llamarse "rocky-nova" o "rocky_nova"
COPY --from=builder /app/target/release/rocky ./firewall

# Copiamos la configuración
COPY config.json ./

EXPOSE 9090

CMD ["./firewall"]