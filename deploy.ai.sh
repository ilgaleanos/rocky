#!/bin/bash

# Detener el script inmediatamente si ocurre algún error
set -e

# --- Variables de configuración ---
IMAGE_NAME="gcr.io/virgilio-stg/rocky-nova"
# Usamos "latest" por defecto, pero puedes cambiarlo por "v1.0.0" o incluso usar el hash de Git: $(git rev-parse --short HEAD)
TAG="latest" 
FULL_IMAGE_PATH="${IMAGE_NAME}:${TAG}"

echo "🚀 Iniciando despliegue de: $FULL_IMAGE_PATH"

# --- 1. Autenticación en Google Cloud (Descomenta si la necesitas) ---
# Si te da error de permisos al hacer push, quita el '#' de la siguiente línea:
# echo "🔑 Autenticando con GCR..."
# gcloud auth configure-docker gcr.io --quiet

# --- 2. Construcción de la imagen ---
echo "🔨 Construyendo la imagen Docker (esto puede tomar un momento)..."
docker build -t "$FULL_IMAGE_PATH" -f Dockerfile.ai .

# --- 3. Subida (Push) de la imagen ---
echo "☁️ Subiendo la imagen a Google Container Registry..."
docker push "$FULL_IMAGE_PATH"

echo "✅ ¡Éxito! La imagen se ha subido correctamente a $FULL_IMAGE_PATH"