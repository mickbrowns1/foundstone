#!/usr/bin/env bash
# Build the UI locally then build+start the Docker container.
set -e
echo "→ Building UI..."
cd ui && npm run build && cd ..
echo "→ Building and starting container..."
docker compose up --build -d
echo "✓ Running at http://localhost:8080"
