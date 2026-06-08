# UI is pre-built locally via `npm run build` — dist/ is copied directly.
# This avoids npm registry access inside the container (proxy/cert issues).
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY foundstone/ ./foundstone/
COPY api.py ./
COPY data/ ./data/
COPY ui/dist/ ./ui/dist/

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
