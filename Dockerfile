# --- web: build the dashboard -------------------------------------------------
FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- app: train the model at build time, then serve API + dashboard -----------
FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY vigil/ vigil/
ARG TRAIN_FLAGS=""
RUN python -m vigil.train ${TRAIN_FLAGS}
COPY --from=web /web/dist web/dist
RUN useradd --create-home vigil && mkdir -p data && chown vigil data
USER vigil
EXPOSE 8710
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8710/api/health')"
CMD ["uvicorn", "vigil.api:app", "--host", "0.0.0.0", "--port", "8710"]
