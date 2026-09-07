# Nextcloud Access Broker — production image.
# Multi-stage: builder compiles deps, runtime is slim and non-root.
# The application owns the PORT only; interface exposure is the
# HOST's decision via docker-compose ports: (design doc 3.7).

FROM python:3.12-slim AS builder
WORKDIR /build
# D6h: bake the source revision into the image for traceable builds
# ('docker compose build --build-arg GIT_COMMIT=$(git rev-parse HEAD)').
# The server reports it alongside the package version when present.
ARG GIT_COMMIT=unknown
COPY pyproject.toml ./
COPY broker ./broker
RUN pip install --no-cache-dir --prefix=/install . \
    && echo -n "${GIT_COMMIT}" > /install/lib/python3.12/site-packages/broker/COMMIT

FROM python:3.12-slim
# non-root runtime user
RUN useradd --system --no-create-home --uid 1000 broker
WORKDIR /app
COPY --from=builder /install /usr/local
COPY broker ./broker
# entrypoint: checks /data writability AS uid 1000 (no sudo in container)
# and prints the operator-facing uid-mismatch fix before exec-ing the
# broker — see entrypoint.sh and cutoverRunbook.md step 2.
COPY entrypoint.sh ./entrypoint.sh
# data dir for the grant store + audit log (mount a volume here)
RUN mkdir -p /data && chown broker:broker /data
USER broker
VOLUME ["/data"]
EXPOSE 8765
HEALTHCHECK --interval=60s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import http.client, sys; c = http.client.HTTPConnection('127.0.0.1', 8765, timeout=5); c.request('GET', '/mcp'); s = c.getresponse().status; sys.exit(0 if s in (200, 401, 405) else 1)"
ENTRYPOINT ["/app/entrypoint.sh"]