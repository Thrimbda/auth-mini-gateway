FROM rust:1-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples/upstream.rs ./examples/upstream.rs
RUN cargo build --release --bin auth-mini-gateway --example upstream

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /app gateway \
    && mkdir -p /data \
    && chown gateway:gateway /data

WORKDIR /app
COPY --from=build /app/target/release/auth-mini-gateway /usr/local/bin/auth-mini-gateway
COPY --from=build /app/target/release/examples/upstream /usr/local/bin/auth-mini-gateway-upstream

ENV HOST=0.0.0.0
ENV PORT=3000
ENV GATEWAY_DB=/data/auth-mini-gateway.sqlite

USER gateway
VOLUME ["/data"]
EXPOSE 3000
CMD ["auth-mini-gateway"]
