# ── Stage 1: Build Rust CLI Binary ──────────────────────────────────────────
FROM rust:1.80-slim AS builder

WORKDIR /build

# Copy manifests for caching dependencies
COPY Cargo.toml Cargo.lock ./
COPY src/core/Cargo.toml src/core/
COPY src/cli/Cargo.toml src/cli/
COPY src/wasm/Cargo.toml src/wasm/

# Copy full source
COPY src/ src/

# Build standalone CLI release binary
RUN cargo build --release -p grey-misnomer-cli

# ── Stage 2: Minimal Runtime (Nginx + CLI + Static Verifier) ────────────────
FROM nginx:alpine

# Install minimal runtime libraries for Rust binary
RUN apk add --no-cache ca-certificates tzdata

# Copy built CLI binary into system PATH
COPY --from=builder /build/target/release/grey-misnomer-cli /usr/local/bin/grey-misnomer-cli

# Copy static web platform and WASM package to Nginx web root
COPY docs/ /usr/share/nginx/html/

# Copy canonical ledger files
COPY events.jsonl /usr/share/nginx/html/events.jsonl
COPY events.jsonl /events.jsonl
COPY manifest.json /usr/share/nginx/html/manifest.json

# Custom minimal Nginx configuration serving on port 8080
RUN printf 'server {\n\
    listen 8080;\n\
    server_name localhost;\n\
    root /usr/share/nginx/html;\n\
    index app.html index.html;\n\
    \n\
    location / {\n\
        try_files $uri $uri/ /app.html;\n\
    }\n\
    \n\
    location ~* \.wasm$ {\n\
        types { application/wasm wasm; }\n\
        add_header Cache-Control "no-cache";\n\
    }\n\
    \n\
    location ~* \.(json|jsonl)$ {\n\
        types { application/json json jsonl; }\n\
        add_header Access-Control-Allow-Origin "*";\n\
        add_header Cache-Control "no-cache";\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/events.jsonl || exit 1

CMD ["nginx", "-g", "daemon off;"]
