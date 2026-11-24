FROM rust:1.80-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release -p greymisnomerd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/greymisnomerd /usr/local/bin/
EXPOSE 9482 9483
ENTRYPOINT ["greymisnomerd", "--enable-relay", "--p2p-port", "9483", "--rpc-port", "9482"]
