FROM docker.io/chainguard/rust:latest-dev AS builder
USER root
RUN apk add -U --no-cache openssl-dev
COPY . .
RUN cargo build --release

FROM docker.io/chainguard/wolfi-base:latest AS runtime
RUN apk add -U --no-cache libssl3 libgcc
USER nonroot
COPY --from=builder /work/target/x86_64-unknown-linux-gnu/release/cloudflare_gateway_pihole /app
COPY lists.txt whitelists.txt /
CMD ["/app"]