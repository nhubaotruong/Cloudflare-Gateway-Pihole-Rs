FROM docker.io/clux/muslrust:stable AS builder
WORKDIR /workdir
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest
RUN apk add -U --no-cache ca-certificates
COPY --from=builder /workdir/target/x86_64-unknown-linux-musl/release/cloudflare_gateway_pihole /app
COPY lists.txt whitelists.txt custom_whitelist.txt /
CMD ["/app"]