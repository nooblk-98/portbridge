# Build the Rust binary in a separate stage so the runtime image has no toolchain.
FROM rust:1.100-alpine3.22 AS build

RUN apk add --no-cache build-base

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# Static files and templates stay under app/; copy them here too so a build that
# embeds assets at compile time sees the same tree the runtime image ships.
COPY app ./app
RUN cargo build --release --locked --bin portbridge

FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    ca-certificates \
    ip6tables \
    iproute2 \
    iptables \
    wireguard-tools

WORKDIR /app
COPY app /app/app
COPY --from=build /src/target/release/portbridge /usr/local/bin/portbridge

ENV APP_HOST=0.0.0.0 \
    APP_PORT=3000 \
    DATA_DIR=/data

EXPOSE 3000/tcp
EXPOSE 51820/udp

CMD ["portbridge"]
