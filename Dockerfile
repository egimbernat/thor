FROM rust:1.60.0 as build

WORKDIR /usr/src/foundry

COPY mqtt-proxy .

RUN cargo install --path .

FROM gcr.io/distroless/cc-debian11

COPY --from=build /usr/local/cargo/bin/thor /usr/local/bin/thor
COPY ./mqtt-proxy/config.toml /usr/etc/d.thor/config.toml
COPY ./mqtt-proxy/tls.json /usr/etc/d.thor/tls.json
COPY --from=build /etc/ssl/certs /etc/ssl/certs

ENV TH_TLS_DEFINITION="/usr/etc/d.thor/tls.json"

ENTRYPOINT ["thor", "-c",  "/usr/etc/d.thor/config.toml"]
