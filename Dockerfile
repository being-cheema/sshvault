# Build with the MSRV toolchain (rust-version = "1.89" in Cargo.toml).
FROM rust:1.89-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked
# Staging dir for the runtime volume mount point (distroless has no shell).
RUN mkdir /data

# distroless/cc is sufficient: TLS is rustls (no openssl) and sqlite is
# compiled in via libsqlite3-sys "bundled", so the binary only needs
# libc/libgcc. The relay itself serves plain HTTP — terminate TLS in a
# reverse proxy (caddy/nginx) in front.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/sshvault /usr/local/bin/sshvault
# 65532 = distroless "nonroot"; pre-owning /data makes the named volume
# writable without a runtime chown.
COPY --from=build --chown=65532:65532 /data /data
USER nonroot
VOLUME /data
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/sshvault", "serve", "--addr", "0.0.0.0:8787", "--db", "/data/relay.db"]
