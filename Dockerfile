# Two stages: build with the Rust toolchain, run on distroless (no shell, no package manager).
FROM rust:1.95-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/keyvault /keyvault

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /keyvault /usr/local/bin/keyvault
USER nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/usr/local/bin/keyvault", "health"]
ENTRYPOINT ["/usr/local/bin/keyvault"]
CMD ["serve"]
