# Hotfix image for fumao15: same /usr/bin/tuwunel layout as upstream OCI.
# syntax=docker/dockerfile:1.7

FROM rust:1.95.0-bookworm AS builder
WORKDIR /src
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		clang cmake g++ libclang-dev pkg-config libssl-dev \
		liburing-dev libsystemd-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY . .
ENV CARGO_TERM_COLOR=always
# Limit parallelism on small hosts (fumao15 ~8Gi RAM).
ENV CARGO_BUILD_JOBS=2
RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/local/cargo/git \
	--mount=type=cache,target=/src/target \
	cargo build --release -p tuwunel \
	&& cp target/release/tuwunel /tuwunel \
	&& strip /tuwunel || true

# MDAD overrides --user=988:988 at runtime; keep CA bundle like upstream.
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /tuwunel /usr/bin/tuwunel
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8008 8448
ENTRYPOINT ["/usr/bin/tuwunel"]
