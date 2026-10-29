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
# Small VPS: limit jobs and disable LTO to avoid OOM during final link.
ENV CARGO_BUILD_JOBS=2
ENV CARGO_PROFILE_RELEASE_LTO=false
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/local/cargo/git \
	--mount=type=cache,target=/src/target \
	cargo build --release -p tuwunel
RUN --mount=type=cache,target=/src/target \
	test -x /src/target/release/tuwunel \
	&& cp /src/target/release/tuwunel /tuwunel \
	&& strip /tuwunel \
	&& mkdir -p /runtime-libs \
	&& ldd /tuwunel | awk '{print $3}' | grep -E '^/' | sort -u \
		| while read -r so; do cp -v --parents "$so" /runtime-libs/; done \
	&& cp -v --parents /lib64/ld-linux-x86-64.so.2 /runtime-libs/ 2>/dev/null || true

# MDAD overrides --user=988:988 at runtime.
FROM gcr.io/distroless/cc-debian12
COPY --from=builder /tuwunel /usr/bin/tuwunel
COPY --from=builder /runtime-libs/ /
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8008 8448
ENTRYPOINT ["/usr/bin/tuwunel"]
