# syntax=docker/dockerfile:1
# The Morse witness (services/transparency-witness) as a reproducible OCI
# image. Build it with ops/witness/build.sh, which supplies the pinned Mesh
# source as the `mesh-lang` build context, sets SOURCE_DATE_EPOCH and writes
# SHA256SUMS. Every input below is pinned: the base image by digest, apt
# packages by an Ubuntu snapshot, rustup-init and LLVM by SHA-256, the Rust
# toolchain by version and the Mesh compiler by the revision build.sh records.
# linux/amd64 and linux/arm64.

ARG UBUNTU=ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

FROM ${UBUNTU} AS builder
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ARG APT_SNAPSHOT=20260915T000000Z
ARG RUSTUP_VERSION=1.29.1
ARG RUST_TOOLCHAIN=1.97.0
ARG LLVM_VERSION=21.1.8
ENV DEBIAN_FRONTEND=noninteractive
# The snapshot service is HTTPS-only, so the live archive supplies the CA
# certificates the build's downloads use; everything that reaches the binary
# comes from the snapshot or is checked against a pinned SHA-256. The witness
# itself needs no CA store: Mesh's HTTP client carries the webpki roots.
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates \
    && apt-get update --snapshot "$APT_SNAPSHOT" \
    && apt-get install --snapshot "$APT_SNAPSHOT" --no-install-recommends -y \
      build-essential curl libffi-dev libssl-dev libsqlite3-dev libtinfo6 \
      libxml2-dev libzstd-dev pkg-config xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; rustup_sha=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71; \
        llvm=LLVM-${LLVM_VERSION}-Linux-X64.tar.xz; llvm_sha=b3b7f2801d15d50736acea3c73982994d025b01c2f035b91ae3b49d1b575732b ;; \
      arm64) triple=aarch64-unknown-linux-gnu; rustup_sha=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433; \
        llvm=LLVM-${LLVM_VERSION}-Linux-ARM64.tar.xz; llvm_sha=65ce0b329514e5643407db2d02a5bd34bf33d159055dafa82825c8385bd01993 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init" -o /tmp/rustup-init \
    && echo "${rustup_sha}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN" \
    && rm /tmp/rustup-init \
    && curl -fsSL "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/${llvm}" -o /tmp/llvm.tar.xz \
    && echo "${llvm_sha}  /tmp/llvm.tar.xz" | sha256sum -c - \
    && mkdir /opt/llvm && tar -xf /tmp/llvm.tar.xz --strip-components=1 -C /opt/llvm && rm /tmp/llvm.tar.xz
ENV PATH="/root/.cargo/bin:/opt/llvm/bin:${PATH}" LLVM_SYS_211_PREFIX=/opt/llvm CARGO_INCREMENTAL=0

# The Mesh compiler, from the source tree build.sh exported at the pinned
# revision (it needs File.rename and File.sync).
COPY --from=mesh-lang . /build/mesh-lang
WORKDIR /build/mesh-lang
RUN cargo build --locked --release -p meshc -p mesh-rt \
    && mkdir /opt/mesh && cp target/release/meshc target/release/libmesh_rt.a /opt/mesh/ \
    && rm -rf target
ENV MESH_RT_LIB_PATH=/opt/mesh/libmesh_rt.a

COPY mesh-private-messenger/packages/messenger-protocol /build/mesh-private-messenger/packages/messenger-protocol
COPY mesh-private-messenger/services/transparency-witness /build/mesh-private-messenger/services/transparency-witness
RUN /opt/mesh/meshc build /build/mesh-private-messenger/services/transparency-witness \
      --opt-level 2 --output /rootfs/app/transparency-witness \
    && mkdir -p /rootfs/var/lib/morse-witness /rootfs/var/lib/morse-witness-guard \
    && chown 65532:65532 /rootfs/var/lib/morse-witness /rootfs/var/lib/morse-witness-guard \
    && chmod 0700 /rootfs/var/lib/morse-witness /rootfs/var/lib/morse-witness-guard \
    && find /rootfs -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

# `--target binary --output type=local` exports only the witness binary, for
# the systemd install and for SHA256SUMS.
FROM scratch AS binary
COPY --from=builder /rootfs/app/transparency-witness /transparency-witness

# The runtime adds one layer to the pinned base: the binary (it needs only
# glibc) and the state and guard directories. Nothing is installed and no
# port is exposed: in pull mode the witness only makes outbound HTTPS requests
# to the directory and the relays.
FROM ${UBUNTU} AS runtime
COPY --from=builder /rootfs/ /
USER 65532:65532
ENV MESSENGER_WITNESS_MODE=pull \
    MESSENGER_WITNESS_CHECKPOINT_PATH=/var/lib/morse-witness/checkpoint \
    MESSENGER_WITNESS_EVIDENCE_DIR=/var/lib/morse-witness \
    MESSENGER_WITNESS_GUARD_PATH=/var/lib/morse-witness-guard/checkpoint
VOLUME ["/var/lib/morse-witness", "/var/lib/morse-witness-guard"]
WORKDIR /var/lib/morse-witness
ENTRYPOINT ["/app/transparency-witness"]
