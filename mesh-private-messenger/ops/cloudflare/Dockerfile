# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS mesh-builder
RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential ca-certificates curl git libssl-dev libsqlite3-dev libtinfo6 \
    libzstd-dev pkg-config xz-utils zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.0
ENV PATH="/root/.cargo/bin:/opt/llvm/bin:${PATH}" LLVM_SYS_211_PREFIX=/opt/llvm CARGO_INCREMENTAL=0
RUN curl -fsSL https://github.com/llvm/llvm-project/releases/download/llvmorg-21.1.8/LLVM-21.1.8-Linux-X64.tar.xz -o /tmp/llvm.tar.xz \
    && echo 'b3b7f2801d15d50736acea3c73982994d025b01c2f035b91ae3b49d1b575732b  /tmp/llvm.tar.xz' | sha256sum -c - \
    && mkdir /opt/llvm && tar -xf /tmp/llvm.tar.xz --strip-components=1 -C /opt/llvm && rm /tmp/llvm.tar.xz
ARG MESH_LANG_REVISION=14dd84d464e62f0a220eecf6ccc6126c338a8214
RUN git init /build/mesh-lang && cd /build/mesh-lang \
    && git remote add origin https://github.com/snowdamiz/mesh-lang.git \
    && git fetch --depth 1 origin "$MESH_LANG_REVISION" && git checkout --detach FETCH_HEAD
WORKDIR /build/mesh-lang
RUN apt-get update && apt-get install --no-install-recommends -y libffi-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/build/mesh-lang/target \
    cargo build --locked --release -p meshc -p mesh-rt \
    && mkdir /opt/mesh && cp target/release/meshc target/release/libmesh_rt.a /opt/mesh/
ENV MESH_RT_LIB_PATH=/opt/mesh/libmesh_rt.a

FROM scratch AS compiler-tools
COPY --from=mesh-builder /opt/mesh/ /

FROM mesh-builder AS services
COPY mesh-private-messenger/packages/messenger-protocol /build/mesh-private-messenger/packages/messenger-protocol
COPY mesh-private-messenger/packages/service-jobs /build/mesh-private-messenger/packages/service-jobs
COPY mesh-private-messenger/services /build/mesh-private-messenger/services
RUN mkdir /artifacts && for service in directory-delivery privacy-edge push-broker object-store transparency-witness; do \
    /opt/mesh/meshc build "/build/mesh-private-messenger/services/$service" --opt-level 2 --output "/artifacts/$service" || exit; \
    done

FROM ubuntu:24.04 AS runtime
RUN apt-get update && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=services /artifacts/ /app/
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/app/directory-delivery"]
