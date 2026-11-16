# S1 compiler environment: same glibc generation as the UBI runtime.
FROM registry.access.redhat.com/ubi9/ubi:9.7
RUN dnf install -y gcc gcc-c++ make openssl-devel pkgconf-pkg-config curl-minimal git tar gzip findutils unzip \
    && dnf clean all
RUN case "$(uname -m)" in \
      x86_64) PROTO_ARCH=x86_64; PROTO_SHA=327e9397c6fb3ea2a542513a3221334c6f76f7aa524a7d2561142b67b312a01f;; \
      aarch64) PROTO_ARCH=aarch_64; PROTO_SHA=a3173ea338ef91b1605b88c4f8120d6c8ccf36f744d9081991d595d0d4352996;; \
      *) exit 1;; esac \
    && curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v30.2/protoc-30.2-linux-${PROTO_ARCH}.zip" -o /tmp/protoc.zip \
    && echo "${PROTO_SHA}  /tmp/protoc.zip" | sha256sum -c - \
    && unzip /tmp/protoc.zip -d /usr/local && rm /tmp/protoc.zip
ARG RUST_VERSION=1.94.1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal --default-toolchain ${RUST_VERSION} \
    && rm /tmp/rustup.sh
ENV PATH="/root/.cargo/bin:${PATH}" CARGO_BUILD_JOBS=2
WORKDIR /work
