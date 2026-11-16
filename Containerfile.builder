# S1 compiler environment: same glibc generation as the UBI runtime.
FROM registry.access.redhat.com/ubi9/ubi:9.7
RUN dnf install -y gcc gcc-c++ make openssl-devel protobuf-compiler pkgconf-pkg-config curl git tar gzip findutils \
    && dnf clean all
ARG RUST_VERSION=1.94.1
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal --default-toolchain ${RUST_VERSION} \
    && rm /tmp/rustup.sh
ENV PATH="/root/.cargo/bin:${PATH}" CARGO_BUILD_JOBS=2
WORKDIR /work
