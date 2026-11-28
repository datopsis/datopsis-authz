# syntax=docker/dockerfile:1.7
ARG BUILDER
ARG RUNTIME
FROM ${BUILDER} AS acquire
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY .image-bundle/ /bundle/
WORKDIR /bundle
RUN sha256sum --check SHA256SUMS \
    && rpmkeys --checksig build-rpms/*.rpm \
    && rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' build-rpms/*.rpm | sort > /actual-nevras \
    && test "$(cat build-rpms.nevras)" = "$(cat /actual-nevras)" \
    && rpm --upgrade --replacepkgs build-rpms/*.rpm \
    && mkdir /toolchain /cargo-auditable \
    && tar -xf tools/rust.tar.xz -C /toolchain --strip-components=1 \
    && /toolchain/install.sh --prefix=/usr/local --without=rust-docs --disable-ldconfig \
    && tar -xf tools/cargo-auditable.tar.xz -C /cargo-auditable --strip-components=1 \
    && cp /cargo-auditable/cargo-auditable /usr/local/bin/cargo-auditable \
    && chmod 0555 /usr/local/bin/cargo-auditable \
    && unzip tools/protoc.zip -d /usr/local \
    && rm -rf /toolchain
ENV PATH="/usr/local/bin:/usr/bin:/bin" CARGO_HOME=/cargo CARGO_BUILD_JOBS=2 OPENSSL_NO_VENDOR=1
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY artifacts/images.lock.json /image-input-lock.json
COPY .cargo/ .cargo/
COPY crates/ crates/
COPY policies/ policies/
COPY migrations/ migrations/
RUN python3 -c 'import hashlib,json; assert hashlib.sha256(open("Cargo.lock","rb").read()).hexdigest() == json.load(open("/image-input-lock.json"))["cargo_lock_sha256"]' \
    && rustc --version | grep -F 'rustc 1.94.1 ' \
    && sha256sum Cargo.lock > /cargo-lock.sha256 \
    && cargo fetch --locked
FROM acquire AS checked
RUN --network=none cargo test --workspace --release --locked --offline
FROM checked AS build
RUN --network=none cargo auditable build --release --locked --offline -p authz-serve -p lakekeeper-bin-datopsis \
    && sha256sum --check /cargo-lock.sha256
# Keep the catalog recipe unchanged. Authz gets its own resolution workspace,
# because cargo-auditable's stable metadata fallback resolves all workspace members.
FROM checked AS build-authz
COPY scripts/prepare-authz-workspace.py /prepare-authz-workspace.py
RUN --network=none python3 /prepare-authz-workspace.py /authz-src
WORKDIR /authz-src
RUN --network=none CARGO_TARGET_DIR=/src/target cargo auditable build --release --locked --offline -p authz-serve \
    && cd /src && sha256sum --check /cargo-lock.sha256
FROM ${RUNTIME} AS micro
FROM acquire AS runtime-root
COPY --from=micro / /runtime/
WORKDIR /bundle
RUN --network=none sha256sum --check SHA256SUMS \
    && rpmkeys --root /runtime --checksig rpms/*.rpm \
    && rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' rpms/*.rpm | sort > /actual-runtime-nevras \
    && test "$(cat rpms.nevras)" = "$(cat /actual-runtime-nevras)" \
    && rpm --root /runtime --upgrade --replacepkgs rpms/*.rpm \
    && find /runtime -xdev -type f -perm /6000 -exec chmod a-s '{}' + \
    && rm -rf /runtime/var/cache/* /runtime/var/log/* /runtime/tmp/*
FROM ${RUNTIME} AS base
ARG SOURCE_REVISION
ARG LOCK_SHA256
LABEL org.opencontainers.image.source="https://github.com/datopsis/datopsis-authz" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.datopsis.artifact-lock.sha256="${LOCK_SHA256}" \
      io.datopsis.lakekeeper.source="a8e013b30e99e5a184486fe166c3ffb3781a7c36"
COPY --from=runtime-root /runtime/ /
ENV LANG=C.UTF-8 TZ=UTC
USER 10001:0
STOPSIGNAL SIGTERM
FROM base AS authz
COPY --from=build-authz --chmod=0555 /src/target/release/authz-serve /usr/local/bin/datopsis-authz
EXPOSE 8443 50051
ENTRYPOINT ["/usr/local/bin/datopsis-authz"]
CMD ["serve"]
FROM base AS lakekeeper-authz
COPY --from=build --chmod=0555 /src/target/release/lakekeeper-bin-datopsis /usr/local/bin/lakekeeper-datopsis
ENV LAKEKEEPER__BIND_IP=127.0.0.1 LAKEKEEPER__LISTEN_PORT=8182
EXPOSE 8181
ENTRYPOINT ["/usr/local/bin/lakekeeper-datopsis"]
CMD ["serve"]
