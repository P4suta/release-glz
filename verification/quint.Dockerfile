# The offline host of the Quint model, which `cargo xtask quint` runs with no network.
FROM docker.io/library/eclipse-temurin:21-jre@sha256:0b99b3376fbb50dbf9c0af8535fdd5b8eb0d3fdfc8b1e4967f383b6919f6901a AS java

FROM docker.io/library/node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c
COPY --from=java /opt/java/openjdk /opt/java/openjdk
ENV PATH=/opt/java/openjdk/bin:/opt/quint/node_modules/.bin:$PATH
ENV QUINT_HOME=/opt/quint

# The lockfile pins Quint and every package it loads by integrity hash.
COPY quint/package.json quint/package-lock.json /opt/quint/
RUN cd /opt/quint && npm ci --ignore-scripts --no-audit --no-fund

# Quint compiles the model through Apalache, whose release lists the checksum that this file repeats, so a replaced asset fails the build.
ARG APALACHE_VERSION=0.62.4
ARG APALACHE_SHA256=b781b53bba32fac14ac2e02b0332e1dc2edc64cb7b850c0608d8142cc7aa2ef4
ADD --checksum=sha256:${APALACHE_SHA256} https://github.com/apalache-mc/apalache/releases/download/v${APALACHE_VERSION}/apalache-${APALACHE_VERSION}.tgz /tmp/apalache.tgz
RUN mkdir -p ${QUINT_HOME}/apalache-dist-${APALACHE_VERSION}/apalache \
    && tar -xzf /tmp/apalache.tgz --strip-components=1 -C ${QUINT_HOME}/apalache-dist-${APALACHE_VERSION}/apalache \
    && rm /tmp/apalache.tgz \
    && test -f ${QUINT_HOME}/apalache-dist-${APALACHE_VERSION}/apalache/lib/apalache.jar
WORKDIR /workspace
