FROM rust:1.99.0-slim-bookworm@sha256:ba81bc3eaa4422af576c0262515d96b0111a628a6ccc2c86557cf55c9a4bbee0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl=7.88.1-10+deb12u15 \
    && rm -rf /var/lib/apt/lists/* \
    && CARGO_BUILD_JOBS=2 cargo install --locked kani-verifier --version 0.68.0 \
    && cargo kani setup
WORKDIR /workspace
