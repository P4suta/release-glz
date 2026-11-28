FROM rust:1.100.0-slim-bookworm@sha256:5d3170f8660a07782d5ff42abc55601d2df51d49e5397a8f22247341a658e128
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl=7.88.1-10+deb12u15 \
    && rm -rf /var/lib/apt/lists/* \
    && CARGO_BUILD_JOBS=2 cargo install --locked kani-verifier --version 0.68.0 \
    && cargo kani setup
# cargo-mutants lists the mutants of the core crates that `cargo xtask proof-mutants` runs through the harnesses.
RUN CARGO_BUILD_JOBS=2 cargo install --locked cargo-mutants --version 27.1.0
WORKDIR /workspace
