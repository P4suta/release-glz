FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update \
    && apt-get install --yes --no-install-recommends zstd=1.5.4+dfsg2-5 \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d https://github.com/leanprover/lean4/releases/download/v4.35.0/lean-4.35.0-linux.tar.zst /tmp/lean.tar.zst
RUN mkdir -p /opt/lean \
    && tar --zstd -xf /tmp/lean.tar.zst -C /opt/lean --strip-components=1 \
    && rm /tmp/lean.tar.zst
ENV PATH=/opt/lean/bin:$PATH
ENV LEAN_PATH=/evidence:/opt/lean/lib/lean
WORKDIR /workspace
