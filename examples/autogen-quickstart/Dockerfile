# AutoGen v0.4+ governance-demo image (rahulnutakki/ardur-demo:autogen).
#
# Build from the ardur repo root:
#
#   cd /path/to/ardur
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     -f examples/autogen-quickstart/Dockerfile \
#     -t rahulnutakki/ardur-demo:autogen \
#     --push .
#
# spiffe-python's transitive protobuf >=6 collides with autogen-core's
# protobuf ~=5.29 pin, so this image drops the Python SPIFFE client and
# uses the official `spire-agent` CLI instead (production sidecar-fetch
# pattern). Same real Workload API, different real client.

# FIX-9 (2026-04-28): production builds MUST digest-pin both base images.
# Resolve current digests with:
#   skopeo inspect docker://ghcr.io/spiffe/spire-agent:1.14.2 \
#     --format '{{.Digest}}'
#   skopeo inspect docker://docker.io/library/python:3.13-slim \
#     --format '{{.Digest}}'
# Then update the FROM lines to use "@sha256:<digest>" form. The
# published demo images keep tag-pinned references for contributor
# reproducibility; CI/release builds must swap to digest pinning so a
# malicious tag re-push at the upstream registry can't poison the
# governance demo.

# Stage 1: pull the real spire-agent binary from the official image.
FROM ghcr.io/spiffe/spire-agent:1.14.6 AS spire

FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 ardur \
    && useradd -m -u 1000 -g 1000 -s /bin/bash ardur

# Bring in the official spire-agent binary.
COPY --from=spire /opt/spire/bin/spire-agent /usr/local/bin/spire-agent

WORKDIR /app

RUN pip install --no-cache-dir \
    biscuit-python==0.4.0 \
    cedarpy==4.8.0 \
    cryptography \
    pyjwt \
    requests \
    "pydantic>=2.10" \
    ollama \
    "autogen-core>=0.4" \
    "autogen-agentchat>=0.4" \
    "autogen-ext[ollama,openai,anthropic]>=0.4"

COPY --chown=ardur:ardur python/vibap /app/ardur/vibap
COPY --chown=ardur:ardur python/pyproject.toml /app/ardur/pyproject.toml
COPY --chown=ardur:ardur examples/_shared/demo_scenes.py /app/demo_scenes.py
COPY --chown=ardur:ardur examples/_shared/verify_bundle.py /app/verify_bundle.py
COPY --chown=ardur:ardur examples/autogen-quickstart/demo.py /app/demo.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/ardur

USER ardur
CMD ["python", "-c", "print('ardur-demo:autogen workload ready')"]
