# Reproducible image for the `ardur run --enforce` end-to-end demo — both the
# BPF-LSM tier (run.sh) and the seccomp fallback tier (run-seccomp.sh, plan
# E4 / issue #104).
#
# Build context is the REPO ROOT:
#   docker build -f docs/demo/enforce-e2e/Dockerfile -t ardur-enforce-demo .
#
# Stage 1 builds the daemon, ardur-exec-shim (the seccomp tier's on-ramp —
# needed on PATH for run-seccomp.sh, since ardur run invokes it by resolving
# it via PATH/well-known install location, never by an explicit path), and
# the offline evidence verifier from source. The committed bpf2go object
# (processguard_bpfel.o) is used as-is, so no clang or kernel headers are
# needed at build time. Stage 2 installs the Python `ardur` CLI. Run the
# image privileged with --pid=host — see docs/demo/enforce-e2e.md.

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download
COPY go/ ./go/
RUN cd go \
 && go build -o /out/ardur-kernelcaptured ./cmd/ardur-kernelcaptured \
 && go build -o /out/ardur-exec-shim      ./cmd/ardur-exec-shim \
 && go build -o /out/enforce-verify        ./cmd/enforce-verify

FROM python:3.13-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 procps \
 && rm -rf /var/lib/apt/lists/*
# Core package + biscuit-python only: biscuit_auth is the sole extra import the
# --enforce path needs (bpf_lower -> mission_compile). The other [dev] extras
# (z3-solver, cedarpy, ...) are unrelated to kernel enforcement and some lack
# aarch64 wheels.
COPY python/ /opt/ardur/python/
RUN pip install --no-cache-dir -e /opt/ardur/python \
 && pip install --no-cache-dir 'biscuit-python==0.4.0'
COPY --from=build /out/ardur-kernelcaptured /usr/local/bin/ardur-kernelcaptured
COPY --from=build /out/ardur-exec-shim      /usr/local/bin/ardur-exec-shim
COPY --from=build /out/enforce-verify        /usr/local/bin/enforce-verify
COPY docs/demo/enforce-e2e/agent.py docs/demo/enforce-e2e/agent_seccomp.py docs/demo/enforce-e2e/run.sh docs/demo/enforce-e2e/run-seccomp.sh /opt/ardur/demo/
RUN chmod +x /opt/ardur/demo/run.sh /opt/ardur/demo/run-seccomp.sh && mkdir -p /run/ardur /var/lib/ardur
WORKDIR /opt/ardur/demo
