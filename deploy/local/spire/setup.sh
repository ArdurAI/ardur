#!/bin/bash
# SPIRE setup: wait for server, generate join token, create registration entries.
set -euo pipefail

echo "[spire-setup] Waiting for SPIRE server..."
until /opt/spire/bin/spire-server healthcheck -serverAddr spire-server:8081 2>/dev/null; do
    sleep 2
done
echo "[spire-setup] SPIRE server is healthy."

# Generate join token for the agent
echo "[spire-setup] Generating agent join token..."
JOIN_TOKEN=$(/opt/spire/bin/spire-server token generate \
    -serverAddr spire-server:8081 \
    -spiffeID spiffe://ardur.dev/spire/agent \
    -ttl 600 2>&1)
echo "$JOIN_TOKEN" > /tmp/spire-shared/join_token
echo "[spire-setup] Join token written."

# Create registration entries for Ardur workloads
echo "[spire-setup] Creating registration entries..."

# Governance proxy
/opt/spire/bin/spire-server entry create \
    -serverAddr spire-server:8081 \
    -spiffeID spiffe://ardur.dev/proxy \
    -parentID spiffe://ardur.dev/spire/agent \
    -selector unix:uid:65532 \
    -ttl 3600

# Personal hub
/opt/spire/bin/spire-server entry create \
    -serverAddr spire-server:8081 \
    -spiffeID spiffe://ardur.dev/hub \
    -parentID spiffe://ardur.dev/spire/agent \
    -selector unix:uid:65532 \
    -ttl 3600

# Test runner (uses host uid for local test execution)
/opt/spire/bin/spire-server entry create \
    -serverAddr spire-server:8081 \
    -spiffeID spiffe://ardur.dev/agent/test-runner \
    -parentID spiffe://ardur.dev/spire/agent \
    -selector unix:uid:0 \
    -ttl 3600

echo "[spire-setup] All registration entries created."
echo "[spire-setup] Setup complete."
