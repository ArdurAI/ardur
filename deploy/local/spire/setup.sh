#!/bin/sh
# SPIRE setup: wait for server, generate join token, create registration entries.
set -euo pipefail

echo "[spire-setup] Waiting for SPIRE server..."
until /opt/spire/bin/spire-server healthcheck -socketPath /run/spire/sockets/server.sock 2>/dev/null; do
    sleep 2
done
echo "[spire-setup] SPIRE server is healthy."

# Publish the server bundle before the agent verifies its first attestation.
/opt/spire/bin/spire-server bundle show \
    -socketPath /run/spire/sockets/server.sock \
    -format pem > /tmp/spire-shared/bundle.crt
chmod 0644 /tmp/spire-shared/bundle.crt

# Generate join token for the agent
echo "[spire-setup] Generating agent join token..."
JOIN_TOKEN=$(/opt/spire/bin/spire-server token generate \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://ardur.dev/agent/local \
    -ttl 600 | sed -n 's/^Token: //p')
test -n "$JOIN_TOKEN"
printf '%s\n' "$JOIN_TOKEN" > /tmp/spire-shared/join_token
echo "[spire-setup] Join token written."

# Create registration entries for Ardur workloads
echo "[spire-setup] Creating registration entries..."

# Governance proxy
/opt/spire/bin/spire-server entry create \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://ardur.dev/proxy \
    -parentID spiffe://ardur.dev/agent/local \
    -selector unix:uid:65532 \
    -x509SVIDTTL 3600

# Personal hub
/opt/spire/bin/spire-server entry create \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://ardur.dev/hub \
    -parentID spiffe://ardur.dev/agent/local \
    -selector unix:uid:65532 \
    -x509SVIDTTL 3600

# Test runner (uses host uid for local test execution)
/opt/spire/bin/spire-server entry create \
    -socketPath /run/spire/sockets/server.sock \
    -spiffeID spiffe://ardur.dev/agent/test-runner \
    -parentID spiffe://ardur.dev/agent/local \
    -selector unix:uid:0 \
    -x509SVIDTTL 3600

echo "[spire-setup] All registration entries created."
echo "[spire-setup] Setup complete."
