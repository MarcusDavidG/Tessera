# Envoy mTLS sidecar (issue #394)

`envoy-config.yaml` contains the sidecar configuration that puts every
Tessera service behind SPIFFE-authenticated mTLS, and an example Deployment
showing how the sidecar and the SPIFFE CSI volume are mounted.

## Traffic path

```
peer pod ──mTLS (SVID, :8443)──▶ envoy sidecar ──plain HTTP──▶ 127.0.0.1:8080
                                      │
                                      └── SDS ──▶ SPIRE agent (unix socket)
```

- **Inbound** (`inbound_mtls`, port 8443) sets
  `require_client_certificate: true` and validates the peer certificate
  against the SPIFFE trust bundle with a SAN matcher restricted to
  `spiffe://tessera.io/`. A caller without a valid SVID cannot complete the
  handshake, so unauthenticated traffic never reaches the API.
- **Outbound** (`tessera_peers`) presents the pod's SVID as its client
  certificate and verifies the peer's SAN under
  `spiffe://tessera.io/ns/prod/sa/` — service-to-service calls are mutually
  authenticated, not just encrypted.
- **SDS** (`spire_agent`) fetches certificates and the bundle from the local
  agent over its Unix socket. No SVID material is written to disk by Envoy,
  and Envoy streams updates, so certificate rotation does not interrupt
  connections.

## Deploy

```bash
kubectl apply -f infrastructure/k8s/mtls/envoy-config.yaml
```

The example Deployment is illustrative; add the `envoy` container and the
`spiffe-workload-api` CSI volume to each real Deployment (the API must bind
loopback so the only ingress is the sidecar).

## Verify

```bash
# From another meshed pod:
openssl s_client -connect tessera-api.prod.svc.cluster.local:8443 \
  -cert /svids/tls.crt -key /svids/tls.key -CAfile /svids/ca.crt \
  -verify_return_error </dev/null | grep -E "Verify return code|subject="

# Without a client certificate the handshake must fail:
openssl s_client -connect tessera-api.prod.svc.cluster.local:8443 </dev/null
```

## Rotation and revocation

- Envoy uses the SDS stream, so a rotated SVID is picked up automatically.
- The Rust side (`api/src/mtls/`) refreshes its `reqwest` client from the SVID
  stream with `tokio::select!` and leaves established connections open; the
  test in `api/src/mtls/tests.rs` revokes a certificate mid-flight and asserts
  the peer's connection is torn down within 10 seconds.
- To revoke a workload permanently, delete its registration entry:
  `spire-server entry delete -entryID <id>` and restart the pod so it cannot
  fetch a new SVID.
