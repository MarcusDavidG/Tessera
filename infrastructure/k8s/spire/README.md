# SPIRE deployment (issue #394)

Deploys a SPIRE server and a per-node agent DaemonSet for the `tessera.io`
trust domain, and registers one SPIFFE ID per service:

```
spiffe://tessera.io/ns/prod/sa/tessera-api
spiffe://tessera.io/ns/prod/sa/tessera-indexer
spiffe://tessera.io/ns/prod/sa/tessera-mpc-signer
spiffe://tessera.io/ns/prod/sa/tessera-channel-node
```

## Files

| File | Contents |
| --- | --- |
| `server.yaml` | Server StatefulSet, service, RBAC, config, PVC, trust-bundle ConfigMap. |
| `agent.yaml` | Agent DaemonSet (k8s_psat node attestation, k8s workload attestation). |
| `registration-entries.yaml` | Job that creates the per-service entries on every attested agent (idempotent). |

## Prerequisites

1. The [SPIFFE CSI driver](https://github.com/spiffe/spiffe-csi) must be
   installed cluster-wide; workloads mount `csi.spiffe.io` to get `/svids`.
2. The `prod` namespace and the service accounts named in
   `registration-entries.yaml` must exist.
3. Each service's Deployment must mount the SVID volume:

   ```yaml
   spec:
     containers:
       - name: tessera-api
         env:
           - name: SPIFFE_SVID_DIR
             value: /svids
           - name: SPIFFE_ID
             value: spiffe://tessera.io/ns/prod/sa/tessera-api
         volumeMounts:
           - name: spiffe-workload-api
             mountPath: /svids
             readOnly: true
     volumes:
       - name: spiffe-workload-api
         csi:
           driver: csi.spiffe.io
           readOnly: true
   ```

## Apply

```bash
kubectl apply -f infrastructure/k8s/spire/server.yaml
kubectl apply -f infrastructure/k8s/spire/agent.yaml
kubectl -n spire wait --for=condition=ready pod -l app=spire-server --timeout=180s
kubectl apply -f infrastructure/k8s/spire/registration-entries.yaml
kubectl -n spire logs job/spire-registration-entries -f
```

## Verify

```bash
kubectl -n spire exec spire-server-0 -- \
  /usr/bin/spire-server entry show -socketPath /run/spire/sockets/server.sock

# From a workload pod with the SVID volume:
ls -l /svids          # tls.crt, tls.key, ca.crt
openssl x509 -in /svids/tls.crt -noout -subject -ext subjectAltName
```

The leaf's SAN should be the workload's SPIFFE ID. The API logs
`inter-service mTLS enabled with the SPIFFE X.509 SVID` at startup and hot
swaps its `reqwest` client when SPIRE rotates the SVID (see
`api/src/mtls/rotation.rs`).

## Trust domain and rotation

- `default_x509_svid_ttl = 1h`, CA `168h`; the agent rotates SVIDs well before
  expiry and rewrites `/svids` atomically.
- `api/src/mtls` polls the mount every 30 s, compares the leaf fingerprint and
  swaps the client without closing live connections.
