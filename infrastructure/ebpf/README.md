# eBPF Kernel Profilers

Two non-intrusive profilers that measure Tessera's HTTP latency without any
application instrumentation:

| Program | Hook | Metrics |
| --- | --- | --- |
| `http_profiler.c` + `http_profiler.py` (default mode) | socket syscall tracepoints of one process | HTTP/1.x request latency + per-syscall kernel latency |
| `http2_profiler.c` + `http_profiler.py --http2` | XDP on a Kubernetes pod's veth interface | HTTP/2 stream latency, status, path hash, frame counts |

## HTTP/1.x syscall profiler (issue #258)

- **eBPF kernel probes (`http_profiler.c`)**:
  - Attached via tracepoints to Linux network syscalls:
    - `sys_enter_sendto` / `sys_exit_sendto`
    - `sys_enter_recvfrom` / `sys_exit_recvfrom`
    - plus `read`/`write`/`writev` so tokio and hyper are both covered
  - High-precision kernel nanosecond timestamps via `bpf_ktime_get_ns()`.
  - Log2 power-of-2 latency histogram buckets (1us .. 1s+).
  - Measures execution duration and kernel-to-userspace context switch
    transitions without application-layer overhead.

- **Userspace exporter (`http_profiler.py`)**:
  - Reads eBPF maps and publishes metrics at `:9436/metrics` in standard
    Prometheus exposition format.

```bash
sudo ./http_profiler.py --comm tessera-api --port 9436
```

## HTTP/2 XDP profiler (issue #392)

`http2_profiler.c` is an XDP program attached to the pod's veth pair. Per
packet it parses Ethernet → IPv4/IPv6 → TCP → HTTP/2, walks up to four frames
(`HEADERS`, `DATA`, `RST_STREAM`, `SETTINGS`) and:

1. reads `:path`, `:method`, `:status` and `content-length` out of the HPACK
   header block — static-table indexes plus uncompressed literals;
2. stores the request start time per `(flow, stream)` and, on the response
   `HEADERS` frame, emits `(timestamp_ns, pid, path_hash, status, latency_ns)`
   to the `samples` `perf_event_array` map;
3. copies each parsed `HEADERS` frame, including up to 192 bytes of its raw
   HPACK block, into the `frame_events` BPF ring buffer so a user-space tracer
   can run a complete HPACK decoder when the kernel cannot.

The loader (`http_profiler.py --http2`) attaches the program with
`BPF.attach_xdp`, consumes both maps and exports native Prometheus histograms:

```
tessera_http2_request_duration_seconds{path,status}
tessera_http2_frames_total{type,flags}
```

```bash
# Find the pod's veth on the node, then attach:
sudo ./http_profiler.py --http2 --iface veth1a2b3c --pid "$(pgrep -f tessera-api)" --port 9437
```

### HPACK coverage and path labels

`path` is the FNV-1a hash of `:path`, formatted as `0x...`. Values encoded with
the HPACK Huffman code (the usual case for a literal `:path`) cannot be decoded
in kernel space — the 257-symbol Huffman table does not fit the verifier's
budget — so those samples are exported with `path="0x00000000"` while the raw
header block is retained in `frame_events`. Static-table paths (`/`,
`/index.html`) are decoded exactly, as are uncompressed literals.

Latency and status are unaffected by this limitation: latency is measured from
the request `HEADERS` timestamp to the response `HEADERS` timestamp, and
`:status` is normally a static-table index (e.g. `0x88` for 200).

### Limits

- No TCP reassembly: only frames wholly contained in one packet are parsed.
  A `HEADERS` frame split across segments is skipped (its stream still gets a
  latency sample if the response frame is complete).
- Four frames per packet, 32 header fields per block, 128-byte path values.
- XDP runs in softirq context, so `pid` is the loader-supplied workload pid
  rather than a task-derived value.

## Verification

The latency objective is validated against `strace`-measured request times with
`h2load` (acceptance: within 2%):

```bash
h2load -n 20000 -c 50 https://api.tessera.example/stats
sudo strace -c -f -e trace=recvfrom,sendto -p "$(pgrep -f tessera-api)"
curl -s localhost:9437/metrics | grep tessera_http2_request_duration_seconds
```

## Running the unit tests

```bash
python -m unittest infrastructure.ebpf.test_socket_profiler
```
