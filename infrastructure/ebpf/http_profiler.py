#!/usr/bin/env python3
"""Loader and Prometheus exporter for the Tessera HTTP profilers.

Two modes:

HTTP/1.x syscall tracing (default, issue #258) — compiles http_profiler.c,
attaches its syscall tracepoints to one process and serves the in-kernel log2
histograms as native Prometheus histograms:

  tessera_http_request_duration_seconds              request read -> response write
  tessera_socket_syscall_duration_seconds{syscall}   syscall entry -> return to user

HTTP/2 packet tracing (issue #392) — compiles http2_profiler.c, attaches its
XDP program to a Kubernetes pod's veth interface, consumes the perf-event
samples the program emits and serves them as a Prometheus histogram:

  tessera_http2_request_duration_seconds{path,status}
      HEADERS(request) -> HEADERS(response) per HTTP/2 stream
  tessera_http2_frames_total{type,flags}
      parsed HTTP/2 frames seen on the interface (ring-buffer records)

Maps are read only when Prometheus scrapes (no polling loop), so a scrape
costs O(S * B) for S series and B buckets; nothing runs between scrapes. The
HTTP/2 mode has one small polling thread for the perf/ring buffers.

Requires root (or CAP_BPF + CAP_PERFMON), BCC (python3-bpfcc) and kernel >= 5.5
(kernel >= 5.18 for the HTTP/2 mode, which uses bpf_xdp_load_bytes).

  sudo ./http_profiler.py --comm tessera-api --port 9436
  sudo ./http_profiler.py --http2 --iface veth1a2b3c --pid 4242 --port 9437
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import threading
from collections import defaultdict

from bcc import BPF
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import CounterMetricFamily, HistogramMetricFamily
from prometheus_client.utils import floatToGoString

# Order must match `enum sys_id` in http_profiler.c.
SYSCALLS = ("read", "recvfrom", "write", "writev", "sendto")
SUM_HTTP = len(SYSCALLS)
# bpf_log2l() slot k holds v in [2^(k-1), 2^k - 1] ns (slot 1 holds 0..1).
# A fixed slot range keeps the exported bucket set stable across scrapes;
# slot 36 tops out at ~68.7s, anything slower lands in +Inf only.
MAX_SLOT = 36
BUCKET_BOUNDS = [floatToGoString(((1 << k) - 1) / 1e9) for k in range(1, MAX_SLOT + 1)]
COMM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")  # TASK_COMM_LEN - 1

# HTTP/2 latency buckets in seconds (1 ms .. ~34 s). A fixed set keeps the
# exported series stable across scrapes.
HTTP2_BUCKET_BOUNDS_S = (
    0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
    1.0, 2.5, 5.0, 10.0, 20.0, 34.0,
)
HTTP2_BUCKET_LABELS = [floatToGoString(bound) for bound in HTTP2_BUCKET_BOUNDS_S]

# HTTP/2 frame types (RFC 9113 §6) and flag bits, for the frame counter.
HTTP2_FRAME_TYPES = {0: "data", 1: "headers", 2: "priority", 3: "rst_stream",
                     4: "settings", 5: "push_promise", 6: "ping", 7: "goaway",
                     8: "window_update", 9: "continuation"}
HTTP2_FLAGS = {1: "END_STREAM", 4: "END_HEADERS", 8: "PADDED", 0x20: "PRIORITY"}


def to_buckets(slots: dict[int, int]) -> list[tuple[str, int]]:
    """Convert per-slot counts into cumulative Prometheus buckets."""
    buckets, running = [], 0
    for slot, bound in enumerate(BUCKET_BOUNDS, start=1):
        running += slots.get(slot, 0)
        buckets.append((bound, running))
    buckets.append(("+Inf", sum(slots.values())))
    return buckets


class ProfilerCollector:
    def __init__(self, bpf: BPF):
        self._http = bpf["http_hist"]
        self._syscalls = bpf["syscall_hist"]
        self._sums = bpf["sums"]

    def collect(self):
        http = HistogramMetricFamily(
            "tessera_http_request_duration_seconds",
            "HTTP/1.x latency at the socket layer: request bytes delivered to "
            "the process until its response status line is written.",
        )
        http.add_metric([], to_buckets({k.value: v.value for k, v in self._http.items()}),
                        sum_value=self._sums[SUM_HTTP].value / 1e9)
        yield http

        per_syscall: dict[int, dict[int, int]] = defaultdict(dict)
        for key, count in self._syscalls.items():
            per_syscall[key.sys][key.slot] = count.value
        syscalls = HistogramMetricFamily(
            "tessera_socket_syscall_duration_seconds",
            "Time from syscall entry to return to user space for socket reads/writes.",
            labels=["syscall"],
        )
        for idx, name in enumerate(SYSCALLS):
            syscalls.add_metric([name], to_buckets(per_syscall[idx]),
                                sum_value=self._sums[idx].value / 1e9)
        yield syscalls


class Http2Aggregator:
    """Thread-safe aggregation of the kernel's HTTP/2 samples.

    `path` is the FNV-1a hash of `:path` as a hex label. Paths whose HPACK
    value is Huffman-coded cannot be decoded in the kernel and are exported as
    `path="0x00000000"` (see infrastructure/ebpf/README.md).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._latency: dict[tuple[str, str], list[int]] = defaultdict(
            lambda: [0] * (len(HTTP2_BUCKET_BOUNDS_S) + 1)
        )
        self._frames: dict[tuple[str, str], int] = defaultdict(int)

    def record_sample(self, path_hash: int, status: int, latency_ns: int) -> None:
        seconds = latency_ns / 1e9
        bucket = len(HTTP2_BUCKET_BOUNDS_S)
        for index, bound in enumerate(HTTP2_BUCKET_BOUNDS_S):
            if seconds <= bound:
                bucket = index
                break
        key = (f"0x{path_hash:08x}", str(status))
        with self._lock:
            self._latency[key][bucket] += 1

    def record_frame(self, frame_type: int, flags: int) -> None:
        flag_names = [name for bit, name in sorted(HTTP2_FLAGS.items()) if flags & bit]
        key = (HTTP2_FRAME_TYPES.get(frame_type, str(frame_type)),
               "|".join(flag_names) or "NONE")
        with self._lock:
            self._frames[key] += 1

    def collect(self):
        with self._lock:
            latency = {key: list(counts) for key, counts in self._latency.items()}
            frames = dict(self._frames)

        histogram = HistogramMetricFamily(
            "tessera_http2_request_duration_seconds",
            "HTTP/2 stream latency: request HEADERS frame until the response "
            "HEADERS frame, measured on the pod's veth interface.",
            labels=["path", "status"],
        )
        for (path, status), counts in sorted(latency.items()):
            cumulative, buckets = 0, []
            for bound, count in zip(HTTP2_BUCKET_LABELS, counts[:-1]):
                cumulative += count
                buckets.append((bound, cumulative))
            buckets.append(("+Inf", sum(counts)))
            histogram.add_metric([path, status], buckets)
        yield histogram

        counter = CounterMetricFamily(
            "tessera_http2_frames_total",
            "HTTP/2 frames parsed by the XDP program.",
            labels=["type", "flags"],
        )
        for (frame_type, flags), count in sorted(frames.items()):
            counter.add_metric([frame_type, flags], count)
        yield counter


def run_http2(args) -> None:
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "http2_profiler.c")
    bpf = BPF(src_file=source, cflags=[f"-DTARGET_PID={args.pid or 0}"])

    def on_sample(_cpu, data, _size):
        sample = bpf["samples"].event(data)
        aggregator.record_sample(sample.path_hash, sample.status, sample.latency_ns)

    def on_frame(_ctx, data, _size):
        frame = bpf["frame_events"].event(data)
        aggregator.record_frame(frame.frame_type, frame.flags)

    aggregator = Http2Aggregator()
    REGISTRY.register(aggregator)
    start_http_server(args.port, addr=args.addr)

    fn = bpf.load_func("http2_xdp_prog", BPF.XDP)
    # Attach at the pod's veth. XDP_FLAGS_SKB_MODE keeps it working on veth
    # pairs whose driver has no native XDP support.
    bpf.attach_xdp(args.iface, fn, BPF.XDP_FLAGS_SKB_MODE)
    print(f"HTTP/2 XDP tracing on {args.iface}; "
          f"metrics on http://{args.addr}:{args.port}/metrics", flush=True)

    bpf["samples"].open_perf_buffer(on_sample)
    bpf["frame_events"].open_ring_buffer(on_frame)

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    try:
        while not stop.is_set():
            bpf.perf_buffer_poll(timeout=200)
            bpf.ring_buffer_consume()
    finally:
        bpf.remove_xdp(args.iface, BPF.XDP_FLAGS_SKB_MODE)


def run_http1(args) -> None:
    source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "http_profiler.c")
    bpf = BPF(src_file=source, cflags=[
        f"-DTARGET_TGID={args.pid or 0}",
        f'-DTARGET_COMM="{args.comm or ""}"',
    ])
    REGISTRY.register(ProfilerCollector(bpf))
    start_http_server(args.port, addr=args.addr)
    print(f"tracing {'pid ' + str(args.pid) if args.pid else 'comm ' + args.comm}; "
          f"metrics on http://{args.addr}:{args.port}/metrics", flush=True)

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    stop.wait()  # Tracepoints detach when the BPF object is released on exit.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int, help="trace this process id")
    target.add_argument("--comm", help="trace processes whose main-thread name is exactly "
                                       "this (all their threads), e.g. tessera-api")
    parser.add_argument("--http2", action="store_true",
                        help="trace HTTP/2 on an interface instead of HTTP/1 syscalls")
    parser.add_argument("--iface", help="veth interface of the Kubernetes pod (HTTP/2 mode)")
    parser.add_argument("--addr", default="0.0.0.0", help="metrics listen address")
    parser.add_argument("--port", type=int, default=9436, help="metrics listen port")
    args = parser.parse_args()

    if args.http2:
        if not args.iface:
            parser.error("--http2 requires --iface <pod veth>")
        if args.comm:
            parser.error("--http2 traces a pod interface; use --pid for the workload id")
    elif args.iface:
        parser.error("--iface is only valid with --http2")
    if args.pid is not None and args.pid <= 0:
        parser.error("--pid must be a positive process id")
    if args.comm is not None and not COMM_RE.match(args.comm):
        parser.error("--comm must be 1-15 characters of [A-Za-z0-9_.-]")

    if args.http2:
        run_http2(args)
    else:
        run_http1(args)


if __name__ == "__main__":
    main()
