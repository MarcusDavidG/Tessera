// SPDX-License-Identifier: GPL-2.0
//
// Tessera — eBPF HTTP/2 request tracing without code instrumentation
// (issue #392).
//
// The program is an XDP hook, attached by http_profiler.py to a Kubernetes
// pod's veth interface. It parses Ethernet → IPv4/IPv6 → TCP → HTTP/2 and:
//
//   1. walks HTTP/2 frame headers (HEADERS, DATA, RST_STREAM, SETTINGS) out of
//      the packet with bpf_xdp_load_bytes() — XDP's packet-load helper; the
//      skb-only bpf_skb_load_bytes() is not available to XDP programs;
//   2. decodes the HPACK header block of HEADERS frames far enough to read the
//      `:path`, `:method`, `:status` and `content-length` fields (static-table
//      indexes plus uncompressed literals — see "HPACK coverage" below);
//   3. records the request start time per (flow, stream) and, when the
//      response HEADERS frame arrives, emits a sample tuple
//      (timestamp_ns, pid, path_hash, status, latency_ns) to the
//      `samples` perf_event_array map for the Prometheus exporter;
//   4. copies every parsed HEADERS frame (its raw HPACK block included) into
//      the `frame_events` BPF ring buffer, so a user-space tracer can run a
//      complete HPACK decoder when the in-kernel one could not decode a value.
//
// HPACK coverage: values are decoded when they are static-table indexes or
// uncompressed string literals. Huffman-coded literals (the common case for a
// literal `:path`) are *not* decoded in the kernel — the Huffman table is far
// too large for the verifier — so those samples carry `path_hash = 0` and the
// raw block is available in `frame_events` for user-space decoding.
//
// `latency_ns` measures HEADERS(request) → HEADERS(response) on the same
// stream: the T+0 latency the application can influence, without waiting for
// the response body. Latency accounting never depends on HPACK decoding, so it
// is available for every stream.
//
// Limits: only frames wholly contained in one packet are parsed (no TCP
// reassembly); four frames per packet are inspected. Both are deliberate: the
// program stays O(1) per packet with no per-flow buffering.

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <bcc/proto.h>

// Compile-time parameter: the workload pid reported in every sample. XDP runs
// in softirq context without the workload's task_struct, so the loader passes
// the pid it resolved for the pod (0 = unknown).
#ifndef TARGET_PID
#define TARGET_PID 0
#endif

#define ETH_P_IPV4 0x0800
#define ETH_P_IPV6 0x86dd
#define IPPROTO_TCP_ 6

#define H2_FRAME_DATA 0x0
#define H2_FRAME_HEADERS 0x1
#define H2_FRAME_RST_STREAM 0x3
#define H2_FRAME_SETTINGS 0x4
#define H2_FLAG_END_STREAM 0x1
#define H2_FLAG_END_HEADERS 0x4
#define H2_FLAG_PADDED 0x8
#define H2_FLAG_PRIORITY 0x20

#define MAX_FRAMES_PER_PACKET 4
#define MAX_HEADER_FIELDS 32

enum h2_method {
    H2_METHOD_UNKNOWN = 0,
    H2_METHOD_GET = 1,
    H2_METHOD_POST = 2,
    H2_METHOD_PUT = 3,
    H2_METHOD_DELETE = 4,
    H2_METHOD_HEAD = 5,
    H2_METHOD_PATCH = 6,
    H2_METHOD_OPTIONS = 7,
};

// Direction-independent connection identity, so the request (client → server)
// and the response (server → client) hash to the same key.
struct flow_key {
    u32 lo[4];
    u32 hi[4];
    u16 port_lo;
    u16 port_hi;
};

struct stream_key {
    struct flow_key flow;
    u32 stream_id;
};

// Tuple consumed by the Prometheus exporter.
struct http2_sample {
    u64 timestamp_ns;
    u64 latency_ns;
    u32 pid;
    u32 path_hash;
    u32 status;
    u32 stream_id;
};

// Per-frame trace record (also carries the raw HPACK block).
struct http2_frame_event {
    u64 timestamp_ns;
    u32 stream_id;
    u32 frame_type;
    u32 length;
    u32 path_hash;
    u32 method;
    u32 status;
    u64 content_length;
    u8 flags;
    u8 is_request;
    u16 reserved;
    u8 header_block[192];
    u32 header_block_len;
    u32 reserved2;
};

BPF_HASH(stream_start, struct stream_key, u64, 65536);
BPF_PERF_OUTPUT(samples);
BPF_RINGBUF_OUTPUT(frame_events, 1 << 12);

struct h2_headers {
    u32 path_hash;
    u32 method;
    u32 status;
    u64 content_length;
    u8 is_request;
    u8 has_status;
};

struct hpack_str {
    u32 off;
    u32 len;
    u8 huffman;
};

static __always_inline int pkt_load(struct xdp_md *ctx, void *dst, u32 off, u32 len)
{
    return bpf_xdp_load_bytes(ctx, off, dst, len);
}

static __always_inline u32 fnv1a_byte(u32 hash, u8 byte)
{
    return (hash ^ byte) * 16777619u;
}

static __always_inline u32 hash_static(const char *s, u32 len)
{
    u32 hash = 2166136261u;
#pragma unroll
    for (u32 i = 0; i < 16; i++) {
        if (i >= len)
            break;
        hash = fnv1a_byte(hash, (u8)s[i]);
    }
    return hash;
}

static __always_inline int parse_decimal(struct xdp_md *ctx, const struct hpack_str *s, u64 *out)
{
    if (s->huffman || s->len == 0 || s->len > 18)
        return -1;
    u64 value = 0;
#pragma unroll
    for (u32 i = 0; i < 18; i++) {
        if (i >= s->len)
            break;
        u8 c;
        if (pkt_load(ctx, &c, s->off + i, 1))
            return -1;
        if (c < '0' || c > '9')
            return -1;
        value = value * 10 + (u64)(c - '0');
    }
    *out = value;
    return 0;
}

static __always_inline int hash_header_value(struct xdp_md *ctx, const struct hpack_str *s,
                                             u32 *out)
{
    if (s->huffman || s->len == 0 || s->len > 128)
        return -1;
    u32 hash = 2166136261u;
#pragma unroll
    for (u32 i = 0; i < 128; i++) {
        if (i >= s->len)
            break;
        u8 c;
        if (pkt_load(ctx, &c, s->off + i, 1))
            return -1;
        hash = fnv1a_byte(hash, c);
    }
    *out = hash;
    return 0;
}

static __always_inline int str_equals(struct xdp_md *ctx, const struct hpack_str *s,
                                      const char *want, u32 want_len)
{
    if (s->huffman || s->len != want_len)
        return 0;
#pragma unroll
    for (u32 i = 0; i < 16; i++) {
        if (i >= want_len)
            break;
        u8 c;
        if (pkt_load(ctx, &c, s->off + i, 1))
            return 0;
        if (c != (u8)want[i])
            return 0;
    }
    return 1;
}

static __always_inline u32 method_from_value(struct xdp_md *ctx, const struct hpack_str *value)
{
    if (str_equals(ctx, value, "GET", 3))
        return H2_METHOD_GET;
    if (str_equals(ctx, value, "POST", 4))
        return H2_METHOD_POST;
    if (str_equals(ctx, value, "PUT", 3))
        return H2_METHOD_PUT;
    if (str_equals(ctx, value, "DELETE", 6))
        return H2_METHOD_DELETE;
    if (str_equals(ctx, value, "HEAD", 4))
        return H2_METHOD_HEAD;
    if (str_equals(ctx, value, "PATCH", 5))
        return H2_METHOD_PATCH;
    if (str_equals(ctx, value, "OPTIONS", 7))
        return H2_METHOD_OPTIONS;
    return H2_METHOD_UNKNOWN;
}

// RFC 7541 Appendix A, entries 1..14 — the pseudo-headers and statuses the
// tracer needs. Higher static indexes are not interesting here.
static __always_inline void apply_static_index(u32 index, struct h2_headers *h)
{
    switch (index) {
    case 2:
        h->method = H2_METHOD_GET;
        h->is_request = 1;
        break;
    case 3:
        h->method = H2_METHOD_POST;
        h->is_request = 1;
        break;
    case 4:
        h->path_hash = hash_static("/", 1);
        h->is_request = 1;
        break;
    case 5:
        h->path_hash = hash_static("/index.html", 11);
        h->is_request = 1;
        break;
    case 8:
        h->status = 200;
        h->has_status = 1;
        break;
    case 9:
        h->status = 204;
        h->has_status = 1;
        break;
    case 10:
        h->status = 206;
        h->has_status = 1;
        break;
    case 11:
        h->status = 304;
        h->has_status = 1;
        break;
    case 12:
        h->status = 400;
        h->has_status = 1;
        break;
    case 13:
        h->status = 404;
        h->has_status = 1;
        break;
    case 14:
        h->status = 500;
        h->has_status = 1;
        break;
    default:
        break;
    }
}

// HPACK integer (RFC 7541 §5.1) with a `prefix_bits`-wide first byte.
static __always_inline int read_hpack_int(struct xdp_md *ctx, u32 *off, u32 end, u32 prefix_bits,
                                          u32 *out)
{
    u8 b;
    if (*off >= end || pkt_load(ctx, &b, *off, 1))
        return -1;
    (*off)++;
    u32 mask = (1u << prefix_bits) - 1;
    u32 value = b & mask;
    if (value < mask) {
        *out = value;
        return 0;
    }
    u32 shift = 0;
#pragma unroll
    for (int i = 0; i < 3; i++) {
        if (*off >= end || pkt_load(ctx, &b, *off, 1))
            return -1;
        (*off)++;
        value += (u32)(b & 0x7f) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    *out = value;
    return 0;
}

// String literal length/offset + Huffman flag (RFC 7541 §5.2).
static __always_inline int read_hpack_str(struct xdp_md *ctx, u32 *off, u32 end,
                                          struct hpack_str *s)
{
    u8 b;
    if (*off >= end || pkt_load(ctx, &b, *off, 1))
        return -1;
    s->huffman = (b & 0x80) != 0;
    u32 len = b & 0x7f;
    (*off)++;
    if (len == 0x7f) {
        u32 shift = 0;
#pragma unroll
        for (int i = 0; i < 3; i++) {
            if (*off >= end || pkt_load(ctx, &b, *off, 1))
                return -1;
            (*off)++;
            len += (u32)(b & 0x7f) << shift;
            if (!(b & 0x80))
                break;
            shift += 7;
        }
    }
    s->len = len;
    s->off = *off;
    if (*off + len > end)
        return -1;
    *off += len;
    return 0;
}

// Walk one HPACK header block. Bounded at MAX_HEADER_FIELDS fields.
static __always_inline void parse_header_block(struct xdp_md *ctx, u32 off, u32 end,
                                               struct h2_headers *h)
{
#pragma unroll
    for (int i = 0; i < MAX_HEADER_FIELDS; i++) {
        if (off >= end)
            break;

        u8 b;
        if (pkt_load(ctx, &b, off, 1))
            break;

        // Indexed header field.
        if (b & 0x80) {
            off++;
            apply_static_index(b & 0x7f, h);
            continue;
        }
        // Dynamic table size update.
        if ((b & 0xe0) == 0x20) {
            off++;
            continue;
        }

        // Literal with incremental indexing (6-bit prefix), without indexing
        // or never indexed (4-bit prefix).
        u32 prefix = (b & 0xc0) == 0x40 ? 6 : 4;
        u32 name_index;
        if (read_hpack_int(ctx, &off, end, prefix, &name_index))
            break;

        struct hpack_str name = { .off = 0, .len = 0, .huffman = 0 };
        if (name_index == 0 && read_hpack_str(ctx, &off, end, &name))
            break;

        struct hpack_str value;
        if (read_hpack_str(ctx, &off, end, &value))
            break;

        if (name_index != 0) {
            // Reuse the static table's meaning for the name, then let the
            // literal value refine it where the value is decodable.
            switch (name_index) {
            case 2:
            case 3:
                h->method = name_index == 2 ? H2_METHOD_GET : H2_METHOD_POST;
                h->is_request = 1;
                break;
            case 4:
            case 5:
                h->is_request = 1;
                break;
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
                h->has_status = 1;
                break;
            default:
                break;
            }
        }

        // Literal name paths.
        int named_path = name_index == 4 || name_index == 5;
        int named_method = name_index == 2 || name_index == 3;
        int named_status = name_index >= 8 && name_index <= 14;

        if (name_index == 0) {
            named_path = str_equals(ctx, &name, ":path", 5);
            named_method = str_equals(ctx, &name, ":method", 7);
            named_status = str_equals(ctx, &name, ":status", 7);
        }

        if (named_path) {
            u32 hash;
            if (hash_header_value(ctx, &value, &hash) == 0) {
                h->path_hash = hash;
                h->is_request = 1;
            }
        } else if (named_method) {
            u32 method = method_from_value(ctx, &value);
            if (method != H2_METHOD_UNKNOWN) {
                h->method = method;
                h->is_request = 1;
            }
        } else if (named_status) {
            u64 status;
            if (parse_decimal(ctx, &value, &status) == 0 && status >= 100 && status <= 599) {
                h->status = (u32)status;
                h->has_status = 1;
            }
        } else if (name_index == 0 && str_equals(ctx, &name, "content-length", 14)) {
            u64 length;
            if (parse_decimal(ctx, &value, &length) == 0)
                h->content_length = length;
        }
    }
}

static __always_inline int addr_cmp(const u32 *a, const u32 *b)
{
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

// Order the two endpoints deterministically so both directions share a key.
static __always_inline void make_flow(struct flow_key *flow, const u32 *src, const u32 *dst,
                                      u16 sport, u16 dport)
{
    int cmp = addr_cmp(src, dst);
    if (cmp <= 0 && !(cmp == 0 && sport > dport)) {
        __builtin_memcpy(flow->lo, src, sizeof(flow->lo));
        __builtin_memcpy(flow->hi, dst, sizeof(flow->hi));
        flow->port_lo = sport;
        flow->port_hi = dport;
    } else {
        __builtin_memcpy(flow->lo, dst, sizeof(flow->lo));
        __builtin_memcpy(flow->hi, src, sizeof(flow->hi));
        flow->port_lo = dport;
        flow->port_hi = sport;
    }
}

static __always_inline void emit_frame(struct http2_frame_event *event)
{
    bpf_ringbuf_output(&frame_events, event, sizeof(*event), 0);
}

static __always_inline void emit_sample(struct xdp_md *ctx, u64 now, const struct flow_key *flow,
                                        u32 stream_id, u32 path_hash, u32 status)
{
    struct stream_key key = { .flow = *flow, .stream_id = stream_id };
    u64 *start = stream_start.lookup(&key);
    if (!start)
        return;

    struct http2_sample sample = {
        .timestamp_ns = now,
        .latency_ns = now - *start,
        .pid = TARGET_PID,
        .path_hash = path_hash,
        .status = status,
        .stream_id = stream_id,
    };
    bpf_perf_event_output(ctx, &samples, BPF_F_CURRENT_CPU, &sample, sizeof(sample));
    stream_start.delete(&key);
}

static __always_inline void handle_headers(struct xdp_md *ctx, const struct flow_key *flow,
                                           u32 stream_id, u8 flags, u32 payload, u32 length,
                                           u64 now)
{
    u32 block = payload;
    u32 block_end = payload + length;

    if (flags & H2_FLAG_PADDED) {
        u8 pad_len;
        if (pkt_load(ctx, &pad_len, block, 1))
            return;
        block += 1;
        if ((u32)pad_len + 1 > block_end - payload)
            return;
        block_end -= pad_len;
    }
    if (flags & H2_FLAG_PRIORITY)
        block += 5;
    if (block > block_end)
        return;

    struct h2_headers headers = {};
    parse_header_block(ctx, block, block_end, &headers);

    struct http2_frame_event event = {
        .timestamp_ns = now,
        .stream_id = stream_id,
        .frame_type = H2_FRAME_HEADERS,
        .length = length,
        .path_hash = headers.path_hash,
        .method = headers.method,
        .status = headers.status,
        .content_length = headers.content_length,
        .flags = flags,
        .is_request = headers.is_request,
    };
    if (block_end > block) {
        u32 copy = block_end - block;
        if (copy > sizeof(event.header_block))
            copy = sizeof(event.header_block);
        if (pkt_load(ctx, event.header_block, block, copy) == 0)
            event.header_block_len = copy;
    }
    emit_frame(&event);

    struct stream_key key = { .flow = *flow, .stream_id = stream_id };
    if (headers.is_request) {
        // Keep the earliest request on a stream; pipelined requests share the
        // stream id only across sequential reuse, so this is the current one.
        stream_start.update(&key, &now);
    } else if (headers.has_status) {
        emit_sample(ctx, now, flow, stream_id, headers.path_hash, headers.status);
    }
}

static __always_inline int handle_tcp_payload(struct xdp_md *ctx, const struct flow_key *flow,
                                              u32 off, u32 end, u64 now)
{
#pragma unroll
    for (int i = 0; i < MAX_FRAMES_PER_PACKET; i++) {
        if (off + 9 > end)
            return 0;

        u8 header[9];
        if (pkt_load(ctx, header, off, 9))
            return 0;

        u32 length = ((u32)header[0] << 16) | ((u32)header[1] << 8) | (u32)header[2];
        u8 type = header[3];
        u8 flags = header[4];
        u32 stream_id = (((u32)header[5] << 24) | ((u32)header[6] << 16) |
                         ((u32)header[7] << 8) | (u32)header[8]) & 0x7fffffff;
        u32 payload = off + 9;

        // No TCP reassembly: skip the rest of a frame split across packets.
        if (payload + length > end)
            return 0;

        if (type == H2_FRAME_HEADERS) {
            handle_headers(ctx, flow, stream_id, flags, payload, length, now);
        } else if (type == H2_FRAME_RST_STREAM) {
            struct stream_key key = { .flow = *flow, .stream_id = stream_id };
            stream_start.delete(&key);
        } else if (type == H2_FRAME_DATA || type == H2_FRAME_SETTINGS) {
            struct http2_frame_event event = {
                .timestamp_ns = now,
                .stream_id = stream_id,
                .frame_type = type,
                .length = length,
                .flags = flags,
            };
            emit_frame(&event);
        }

        // DATA frames may be padded too, but their content is not inspected.
        off = payload + length;
    }
    return 0;
}

int http2_xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    u16 eth_type = eth->h_proto;
    u32 off = sizeof(struct ethhdr);

    u32 src[4] = {};
    u32 dst[4] = {};
    u16 sport, dport;

    if (eth_type == ETH_P_IPV4) {
        if (data + off + sizeof(struct iphdr) > data_end)
            return XDP_PASS;
        struct iphdr *ip = data + off;
        if (ip->protocol != IPPROTO_TCP_)
            return XDP_PASS;
        src[0] = ip->saddr;
        dst[0] = ip->daddr;
        off += (u32)ip->ihl * 4;
    } else if (eth_type == ETH_P_IPV6) {
        if (data + off + sizeof(struct ipv6hdr) > data_end)
            return XDP_PASS;
        struct ipv6hdr *ip6 = data + off;
        if (ip6->nexthdr != IPPROTO_TCP_)
            return XDP_PASS;
        __builtin_memcpy(src, &ip6->saddr, sizeof(src));
        __builtin_memcpy(dst, &ip6->daddr, sizeof(dst));
        off += sizeof(struct ipv6hdr);
    } else {
        return XDP_PASS;
    }

    if (data + off + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    struct tcphdr *tcp = data + off;
    sport = tcp->source;
    dport = tcp->dest;
    u32 payload = off + (u32)tcp->doff * 4;
    if (payload >= (u32)((long)data_end - (long)data))
        return XDP_PASS;

    struct flow_key flow;
    make_flow(&flow, src, dst, sport, dport);

    handle_tcp_payload(ctx, &flow, payload, (u32)((long)data_end - (long)data),
                       bpf_ktime_get_ns());
    return XDP_PASS;
}
