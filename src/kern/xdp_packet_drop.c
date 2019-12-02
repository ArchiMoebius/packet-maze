/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../headers/packet_parsers.h"

/* Header cursor to keep track of current parsing position */

struct dropState {
        __u32 dropAll;
};

struct bpf_map_def SEC("maps") ipv4drop = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(short),
        .max_entries = 1,
        .map_flags   = 0
};

#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
        ({                                             \
                char ____fmt[] = fmt;                      \
                bpf_trace_printk(____fmt, sizeof(____fmt), \
                                 ## __VA_ARGS__);           \
        })
#else
#define bpf_debug(fmt, ...) \
        {                       \
        }                       \
        while (0)
#endif

SEC("xdp_packet_trainer")
int xdp_main(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth;
        struct iphdr *ip;
        struct tcphdr *tcphdr;
        const short one = 1;

        __u32 action = XDP_PASS;

        struct hdr_cursor nh;
        int nh_type;
        int p_type;
        int res = 1;
        __u32 key = 0x0;

        nh.pos = data;

        nh_type = parse_ethhdr(&nh, data_end, &eth);

        if (nh_type != bpf_htons(ETH_P_IP))
                goto end;

        p_type = parse_ip4hdr(&nh, data_end, &ip);

        if (p_type != IPPROTO_TCP)
                goto end;

        if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
                goto end;
        }

        struct dropState *dropStateEntry;

        if (ip + 1 > data_end)
                return 0;

        short *value = bpf_map_lookup_elem(&ipv4drop, &key);

        if (value && *value) {
                action = XDP_DROP;
        }

        if (
                bpf_ntohs(tcphdr->dest) == 0x2775 &&
                bpf_ntohs(tcphdr->source) == 0x2775 &&
                bpf_ntohl(tcphdr->seq) == 0x2775
                ) {
                short v = 2;

                if (value <= 0) {
                        value = &v;
                }
                v = *value ^ one;

                if (v) {
                        action = XDP_DROP;
                } else {
                        action = XDP_PASS;
                }

                if ((res = bpf_map_update_elem(
                             &ipv4drop,
                             &key,
                             &v,
                             BPF_ANY
                             ))) {// returns 0 on success
                        bpf_debug("Unable to update 0x%x: %d", key, res);
                }
        }

end:
        return action;
}

char _license[] SEC("license") = "GPL";
