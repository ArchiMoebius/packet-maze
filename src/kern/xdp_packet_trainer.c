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

#include "../headers/xdp_level_user.h"
#include "../headers/packet_parsers.h"

struct bpf_map_def SEC("maps") ipv4hashmap = {
        .type = BPF_MAP_TYPE_PERCPU_HASH,
        .key_size = sizeof(__u32), /* IPv4 Address    */
        .value_size = sizeof(struct userLevelInfo), /* Level struct    */
        .max_entries = 1000, /* enough :-?      */
        .map_flags = BPF_F_NO_PREALLOC,
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

        __u32 action = XDP_PASS;

        struct hdr_cursor nh;
        int nh_type;
        int p_type;
        int res = 1;
        __u32 ip_src = 0;

        nh.pos = data;

        nh_type = parse_ethhdr(&nh, data_end, &eth);

        if (nh_type != bpf_htons(ETH_P_IP))
                goto end;

        p_type = parse_ip4hdr(&nh, data_end, &ip);
        struct userLevelInfo *userLevelInfoByIPv4;

        if (ip + 1 > data_end)
                return 0;

        ip_src = (__u32)bpf_ntohs(ip->saddr);

        userLevelInfoByIPv4 = bpf_map_lookup_elem(&ipv4hashmap, &ip_src);

        if (!userLevelInfoByIPv4)
        {
                struct userLevelInfo userLevelInfoByIPv4New = {};
                userLevelInfoByIPv4New.rx_packets = 0;
                userLevelInfoByIPv4New.key = 0;
                userLevelInfoByIPv4New.level = 0;
                if (!(res = bpf_map_update_elem(
                              &ipv4hashmap,
                              &ip_src,
                              &userLevelInfoByIPv4New,
                              BPF_NOEXIST
                              ))) {// returns 0 on success
                        userLevelInfoByIPv4 = &userLevelInfoByIPv4New;
                        bpf_debug("Made new? [0x%x] : %d", &userLevelInfoByIPv4New, res);
                } else {
                        bpf_debug("Unable to update elem no exst 0x%x, : %d", ip_src, res);
                        goto end;
                }
        }

        userLevelInfoByIPv4->rx_packets++;

        bpf_debug("IP: 0x%x\t[0x%x]\tCount: 0x%x\n", ip_src, userLevelInfoByIPv4, userLevelInfoByIPv4->rx_packets);

        if ((res = bpf_map_update_elem(
                     &ipv4hashmap,
                     &ip_src,
                     userLevelInfoByIPv4,
                     BPF_EXIST
                     ))) {// returns 0 on success
                bpf_debug("Unable to update 0x%x: %d", ip_src, res);
        }

end:
        return action;
}

char _license[] SEC("license") = "GPL";
