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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

struct bpf_map_def SEC("maps") ipv4hashmap = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__be32),					/* IPv4 Address    */
	.value_size = sizeof(struct userLevelInfo), /* Level struct    */
	.max_entries = 1000,						/* enough :-?      */
	.map_flags = BPF_F_NO_PREALLOC,
};

#define DEBUG 1

#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                        \
	({                                             \
		char ____fmt[] = fmt;                      \
		bpf_trace_printk(____fmt, sizeof(____fmt), \
						 ##__VA_ARGS__);           \
	})
#else
#define bpf_debug(fmt, ...) \
	{                       \
	}                       \
	while (0)
#endif

static __always_inline int parse_ethhdr(
	struct hdr_cursor *nh,
	void *data_end,
	struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	bpf_debug("Debug: eth_type:0x%x\n", bpf_ntohs(eth->h_proto));

	return eth->h_proto;
}

static __always_inline int parse_ip4hdr(
	struct hdr_cursor *nh,
	void *data_end,
	struct iphdr **ip4hdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip4hdr = iph;

	return (*ip4hdr)->protocol;
}

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
	__be32 ip_src = 0;

	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type != bpf_htons(ETH_P_IP))
		goto end;

	p_type = parse_ip4hdr(&nh, data_end, &ip);
	struct userLevelInfo *userLevelInfoByIPv4;

	if (ip + 1 > data_end)
		return 0;

	ip_src = bpf_ntohs(ip->saddr);

	bpf_debug("Debug: IP:0x%x\n", ip_src);

  userLevelInfoByIPv4 = bpf_map_lookup_elem(&ipv4hashmap, &ip_src);

  if (userLevelInfoByIPv4 <= 0)
  {
    struct userLevelInfo userLevelInfoByIPv4New = {};
    userLevelInfoByIPv4New.rx_packets = 0;
    userLevelInfoByIPv4New.key = 0;
    userLevelInfoByIPv4New.level = 0;
    res = bpf_map_update_elem(
      &ipv4hashmap,
      &ip_src,
      &userLevelInfoByIPv4New,
      BPF_NOEXIST);
  }
  userLevelInfoByIPv4 = bpf_map_lookup_elem(&ipv4hashmap, &ip_src);

  if (userLevelInfoByIPv4 <= 0) {
    goto end;
  }

  userLevelInfoByIPv4->rx_packets++;

  res = bpf_map_update_elem(
    &ipv4hashmap,
    &ip_src,
    userLevelInfoByIPv4,
    BPF_EXIST);
    
end:
	return action;
}

char _license[] SEC("license") = "GPL";
