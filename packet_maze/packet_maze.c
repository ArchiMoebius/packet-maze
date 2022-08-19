#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define LEVEL_1 1
#define LEVEL_2 2
#define LEVEL_3 3
#define LEVEL_4 4
#define LEVEL_5 5
#define LEVEL_6 6

#define LEVEL_1_LIFESPAN 60
#define LEVEL_2_LIFESPAN 60
#define LEVEL_3_LIFESPAN 60
#define LEVEL_4_LIFESPAN 60
#define LEVEL_5_LIFESPAN 60
#define LEVEL_6_LIFESPAN 60

/******************************Level*Zero*Features****************************/
#define ETH_ARP_HDR 256 // htons(ARPHRD_ETHER)
#define ARP_OP 65535

const unsigned char ARP_PAYLOAD[7] = {0x13, 0x37, 0x0, 0xca, 0xfe, 0x0};

struct arp_data_t {
  unsigned char sha[ETH_ALEN]; /* sender hardware address	*/
  unsigned char sip[4];        /* sender IP address		*/
  unsigned char tha[ETH_ALEN]; /* target hardware address	*/
  unsigned char tip[4];        /* target IP address		*/
};
/*****************************************************************************/

/******************************Level*One*Features*****************************/
#define ETH_PAYLOAD_IP 8 // htons(ETH_P_IP)
#define EVIL_IP_FLAG 0x8000
/*****************************************************************************/

/******************************Level*Two*Features*****************************/
#define LEET_IP 117637889 // htonl(16974599) // literally 1.3.3.7
#define ICMP_ECHO_ID 0x42
#define ICMP_ECHO_SEQUENCE 88

struct icmp_data_t {
  u32 ts_originate;
  u32 ts_receive;
  u32 ts_transmit;
};
/*****************************************************************************/

/******************************Level*Three*Features***************************/
#define UDP_PORT 985 // htons(55555)

const unsigned char UDP_PAYLOAD[10] = "[x)0.0(x]";

struct udp_data_t {
  unsigned char pkt[10];
};
/*****************************************************************************/

/******************************Level*Four*Features****************************/
#define TCP_PORT 985 // htons(55555)

const unsigned char TCP_PAYLOAD[7] = "ACK\x00\x01\x02\x03";

struct tcp_data_t {
  unsigned char pkt[7];
};
/*****************************************************************************/

/******************************Level*Five*Features****************************/
#define HTTP_PORT 985 // htons(55555)

const unsigned char HTTP_PAYLOAD[21] = "OPTIONS * HTTP/13\r\n\r\n";

struct http_data_t {
  unsigned char pkt[21];
};
/*****************************************************************************/

struct HashValue {
  int timestamp; // timestamp in ns
  u8 level;
  u8 lifespan;
};

BPF_HASH(sessions, u64, struct HashValue, 1024);

static inline int parse_arp_packet(struct xdp_md *ctx, u64 *hk,
                                   struct HashValue *hv) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct arphdr *arp = data + sizeof(struct ethhdr);
  if ((void *)arp + sizeof(*arp) <= data_end) {

    if (arp->ar_hrd == ETH_ARP_HDR) {

      if (arp->ar_op == ARP_OP) { // op == 0xFFFF
        struct arp_data_t *arpdata = (void *)arp + sizeof(*arp);
        if ((void *)arpdata + sizeof(*arpdata) <= data_end) {

          for (int i = 0; i < 6; i++) {
            if (ARP_PAYLOAD[i] != arpdata->sha[i]) {
              goto fail;
            }
          }

          if (!hv) {
            struct HashValue hashvalue = {};
            hashvalue.lifespan = LEVEL_1_LIFESPAN;
            hashvalue.level = LEVEL_1;

            sessions.insert(hk, &hashvalue);
          } else {
            sessions.delete(hk); // Follow instructions a student should...
          }

          goto drop;

        fail:
          // TODO: insert into hash of 'almost there' for wall of shame?
          bpf_trace_printk("There be dragons %d, you're using a bad "
                           "arphdr->ar_sha value...",
                           hk);
        }

        goto drop; // don't let the host get all confused by our weirdness
      }
    }
  }

end:
  return XDP_PASS;
drop:
  return XDP_DROP;
}

static inline int parse_icmp_packet(struct xdp_md *ctx, u64 *hk,
                                    struct HashValue *hv) {
  // bpf_trace_printk("icmp packet");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)icmp + sizeof(*icmp) <= data_end) {

    if (icmp->type == ICMP_TIMESTAMP &&
        ntohs(icmp->un.echo.id) == ICMP_ECHO_ID &&
        ntohs(icmp->un.echo.sequence) == ICMP_ECHO_SEQUENCE) {

      struct icmp_data_t *icmpdata = (void *)icmp + sizeof(*icmp);
      if ((void *)icmpdata + sizeof(*icmpdata) <= data_end) {

        if (hv->level == LEVEL_2 && icmpdata->ts_originate == LEET_IP) {
          hv->level = LEVEL_3;
          hv->lifespan = LEVEL_3_LIFESPAN;

          sessions.update(hk, hv);

          goto drop; // don't let the host get all confused by our weirdness
        }
      }
    }
  }

end:
  return XDP_PASS;
drop:
  return XDP_DROP;
}
static inline int parse_tcp_packet(struct xdp_md *ctx, u64 *hk,
                                   struct HashValue *hv, u8 iphl) {
  // bpf_trace_printk("tcp packet");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct tcphdr *tcp = data + sizeof(struct ethhdr) + iphl;
  if ((void *)tcp + sizeof(*tcp) <= data_end) {

    if (tcp->ack && !tcp->syn) { // only the data packets no?

      if (tcp->dest == TCP_PORT && tcp->psh) {

        struct tcp_data_t *tcpdata = (void *)tcp + (tcp->doff << 2);

        if ((void *)tcpdata + sizeof(*tcpdata) <= data_end) {

          for (int i = 0; i < sizeof(*tcpdata); i++) {

            if (TCP_PAYLOAD[i] != tcpdata->pkt[i]) {
              goto next;
            }
          }

          if (hv->level == LEVEL_4) {
            hv->level = LEVEL_5;
            hv->lifespan = LEVEL_5_LIFESPAN;

            sessions.update(hk, hv);
          }
        }
      } // level 4

    next:
      if (tcp->dest == HTTP_PORT) {

        struct http_data_t *httpdata = (void *)tcp + (tcp->doff << 2);

        if ((void *)httpdata + sizeof(*httpdata) <= data_end) {
          for (int i = 0; i < sizeof(*httpdata); i++) {
            if (HTTP_PAYLOAD[i] != httpdata->pkt[i]) {
              goto end;
            }
          }

          if (hv->level == LEVEL_5) {
            hv->level = LEVEL_6;
            hv->lifespan = LEVEL_6_LIFESPAN;

            sessions.update(hk, hv);
          }
        }
      } // level 5
    }   // only "data packets"
  }

end:
  return XDP_PASS;
drop:
  return XDP_DROP;
}

static inline int parse_udp_packet(struct xdp_md *ctx, u64 *hk,
                                   struct HashValue *hv) {
  // bpf_trace_printk("udp packet");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if ((void *)udp + sizeof(*udp) <= data_end) {

    if (udp->source == UDP_PORT && udp->dest == UDP_PORT) {
      struct udp_data_t *udpdata = (void *)udp + sizeof(*udp);

      if ((void *)udpdata + sizeof(*udpdata) <= data_end) {

        for (int i = 0; i < sizeof(UDP_PAYLOAD); i++) {

          if (UDP_PAYLOAD[i] != udpdata->pkt[i]) {
            goto end;
          }
        }

        if (hv->level == LEVEL_3) {
          hv->level = LEVEL_4;
          hv->lifespan = LEVEL_4_LIFESPAN;

          sessions.update(hk, hv);
        }

        goto drop; // don't let the host get all confused by our weirdness
      }
    }
  }

end:
  return XDP_PASS;
drop:
  return XDP_DROP;
}

static inline u64 get_eth_key(struct ethhdr *eth) {

  u64 hk = 9001;

  for (short i = 0; i < ETH_ALEN; i++) {
    hk ^= (eth->h_source[i] * i);
  }

  for (short i = 0; i < ETH_ALEN; i++) {
    hk ^= (eth->h_dest[i] * i);
  }

  return hk;
}

int packet_maze_xdp(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;

  if ((void *)eth + sizeof(*eth) <= data_end) {

    uint16_t h_proto = eth->h_proto;

    u64 hk = get_eth_key(eth);

    struct HashValue *hv = sessions.lookup(&hk);

    if (h_proto == htons(ETH_P_IP)) {

      if (!hv) {
        goto end; // player must "register" first xD
      }

      struct iphdr *ip = data + sizeof(*eth);
      if ((void *)ip + sizeof(*ip) <= data_end) {

        if (hv->level == LEVEL_1 && ntohs(ip->frag_off) & 0x8000) {
          hv->level = LEVEL_2;
          hv->lifespan = LEVEL_2_LIFESPAN;

          sessions.update(&hk, hv);
        }

        if (ip->protocol == IPPROTO_TCP) {

          u8 iphl = ip->ihl << 2;

          return parse_tcp_packet(ctx, &hk, hv, iphl);
        } else if (ip->protocol == IPPROTO_ICMP) {
          return parse_icmp_packet(ctx, &hk, hv);
        } else if (ip->protocol == IPPROTO_UDP) {
          return parse_udp_packet(ctx, &hk, hv);
        }
      }
    } else if (h_proto == htons(ETH_P_ARP)) {
      return parse_arp_packet(ctx, &hk, hv);
    }
  }

end:
  return XDP_PASS;
drop:
  return XDP_DROP;
}

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

int packet_maze_socket_filter(struct __sk_buff *skb) {

  int eth_proto = load_byte(skb, offsetof(struct ethhdr, h_proto));
  int size = 0; // by default, do not allow any packet through

  switch (eth_proto) {
  case ETH_PAYLOAD_IP:

    if (ntohs(load_byte(skb, ETH_HLEN + offsetof(struct iphdr, frag_off))) &
        EVIL_IP_FLAG) {
      size = skb->len;
    }
    break;

  /*
    int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    size += sizeof(struct iphdr);
    switch (proto) {
    case IPPROTO_ICMP:
      // bpf_trace_printk("icmp");
      size += sizeof(struct icmphdr);
      break;
    case IPPROTO_TCP:
      // bpf_trace_printk("tcp");
      size += sizeof(struct tcphdr);
      break;
    case IPPROTO_UDP:
      // bpf_trace_printk("udp");
      size += sizeof(struct udphdr);
      break;
    default:
      break;
    }
    break;
  */
  default:
    break;
  }

  return size;
}
