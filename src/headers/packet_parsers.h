#ifndef PACKET_PARSERS
#define PACKET_PARSERS

struct hdr_cursor
{
        void *pos;
};


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


static __always_inline int parse_tcphdr(
        struct hdr_cursor *nh,
        void *data_end,
        struct tcphdr **tcphdr)
{
        int len;
        struct tcphdr *h = nh->pos;

        if (h + 1 > data_end)
                return -1;

        len = h->doff * 4;
        if ((void *) h + len > data_end)
                return -1;

        nh->pos  = h + 1;
        *tcphdr = h;

        return len;
}

#endif
