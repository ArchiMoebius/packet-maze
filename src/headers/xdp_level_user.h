/*
 * Common struct for level info
 */
#ifndef __XDP_LEVEL_USER_H
#define __XDP_LEVEL_USER_H

struct userLevelInfo
{
    __u64 rx_packets;
    __u32 key;
    __u32 level;
};

#endif /* __XDP_LEVEL_USER_H */
