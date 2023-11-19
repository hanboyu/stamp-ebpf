#include <linux/bpf.h>

#ifndef COLLECTOR_H
#define COLLECTOR_H

// Max size support 100 flows sending at 5pps
#define STAMP_MAP_SIZE 1800000

struct stamp_data
{
    __u16 ssid;
    __u32 seq;
    __u32 test_tx[2];
    __u32 test_rx[2];
    __u32 reply_tx[2];
    __u64 reply_rx;
};


enum counter_map_key {
    COUNTER_KEY
};


#define NTP_UNIX_OFFSET 2208988800
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

#endif  /* COLLECTOR_H */
