/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../stamp.h"


//compute new checksum
static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u64 csum_add(__u64 csum, __u64 addend) {
    csum += addend;
    return csum + (csum < addend);
}

static __always_inline __u64 csum_sub(__u64 csum, __u64 addend) {
    return csum_add(csum, ~addend);
}

static __always_inline void update_checksum(__u16 *csum, __u16 old, __u16 new) {
    __u64 cs = *csum;
    cs = csum_sub(cs, ~(((__u64)old) << 16));
    cs = csum_add(cs, ((__u64)new) << 16);
    *csum = csum_fold_helper(cs);
}


/*
 * Swaps destination and source MAC addresses inside an Ethernet header
 */
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	__u8 h_tmp[ETH_ALEN];

	__builtin_memcpy(h_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

/*
 * Swaps destination and source IPv4 addresses inside an IPv4 header
 */
static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

static __always_inline struct stamp_reply_pkt* rewrite_stamp_packet(struct hdr_cursor *nh, void *data_end){

	struct ethhdr *eth_hdr;
	struct iphdr *ipv4_hdr;
	struct udphdr *udp_hdr;

	__u16 tmp_port;

	struct stamp_test_pkt *sender_pkt;
	struct stamp_reply_pkt *reflector_pkt;
	
	int ip_hdrsize;

	/* Parse ethernet header */
	eth_hdr = nh->pos;
	if (nh->pos + sizeof(*eth_hdr) > data_end)
		return NULL;
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP))
		return NULL;	
	nh->pos += sizeof(*eth_hdr);

	/* Parse IPv4 header */
	ipv4_hdr = nh->pos;
	if (ipv4_hdr + 1 > data_end)
		return NULL;
	ip_hdrsize = ipv4_hdr->ihl * 4;
	// Sanity check packet field is valid
	if(ip_hdrsize < sizeof(*ipv4_hdr))
		return NULL;
	// Variable-length IPv4 header, need to use byte-based arithmetic
	if (nh->pos + ip_hdrsize > data_end)
		return NULL;
	// Check if UDP
	if (ipv4_hdr->protocol != IPPROTO_UDP) {
		return NULL;
	}
	nh->pos += ip_hdrsize;

	/* Parse UDP header */
	udp_hdr = nh->pos;
	if (udp_hdr + 1 > data_end)
		return NULL;
	if (bpf_ntohs(udp_hdr->len) - sizeof(struct udphdr) < 0){
		return NULL;
	}
	
	// Check UDP source port, STAMP uses 862 by default
	if (bpf_ntohs(udp_hdr->source) != 862)
		return NULL;
	nh->pos  = udp_hdr + 1;

	/* Verify STAMP packet */
	sender_pkt = nh->pos;
	if (sender_pkt + 1 > data_end) {
		return NULL;
	}
	if (sender_pkt->mbz[0] || sender_pkt->mbz[1] || sender_pkt->mbz[2] || sender_pkt->mbz[3] ||
     sender_pkt->mbz[4] || sender_pkt->mbz[5] || sender_pkt->mbz[6]){
		return NULL;
	}

    /* Swap IP source and destination */
	swap_src_dst_ipv4(ipv4_hdr);

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth_hdr);

	/* Patch the packet and update the checksum */
	udp_hdr->check = 0;

	//swap udp dest and source port here
	tmp_port = udp_hdr->source;
    udp_hdr->source = udp_hdr->dest;
    udp_hdr->dest = tmp_port;

	// 在交换端口后，更新校验和
    if (udp_hdr->check != 0) { // 如果原始校验和不为0，则需要更新
        update_checksum(&udp_hdr->check, udp_hdr->source, tmp_port);
        update_checksum(&udp_hdr->check, udp_hdr->dest, udp_hdr->source);
    }

	//store temp data for sender_pkt
	__be32 seq_sender = sender_pkt->seq;
	__be32 sender_tx_timestamp_0 = sender_pkt->sender_tx_timestamp[0];
	__be32 sender_tx_timestamp_1 = sender_pkt->sender_tx_timestamp[1];
	__be16 error_est_sender = sender_pkt->error_est;
	__be16 ssid_sender = sender_pkt->ssid;

	//update reflector_pkt with stored data
	reflector_pkt = nh->pos;

	reflector_pkt->seq = seq_sender;
	reflector_pkt->tx_timestamp[0] = sender_tx_timestamp_0;
	reflector_pkt->tx_timestamp[1] = sender_tx_timestamp_1;
	reflector_pkt->error_est = error_est_sender;
	reflector_pkt->ssid = ssid_sender;
	reflector_pkt->rx_timestamp[0] = sender_tx_timestamp_0;
	reflector_pkt->rx_timestamp[1] = sender_tx_timestamp_1;
	reflector_pkt->sender_seq = ssid_sender;
	reflector_pkt->sender_tx_timestamp[0] = sender_tx_timestamp_0;
	reflector_pkt->sender_tx_timestamp[1] = sender_tx_timestamp_1;
	reflector_pkt->sender_error_est = error_est_sender;
	reflector_pkt->mbz16 = 0;
	reflector_pkt->sender_ttl = 0;


	return reflector_pkt;
}

SEC("xdp")
int  stamp_reflector(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh; /* These keep track of the next header type and iterator pointer */
	struct stamp_reply_pkt *stamp_pkt;

	nh.pos = data;
	
	stamp_pkt = rewrite_stamp_packet(&nh, data_end);
	
	if (stamp_pkt){
		//With XDP_TX, eBPF will redirect packet to the original interface
		return XDP_TX;
	}else{
		return XDP_PASS;
	}
}

char _license[] SEC("license") = "GPL";