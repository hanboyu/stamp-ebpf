/**
 * @author Boyu Han
 * @email bh2470@nyu.edu
 * @create date Nov 19th, 2023
 * @modify date May 27th, 2024
 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "collector.h"
#include "../stamp.h"


static __always_inline struct stamp_reply_pkt* is_stamp_packet(struct hdr_cursor *nh, void *data_end){

	struct ethhdr *eth_hdr;
	struct iphdr *ipv4_hdr;
	struct udphdr *udp_hdr;
	struct stamp_reply_pkt *stamp_reply_pkt;
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
	stamp_reply_pkt = nh->pos;
	if (stamp_reply_pkt + 1 > data_end) {
		return NULL;
	}
	if (stamp_reply_pkt->mbz16 || stamp_reply_pkt->mbz8[0] || stamp_reply_pkt->mbz8[1] || stamp_reply_pkt->mbz8[2]){
		return NULL;
	}

	return stamp_reply_pkt;

}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct stamp_data);
	__uint(max_entries, STAMP_MAP_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} stamp_data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} counter_map SEC(".maps");

SEC("xdp")
int  stamp_collector(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh; /* These keep track of the next header type and iterator pointer */
	struct stamp_data *temp_data;
	struct stamp_reply_pkt *stamp_pkt;
	__u32 *counter;
	__u32 counter_map_key = COUNTER_KEY;

	nh.pos = data;
	
	stamp_pkt = is_stamp_packet(&nh, data_end);
	if (!stamp_pkt){
		return XDP_PASS;
	}

	// bpf_printk("Verified STAMP packet");


	/* Get BPF map */
	counter = bpf_map_lookup_elem(&counter_map, &counter_map_key);
	if (!counter){
		bpf_printk("Fail to look up counter map");
		return XDP_PASS;
	}

	temp_data = bpf_map_lookup_elem(&stamp_data_map, counter);	
	if (!temp_data){
		bpf_printk("Fail to look up stamp_data_map");
		return XDP_PASS;
	}


	/* Extract and store STAMP packet data */
	temp_data->ssid = bpf_ntohs(stamp_pkt->ssid);
	temp_data->seq = bpf_ntohs(stamp_pkt->seq);
	temp_data->test_tx[0] = bpf_ntohl(stamp_pkt->sender_tx_timestamp[0]);
	temp_data->test_tx[1] = bpf_ntohl(stamp_pkt->sender_tx_timestamp[1]);
	temp_data->test_rx[0] = bpf_ntohl(stamp_pkt->rx_timestamp[0]);
	temp_data->test_rx[1] = bpf_ntohl(stamp_pkt->rx_timestamp[1]);
	temp_data->reply_tx[0] = bpf_ntohl(stamp_pkt->tx_timestamp[0]);
	temp_data->reply_tx[1] = bpf_ntohl(stamp_pkt->tx_timestamp[1]);
	temp_data->reply_rx = bpf_ktime_get_ns();

	
	// bpf_printk("counter: %u, ssid: %u, seq: %u", *counter, temp_data->ssid, temp_data->seq);
	

	/* Increment counter */
	if (*counter + 1 >= STAMP_MAP_SIZE){
		*counter = 0;
	}
	else{
		*counter += 1;
	}

	return XDP_DROP;
}

/* SPDX-License-Identifier: GPL-2.0 */
char _license[] SEC("license") = "GPL";