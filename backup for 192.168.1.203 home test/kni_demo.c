/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_flow.h>
#include <rte_flow_classify.h>
#include <rte_table_acl.h>
#include <rte_per_lcore.h>
#include <rte_ip_frag.h>

#include "kni_demo.h"

#define SRC_IP ((0<<24) + (0<<16) + (0<<8) + 0) /* src ip = 0.0.0.0 */
#define DEST_IP ((239<<24) + (255<<16) + (0<<8) + 1) /* dest ip = 192.168.1.1 */
#define FULL_MASK 0xffffffff /* full mask */
#define EMPTY_MASK 0x0 /* empty mask */

int real_count = 0;

struct rte_flow *
generate_ipv4_flow(uint16_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error);

struct rte_flow *
generate_ipv4_flow(uint16_t port_id, uint16_t rx_q,
		uint32_t src_ip, uint32_t src_mask,
		uint32_t dest_ip, uint32_t dest_mask,
		struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action action[2];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = rx_q };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	int res;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/*
	 * set the rule attribute.
	 * in this case only ingress packets will be checked.
	 */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (ETH).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	/*
	 * setting the second level of the pattern (IP).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ip_spec.hdr.dst_addr = htonl(dest_ip);
	ip_mask.hdr.dst_addr = dest_mask;
	ip_spec.hdr.src_addr = htonl(src_ip);
	ip_mask.hdr.src_addr = src_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;

	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);

	return flow;
}

#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_NUM_CLASSIFY 200
#define FLOW_FILTER_MIN_PRIORITY 62

#define COMMENT_LEAD_CHAR	('#')
/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)


/* flow classify data */
static int num_flow_filters = 0;

/* parameters for rte_flow_classify_validate and
 * rte_flow_classify_table_entry_add functions
 */

static struct rte_flow_item  eth_item = { RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0 };
static struct rte_flow_item  end_item = { RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0 };
struct rte_flow_action_queue queue = { .index = 1 };
static struct rte_flow_action queue_action = { RTE_FLOW_ACTION_TYPE_QUEUE,
    &queue};
static struct rte_flow_action end_action = { RTE_FLOW_ACTION_TYPE_END, 0};
static struct rte_flow_action actions[2];

static int
get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim,
		char dlm)
{
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(*in, &end, base);
	if (errno != 0 || end[0] != dlm || val > lim)
		return -EINVAL;
	*fd = (uint32_t)val;
	*in = end + 1;
	return 0;
}

static int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint32_t a, b, c, d, m;

	if (get_cb_field(&in, &a, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &b, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &c, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &d, 0, UINT8_MAX, '/'))
		return -EINVAL;
	if (get_cb_field(&in, &m, 0, sizeof(uint32_t) * CHAR_BIT, 0))
		return -EINVAL;

	addr[0] = RTE_IPV4(a, b, c, d);
	mask_len[0] = m;
	return 0;
}

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_MASK,
	CB_FLD_DST_PORT,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_MASK,
	CB_FLD_PROTO,
	CB_FLD_PRIORITY,
	CB_FLD_NUM,
};

const char cb_port_delim[] = ":";
static int
parse_ipv4_5tuple_rule(char *str, struct rte_eth_ntuple_filter *ntuple_filter)
{
	int i, ret;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = CB_FLD_NUM;
	uint32_t temp;

	s = str;
	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	ret = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&ntuple_filter->src_ip,
			&ntuple_filter->src_ip_mask);
	if (ret != 0) {
		RTE_LOG(ERR, APP, "failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return ret;
	}

	ret = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&ntuple_filter->dst_ip,
			&ntuple_filter->dst_ip_mask);
	if (ret != 0) {
		RTE_LOG(ERR, APP, "failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return ret;
	}

	if (get_cb_field(&in[CB_FLD_SRC_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_SRC_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_DST_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_DST_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, '/'))
		return -EINVAL;
	ntuple_filter->proto = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, 0))
		return -EINVAL;
	ntuple_filter->proto_mask = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PRIORITY], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->priority = (uint16_t)temp;
	if (ntuple_filter->priority > FLOW_FILTER_MIN_PRIORITY)
		ret = -EINVAL;

	return ret;
}

/* Bypass comment and empty lines */
static inline int
is_bypass_line(char *buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

static uint32_t
convert_depth_to_bitmask(uint32_t depth_val)
{
	uint32_t bitmask = 0;
	int i, j;

	for (i = depth_val, j = 0; i > 0; i--, j++)
		bitmask |= (1 << (31 - j));
	return bitmask;
}

static int
add_classify_rule(struct rte_eth_ntuple_filter *ntuple_filter)
{
    int ret = -1;
	static struct rte_flow_attr attr;
    struct rte_flow_error error;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item ipv4_udp_item;
	struct rte_flow_item ipv4_tcp_item;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item udp_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item tcp_item;
	struct rte_flow_item pattern_ipv4_5tuple[4];
	struct rte_flow *flow = NULL;
	uint8_t ipv4_proto;

	if (num_flow_filters >= MAX_NUM_CLASSIFY) {
		printf(
			"\nINFO:  classify rule capacity %d reached\n",
			num_flow_filters);
		return ret;
	}

    struct in_addr saddr, daddr;
    saddr.s_addr = ntohl(ntuple_filter->src_ip);
    daddr.s_addr = ntohl(ntuple_filter->dst_ip);
    RTE_LOG(INFO, APP, "proto=%x, src_ip=%s, dst_ip=%s\n", ntuple_filter->proto, inet_ntoa(saddr),inet_ntoa(daddr));
	/* set up parameters for validate and add */
	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = ntuple_filter->proto;
	ipv4_spec.hdr.src_addr = ntuple_filter->src_ip;
	ipv4_spec.hdr.dst_addr = ntuple_filter->dst_ip;
	ipv4_proto = ipv4_spec.hdr.next_proto_id;

	memset(&ipv4_mask, 0, sizeof(ipv4_mask));
	ipv4_mask.hdr.next_proto_id = ntuple_filter->proto_mask;
	ipv4_mask.hdr.src_addr = ntuple_filter->src_ip_mask;
	ipv4_mask.hdr.src_addr =
		convert_depth_to_bitmask(ipv4_mask.hdr.src_addr);
	ipv4_mask.hdr.dst_addr = ntuple_filter->dst_ip_mask;
	ipv4_mask.hdr.dst_addr =
		convert_depth_to_bitmask(ipv4_mask.hdr.dst_addr);

	switch (ipv4_proto) {
	case IPPROTO_UDP:
		ipv4_udp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_udp_item.spec = &ipv4_spec;
		ipv4_udp_item.mask = &ipv4_mask;
		ipv4_udp_item.last = NULL;

		udp_spec.hdr.src_port = ntuple_filter->src_port;
		udp_spec.hdr.dst_port = ntuple_filter->dst_port;
		udp_spec.hdr.dgram_len = 0;
		udp_spec.hdr.dgram_cksum = 0;

		udp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		udp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
		udp_mask.hdr.dgram_len = 0;
		udp_mask.hdr.dgram_cksum = 0;

		udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		udp_item.spec = &udp_spec;
		udp_item.mask = &udp_mask;
		udp_item.last = NULL;

		attr.priority = ntuple_filter->priority;
		pattern_ipv4_5tuple[1] = ipv4_udp_item;
		pattern_ipv4_5tuple[2] = udp_item;
		break;
	case IPPROTO_TCP:
		ipv4_tcp_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		ipv4_tcp_item.spec = &ipv4_spec;
		ipv4_tcp_item.mask = &ipv4_mask;
		ipv4_tcp_item.last = NULL;

		memset(&tcp_spec, 0, sizeof(tcp_spec));
		tcp_spec.hdr.src_port = ntuple_filter->src_port;
		tcp_spec.hdr.dst_port = ntuple_filter->dst_port;

		memset(&tcp_mask, 0, sizeof(tcp_mask));
		tcp_mask.hdr.src_port = ntuple_filter->src_port_mask;
		tcp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;

		tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
		tcp_item.spec = &tcp_spec;
		tcp_item.mask = &tcp_mask;
		tcp_item.last = NULL;

		attr.priority = ntuple_filter->priority;
		pattern_ipv4_5tuple[1] = ipv4_tcp_item;
		pattern_ipv4_5tuple[2] = tcp_item;
		break;
	default:
		return ret;
	}

	attr.ingress = 1;
	pattern_ipv4_5tuple[0] = eth_item;
	pattern_ipv4_5tuple[3] = end_item;
	actions[0] = queue_action;
	actions[1] = end_action;

	/* Validate and add rule */
	ret = rte_flow_validate(0, &attr,
			pattern_ipv4_5tuple, actions, &error);
	if (ret) {
		printf("Filter validate failed ipv4_proto = %u,message:%s\n",
			ipv4_proto, error.message);
		return ret;
	}

	flow = rte_flow_create(0, &attr,
			pattern_ipv4_5tuple, actions, &error);
	if (!flow) {
		printf("Filter add failed ipv4_proto = %u,message:%s\n",
			ipv4_proto, error.message);
		ret = -1;
		return ret;
	}
	num_flow_filters++;

	return 0;
}

static int
add_rules(const char *rule_path)
{
	RTE_LOG(INFO, APP, "adding flow rules.\n");
    FILE *fh;
	char buff[2048];
	unsigned int i = 0;
	unsigned int total_num = 0;
	struct rte_eth_ntuple_filter ntuple_filter;
	int ret;

	fh = fopen(rule_path, "rb");
	if (fh == NULL)
		rte_exit(EXIT_FAILURE, "%s: fopen %s failed\n", __func__,
			rule_path);

	ret = fseek(fh, 0, SEEK_SET);
	if (ret)
		rte_exit(EXIT_FAILURE, "%s: fseek %d failed\n", __func__,
			ret);

	i = 0;
	while (fgets(buff, 2048, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))
			continue;

		if (parse_ipv4_5tuple_rule(buff, &ntuple_filter) != 0)
			rte_exit(EXIT_FAILURE,
				"%s Line %u: parse rules error\n",
				rule_path, i);

		if (add_classify_rule(&ntuple_filter) != 0)
			rte_exit(EXIT_FAILURE, "add rule error\n");

		total_num++;
	}

	fclose(fh);
	return 0;
}

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048
/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)
/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16) - 1
/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32
/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ
/* Number of RX ring descriptors */
#define NB_RXD                  1024
/* Number of TX ring descriptors */
#define NB_TXD                  1024
/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14
/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4
#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400
#define KNI_MAX_KTHREAD 32
/*
 * Structure of port parameters
 */
struct kni_port_params {
    uint16_t port_id;/* Port ID */
    unsigned lcore_rx; /* lcore ID for RX */
    unsigned lcore_tx; /* lcore ID for TX */
    uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
    uint32_t nb_kni; /* Number of KNI devices to be created */
    unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
    struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;
static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
    .rxmode = {
			.split_hdr_size = 0,
		},
    .txmode = {
			.offloads =
				DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
		},
};
/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;
/* Mask of enabled ports */
static uint32_t ports_mask = 0x1;
/* Monitor link status continually. off by default. */
static int monitor_links;
/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;
    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;
    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;
    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
};
/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];
static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);
static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);
/* Print out statistics on packets handled */
static void
print_stats(void)
{
    uint16_t i;
    printf("\n**KNI example application statistics**\n"
           "======  ==============  ============  ============  ============  ============\n"
           " Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
           "------  --------------  ------------  ------------  ------------  ------------\n");
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (!kni_port_params_array[i])
            continue;
        printf("%7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
                            "%13"PRIu64"\n", i,
                    kni_port_params_array[i]->lcore_rx,
                    kni_port_params_array[i]->lcore_tx,
                        kni_stats[i].rx_packets,
                        kni_stats[i].rx_dropped,
                        kni_stats[i].tx_packets,
                        kni_stats[i].tx_dropped);
    }
    printf("======  ==============  ============  ============  ============  ============\n");
    fflush(stdout);
}
/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
    /* When we receive a USR1 signal, print stats */
    if (signum == SIGUSR1) {
        print_stats();
    }
    /* When we receive a USR2 signal, reset stats */
    if (signum == SIGUSR2) {
        memset(&kni_stats, 0, sizeof(kni_stats));
        printf("\n** Statistics have been reset **\n");
        return;
    }
    /* When we receive a RTMIN or SIGINT signal, stop kni processing */
    if (signum == SIGRTMIN || signum == SIGINT){
        printf("\nSIGRTMIN/SIGINT received. KNI processing stopping.\n");
        rte_atomic32_inc(&kni_stop);
        return;
        }
}
void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;
    if (pkts == NULL)
        return;
    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
        pkts[i] = NULL;
    }
}

/* struct rte_ip_frag_tbl *frag_tbl;
frag_tbl = rte_ip_frag_table_create(
    4096, 16, 4096
); */
int get_packets(uint16_t port_id, struct rte_mbuf** pkts_burst)
{
    unsigned nb_rx;
    
    /* Burst rx from eth */
    nb_rx = rte_eth_rx_burst(port_id, 1, pkts_burst, PKT_BURST_SZ);
    if (unlikely(nb_rx > PKT_BURST_SZ)) {
        RTE_LOG(ERR, APP, "Error receiving from eth\n");
       return;
    }

    /* check if need to reassemble */
    /* int i;
    for (i = 0; i < nb_rx && nb_rx; i++)
    {
        struct rte_mbuf *m = pkts_burst[i];
        struct rte_ipv4_hdr *ip_hdr;
        ip_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        
        if(rte_ipv4_frag_pkt_is_fragmented(ip_hdr))
        {
            struct rte_mbuf *mo;
            frag_tbl = 
        }
    } */
    

    /* for test: print the packet. packet will lost on high speed env. */
    /* for (i = 0; i < nb_rx && nb_rx; i++)
    {
        struct rte_mbuf *m = pkts_burst[i];

        struct rte_ether_hdr *eth_hdr;
        eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        if(eth_hdr->ether_type != 8)continue;
        struct rte_ipv4_hdr *ip_hdr;
        ip_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
        struct rte_tcp_hdr *tcp_hdr = NULL;
        struct rte_udp_hdr *udp_hdr = NULL;
        if(ip_hdr->next_proto_id == 6)
           tcp_hdr = rte_pktmbuf_mtod_offset(m,
           struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
        else if (ip_hdr->next_proto_id == 17)
        udp_hdr = rte_pktmbuf_mtod_offset(m,
            struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
        struct in_addr addr;
        addr.s_addr = ip_hdr->src_addr;
        printf("src = %-15s\t", inet_ntoa(addr));
        addr.s_addr = ip_hdr->dst_addr;
        printf(" - dst = %-15s\t", inet_ntoa(addr));
        uint16_t port;
        if(tcp_hdr)port = rte_be_to_cpu_16(tcp_hdr->src_port);
        else if(udp_hdr)port = rte_be_to_cpu_16(udp_hdr->src_port);
        else port = 0;
        printf(" - src = %-5d", port);
        if(tcp_hdr)port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        else if(udp_hdr)port = rte_be_to_cpu_16(udp_hdr->dst_port);
        else port = 0;
        printf(" - dst = %-5d", port);
		printf(" - queue= 1\n");
    } */

    kni_stats[port_id].rx_packets += nb_rx;
    //kni_burst_free_mbufs(pkts_burst, nb_rx);

    return nb_rx;
}
static void
kni_ingress(struct kni_port_params *p)
{
    uint8_t i;
    uint16_t port_id;
    unsigned nb_rx, num;
    uint32_t nb_kni;
    struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
    if (p == NULL)
        return;
    nb_kni = p->nb_kni;
    port_id = p->port_id;
    for (i = 0; i < nb_kni; i++) {
        /* Burst rx from eth */
        nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
        if (unlikely(nb_rx > PKT_BURST_SZ)) {
            RTE_LOG(ERR, APP, "Error receiving from eth\n");
            return;
        }

        /* Burst tx to kni */
        num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
        if (num)
            kni_stats[port_id].rx_packets += num;
        rte_kni_handle_request(p->kni[i]);
        if (unlikely(num < nb_rx)) {
            /* Free mbufs not tx to kni interface */
            kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
            kni_stats[port_id].rx_dropped += nb_rx - num;
        }
    }
}
static void
kni_egress(struct kni_port_params *p)
{
    uint8_t i;
    uint16_t port_id;
    unsigned nb_tx, num;
    uint32_t nb_kni;
    struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
    if (p == NULL)
        return;
    nb_kni = p->nb_kni;
    port_id = p->port_id;
    for (i = 0; i < nb_kni; i++) {
        /* Burst rx from kni */
        num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
        if (unlikely(num > PKT_BURST_SZ)) {
            RTE_LOG(ERR, APP, "Error receiving from KNI\n");
            return;
        }

        /* wanna to edit the packet, modify the pkts_burst*/
        
        /* Burst tx to eth */
        nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
        if (nb_tx)
            kni_stats[port_id].tx_packets += nb_tx;
        if (unlikely(nb_tx < num)) {
            /* Free mbufs not tx to NIC */
            kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
            kni_stats[port_id].tx_dropped += num - nb_tx;
        }
    }
}
static int
main_loop(__rte_unused void *arg)
{
    uint16_t i;
    int32_t f_stop;
    int32_t f_pause;
    const unsigned lcore_id = rte_lcore_id();
    enum lcore_rxtx {
        LCORE_NONE,
        LCORE_RX,
        LCORE_TX,
        LCORE_MAX
    };
    enum lcore_rxtx flag = LCORE_NONE;
    RTE_ETH_FOREACH_DEV(i) {
        if (!kni_port_params_array[i])
            continue;
        if (kni_port_params_array[i]->lcore_rx == (uint8_t)lcore_id) {
            flag = LCORE_RX;
            break;
        } else if (kni_port_params_array[i]->lcore_tx ==
                        (uint8_t)lcore_id) {
            flag = LCORE_TX;
            break;
        }
    }
    if (flag == LCORE_RX) {
        RTE_LOG(INFO, APP, "Lcore %u is reading from queue 0 on port %d\n",
                    kni_port_params_array[i]->lcore_rx,
                    kni_port_params_array[i]->port_id);
	    /*
	     * Check that the port is on the same NUMA node as the polling thread
	     * for best performance.
	     */
        uint16_t port = 0;
	    if (rte_eth_dev_socket_id(port) >= 0 &&
			    rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
			    printf("\n\n");
			    printf("WARNING: port %u is on remote NUMA node\n",
			           port);
			    printf("to polling thread.\n");
			    printf("Performance will not be optimal.\n");
		}
        while (1) {
            f_stop = rte_atomic32_read(&kni_stop);
            f_pause = rte_atomic32_read(&kni_pause);
            if (f_stop)
                break;
            if (f_pause)
                continue;
            kni_ingress(kni_port_params_array[i]);
        }
    } else if (flag == LCORE_TX) {
        RTE_LOG(INFO, APP, "Lcore %u is writing to port %d\n",
                    kni_port_params_array[i]->lcore_tx,
                    kni_port_params_array[i]->port_id);
        while (1) {
            f_stop = rte_atomic32_read(&kni_stop);
            f_pause = rte_atomic32_read(&kni_pause);
            if (f_stop)
                break;
            if (f_pause)
                continue;
            kni_egress(kni_port_params_array[i]);
        }
    } else {
        RTE_LOG(INFO, APP, "Lcore %u is reading from queue 1 on port %d\n",
                    lcore_id, kni_port_params_array[0]->port_id);
        /* unsigned num_ts;
        while (1) {
            get_packets(kni_port_params_array[0]->port_id, &num_ts);
        } */
    }
    return 0;
}
/* Display usage instructions */
static void
print_usage(const char *prgname)
{
    RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P -m "
           "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
           "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
           "    -p PORTMASK: hex bitmask of ports to use\n"
           "    -P : enable promiscuous mode\n"
           "    -m : enable monitoring of port carrier state\n"
           "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
           "port and lcore configurations\n",
               prgname);
}

static void
print_config(void)
{
    uint32_t i, j;
    struct kni_port_params **p = kni_port_params_array;
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (!p[i])
            continue;
        RTE_LOG(INFO, APP, "Port ID: %d\n", p[i]->port_id);
        RTE_LOG(INFO, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
                    p[i]->lcore_rx, p[i]->lcore_tx);
        for (j = 0; j < p[i]->nb_lcore_k; j++)
            RTE_LOG(INFO, APP, "Kernel thread lcore ID: %u\n",
                            p[i]->lcore_k[j]);
    }
}
static int
parse_config(const char *arg)
{
    const char *p, *p0 = arg;
    char s[256], *end;
    unsigned size;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_LCORE_RX,
        FLD_LCORE_TX,
        _NUM_FLD = KNI_MAX_KTHREAD + 3,
    };
    int i, j, nb_token;
    char *str_fld[_NUM_FLD];
    unsigned long int_fld[_NUM_FLD];
    uint16_t port_id, nb_kni_port_params = 0;
    memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
    while (((p = strchr(p0, '(')) != NULL) &&
        nb_kni_port_params < RTE_MAX_ETHPORTS) {
        p++;
        if ((p0 = strchr(p, ')')) == NULL)
            goto fail;
        size = p0 - p;
        if (size >= sizeof(s)) {
            printf("Invalid config parameters\n");
            goto fail;
        }
        snprintf(s, sizeof(s), "%.*s", size, p);
        nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
        if (nb_token <= FLD_LCORE_TX) {
            printf("Invalid config parameters\n");
            goto fail;
        }
        for (i = 0; i < nb_token; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i]) {
                printf("Invalid config parameters\n");
                goto fail;
            }
        }
        i = 0;
        port_id = int_fld[i++];
        if (port_id >= RTE_MAX_ETHPORTS) {
            printf("Port ID %d could not exceed the maximum %d\n",
                        port_id, RTE_MAX_ETHPORTS);
            goto fail;
        }
        if (kni_port_params_array[port_id]) {
            printf("Port %d has been configured\n", port_id);
            goto fail;
        }
        kni_port_params_array[port_id] =
            rte_zmalloc("KNI_port_params",
                    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
        kni_port_params_array[port_id]->port_id = port_id;
        kni_port_params_array[port_id]->lcore_rx =
                    (uint8_t)int_fld[i++];
        kni_port_params_array[port_id]->lcore_tx =
                    (uint8_t)int_fld[i++];
        if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
        kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
            printf("lcore_rx %u or lcore_tx %u ID could not "
                        "exceed the maximum %u\n",
                kni_port_params_array[port_id]->lcore_rx,
                kni_port_params_array[port_id]->lcore_tx,
                        (unsigned)RTE_MAX_LCORE);
            goto fail;
        }
        for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
            kni_port_params_array[port_id]->lcore_k[j] =
                        (uint8_t)int_fld[i];
        kni_port_params_array[port_id]->nb_lcore_k = j;
    }
    print_config();
    return 0;
fail:
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (kni_port_params_array[i]) {
            rte_free(kni_port_params_array[i]);
            kni_port_params_array[i] = NULL;
        }
    }
    return -1;
}
static int
validate_parameters(uint32_t portmask)
{
    uint32_t i;
    if (!portmask) {
        printf("No port configured in port mask\n");
        return -1;
    }
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
            (!(portmask & (1 << i)) && kni_port_params_array[i]))
            rte_exit(EXIT_FAILURE, "portmask is not consistent "
                "to port ids specified in --config\n");
        if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
            (unsigned)(kni_port_params_array[i]->lcore_rx)))
            rte_exit(EXIT_FAILURE, "lcore id %u for "
                    "port %d receiving not enabled\n",
                    kni_port_params_array[i]->lcore_rx,
                    kni_port_params_array[i]->port_id);
        if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
            (unsigned)(kni_port_params_array[i]->lcore_tx)))
            rte_exit(EXIT_FAILURE, "lcore id %u for "
                    "port %d transmitting not enabled\n",
                    kni_port_params_array[i]->lcore_tx,
                    kni_port_params_array[i]->port_id);
    }
    return 0;
}
#define CMDLINE_OPT_CONFIG  "config"
/* Parse the arguments given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
    int opt, longindex, ret = 0;
    const char *prgname = argv[0];
    static struct option longopts[] = {
        {CMDLINE_OPT_CONFIG, required_argument, NULL, 0},
        {NULL, 0, NULL, 0}
    };
    /* Disable printing messages within getopt() */
    opterr = 0;
    /* Parse command line */
    while ((opt = getopt_long(argc, argv, "m", longopts,
                        &longindex)) != EOF) {
        switch (opt) {
        case 'm':
            monitor_links = 1;
            break;
        case 0:
            if (!strncmp(longopts[longindex].name,
                     CMDLINE_OPT_CONFIG,
                     sizeof(CMDLINE_OPT_CONFIG))) {
                ret = parse_config(optarg);
                if (ret) {
                    printf("Invalid config\n");
                    print_usage(prgname);
                    return -1;
                }
            }
            break;
        default:
            print_usage(prgname);
            rte_exit(EXIT_FAILURE, "Invalid option specified\n");
        }
    }
    /* Check that options were parsed ok */
    if (validate_parameters(ports_mask) < 0) {
        print_usage(prgname);
        rte_exit(EXIT_FAILURE, "Invalid parameters\n");
    }
    return ret;
}
/* Initialize KNI subsystem */
static void
init_kni(void)
{
    unsigned int num_of_kni_ports = 0, i;
    struct kni_port_params **params = kni_port_params_array;
    /* Calculate the maximum number of KNI interfaces that will be used */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        if (kni_port_params_array[i]) {
            num_of_kni_ports += (params[i]->nb_lcore_k ?
                params[i]->nb_lcore_k : 1);
        }
    }
    /* Invoke rte KNI init to preallocate the ports */
    rte_kni_init(num_of_kni_ports);
}
/* Initialise a single port on an Ethernet device */
static void
init_port(uint16_t port)
{
    int ret;
    uint16_t nb_rxd = NB_RXD;
    uint16_t nb_txd = NB_TXD;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
		},
	};
    struct rte_eth_conf local_port_conf = port_conf;
    /* Initialise device and RX/TX queues */
    RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
    fflush(stdout);

    /* struct rte_flow_error error;
    ret = rte_flow_isolate(0, 1, &error);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
            "Error during entering isolated mod (port %u) info: %s\n",
            port, error.message); */

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0)
        rte_exit(EXIT_FAILURE,
            "Error during getting device (port %u) info: %s\n",
            port, strerror(-ret));
    // if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    //     local_port_conf.txmode.offloads |=
    //         DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    local_port_conf.txmode.offloads &= dev_info.tx_offload_capa;        
    ret = rte_eth_dev_configure(port, 2, 2, &local_port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
                    (unsigned)port, ret);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
                "for port%u (%d)\n", (unsigned)port, ret);
    
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    int i;
    for (i = 0; i < 2; i++)
    {
        ret = rte_eth_rx_queue_setup(port, i, nb_rxd,
        rte_eth_dev_socket_id(port), &rxq_conf, pktmbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
                "port%u (%d)\n", (unsigned)port, ret);
    }
    
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    for (i = 0; i < 2; i++)
    {
        ret = rte_eth_tx_queue_setup(port, i, nb_txd,
        rte_eth_dev_socket_id(port), &txq_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
                "port%u (%d)\n", (unsigned)port, ret);
    }
    
                
    ret = rte_eth_dev_start(port);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
                        (unsigned)port, ret);
    /* Display the port MAC address. */
    struct rte_ether_addr addr;
	ret = rte_eth_macaddr_get(port, &addr);
	if (ret != 0)
		return;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);
}
/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    int ret;
    printf("\nChecking link status\n");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        RTE_ETH_FOREACH_DEV(portid) {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                all_ports_up = 0;
                if (print_flag == 1)
                    printf("Port %u link get failed: %s\n",
                        portid, rte_strerror(-ret));
                continue;
            }
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf(
                    "Port%d Link Up - speed %uMbps - %s\n",
                        portid, link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex"));
                else
                    printf("Port %d Link Down\n", portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;
        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }
        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}
static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
    if (kni == NULL || link == NULL)
        return;
    if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
        RTE_LOG(INFO, APP, "%s NIC Link is Up %d Mbps %s %s.\n",
            rte_kni_get_name(kni),
            link->link_speed,
            link->link_autoneg ?  "(AutoNeg)" : "(Fixed)",
            link->link_duplex ?  "Full Duplex" : "Half Duplex");
    } else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
        RTE_LOG(INFO, APP, "%s NIC Link is Down.\n",
            rte_kni_get_name(kni));
    }
}
/*
 * Monitor the link status of all ports and update the
 * corresponding KNI interface(s)
 */
static void *
monitor_all_ports_link_status(void *arg)
{
    uint16_t portid;
    struct rte_eth_link link;
    unsigned int i;
    struct kni_port_params **p = kni_port_params_array;
    int prev;
    (void) arg;
    int ret;
    while (monitor_links) {
        rte_delay_ms(500);
        RTE_ETH_FOREACH_DEV(portid) {
            if ((ports_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            ret = rte_eth_link_get_nowait(portid, &link);
            if (ret < 0) {
                RTE_LOG(ERR, APP,
                    "Get link failed (port %u): %s\n",
                    portid, rte_strerror(-ret));
                continue;
            }
            for (i = 0; i < p[portid]->nb_kni; i++) {
                prev = rte_kni_update_link(p[portid]->kni[i],
                        link.link_status);
                log_link_state(p[portid]->kni[i], prev, &link);
            }
        }
    }
    return NULL;
}
static int
kni_change_mtu_(uint16_t port_id, unsigned int new_mtu)
{
    int ret;
    uint16_t nb_rxd = NB_RXD;
    uint16_t nb_txd = NB_TXD;
    struct rte_eth_conf conf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }
    RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);
    /* Stop specific port */
    rte_eth_dev_stop(port_id);
    memcpy(&conf, &port_conf, sizeof(conf));
    /* Set new MTU */
    if (new_mtu > RTE_ETHER_MAX_LEN)
        conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
    else
        conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;
    /* mtu + length of header + length of FCS = max pkt length */
    conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
                            KNI_ENET_FCS_SIZE;
    ret = rte_eth_dev_configure(port_id, 2, 2, &conf);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
        return ret;
    }
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
                "for port%u (%d)\n", (unsigned int)port_id,
                ret);
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        RTE_LOG(ERR, APP,
            "Error during getting device (port %u) info: %s\n",
            port_id, strerror(-ret));
        return ret;
    }
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
        rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
                port_id);
        return ret;
    }
    ret = rte_eth_rx_queue_setup(port_id, 1, nb_rxd,
        rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
                port_id);
        return ret;
    }
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
        rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to setup Tx queue of port %d\n",
                port_id);
        return ret;
    }
    ret = rte_eth_tx_queue_setup(port_id, 1, nb_txd,
        rte_eth_dev_socket_id(port_id), &txq_conf);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to setup Tx queue of port %d\n",
                port_id);
        return ret;
    }
    /* Restart specific port */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
        return ret;
    }
    return 0;
}
/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
    int ret;
    rte_atomic32_inc(&kni_pause);
    ret =  kni_change_mtu_(port_id, new_mtu);
    rte_atomic32_dec(&kni_pause);
    return ret;
}
/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
    int ret = 0;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }
    RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
                    port_id, if_up ? "up" : "down");
    rte_atomic32_inc(&kni_pause);
    if (if_up != 0) { /* Configure network interface up */
        //rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else /* Configure network interface down */
        rte_eth_dev_stop(port_id);
    rte_atomic32_dec(&kni_pause);
    if (ret < 0)
        RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);
    return ret;
}
static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
    RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}
/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
    int ret = 0;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }
    RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
    print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);
    ret = rte_eth_dev_default_mac_addr_set(port_id,
                    (struct rte_ether_addr *)mac_addr);
    if (ret < 0)
        RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
            port_id);
    return ret;
}
static int
kni_alloc(uint16_t port_id)
{
    uint8_t i;
    struct rte_kni *kni;
    struct rte_kni_conf conf;
    struct kni_port_params **params = kni_port_params_array;
    int ret;
    if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
        return -1;
    params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
                params[port_id]->nb_lcore_k : 1;
    for (i = 0; i < params[port_id]->nb_kni; i++) {
        /* Clear conf at first */
        memset(&conf, 0, sizeof(conf));
        if (params[port_id]->nb_lcore_k) {
            snprintf(conf.name, RTE_KNI_NAMESIZE,
                    "vEth%u_%u", port_id, i);
            conf.core_id = params[port_id]->lcore_k[i];
            conf.force_bind = 1;
        } else
            snprintf(conf.name, RTE_KNI_NAMESIZE,
                        "vEth%u", port_id);
        conf.group_id = port_id;
        conf.mbuf_size = MAX_PACKET_SZ;
        /*
         * The first KNI device associated to a port
         * is the master, for multiple kernel thread
         * environment.
         */
        if (i == 0) {
            struct rte_kni_ops ops;
            struct rte_eth_dev_info dev_info;
            ret = rte_eth_dev_info_get(port_id, &dev_info);
            if (ret != 0)
                rte_exit(EXIT_FAILURE,
                    "Error during getting device (port %u) info: %s\n",
                    port_id, strerror(-ret));
            /* Get the interface default mac address */
            ret = rte_eth_macaddr_get(port_id,
                (struct rte_ether_addr *)&conf.mac_addr);
            if (ret != 0)
                rte_exit(EXIT_FAILURE,
                    "Failed to get MAC address (port %u): %s\n",
                    port_id, rte_strerror(-ret));
            rte_eth_dev_get_mtu(port_id, &conf.mtu);
            conf.min_mtu = dev_info.min_mtu;
            conf.max_mtu = dev_info.max_mtu;
            memset(&ops, 0, sizeof(ops));
            ops.port_id = port_id;
            ops.change_mtu = kni_change_mtu;
            ops.config_network_if = kni_config_network_interface;
            ops.config_mac_address = kni_config_mac_address;
            kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
        } else
            kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);
        if (!kni)
            rte_exit(EXIT_FAILURE, "Fail to create kni for "
                        "port: %d\n", port_id);
        params[port_id]->kni[i] = kni;
    }
    return 0;
}
static int
kni_free_kni(uint16_t port_id)
{
    uint8_t i;
    struct kni_port_params **p = kni_port_params_array;
    if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
        return -1;
    for (i = 0; i < p[port_id]->nb_kni; i++) {
        if (rte_kni_release(p[port_id]->kni[i]))
            printf("Fail to release kni\n");
        p[port_id]->kni[i] = NULL;
    }
    rte_eth_dev_stop(port_id);
    return 0;
}

void* dpdk_init()
{
    char *args[7] = {"./build/app/kni", "-l", "4-5",
                    "-n", "2", "--", "--config=(0,4,5,6)"};
    char **argv = args;
    int ret;
    uint16_t nb_sys_ports;
    unsigned i;

    int argc = 7;

     /* Initialise EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
    argc -= ret;
    argv += ret;
    /* Parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");
    /* Create the mbuf pool */
    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
        MBUF_CACHE_SIZE, 0, MBUF_DATA_SZ, rte_socket_id());
    if (pktmbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
        return;
    }
    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0)
        rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
    /* Check if the configured port ID is valid */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++)
        if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
            rte_exit(EXIT_FAILURE, "Configured invalid "
                        "port ID %u\n", i);
    /* Initialize KNI subsystem */
    init_kni();
    init_port(0);
    kni_alloc(0);

    check_all_ports_link_status(ports_mask);

    /* create flow for send packet with */
	struct rte_flow *flow;
    struct rte_flow_error error;
    flow = generate_ipv4_flow(0, 1,
				SRC_IP, FULL_MASK ,
				DEST_IP, EMPTY_MASK, &error);
	if (!flow) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}

    /* Launch per-lcore function on every lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(i) {
        if (rte_eal_wait_lcore(i) < 0)
            return -1;
    }
}

void dpdk_destroy()
{
    printf("\nSIGRTMIN/SIGINT received. KNI processing stopping.\n");
    rte_atomic32_inc(&kni_stop);
    uint16_t port;
    unsigned i;
    /* Release resources */
    RTE_ETH_FOREACH_DEV(port) {
        if (!(ports_mask & (1 << port)))
            continue;
        kni_free_kni(port);
    }
    for (i = 0; i < RTE_MAX_ETHPORTS; i++)
        if (kni_port_params_array[i]) {
            rte_free(kni_port_params_array[i]);
            kni_port_params_array[i] = NULL;
        }
    /* clean up the EAL */
    rte_eal_cleanup();
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main0(int argc, char** argv)
{
    int ret;
    uint16_t nb_sys_ports, port;
    unsigned i;
    void *retval;
    pthread_t kni_link_tid;
    int pid;

    /* Associate signal_hanlder function with USR signals */
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    signal(SIGRTMIN, signal_handler);
    signal(SIGINT, signal_handler);
    /* Initialise EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
    argc -= ret;
    argv += ret;
    /* Parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");
    /* Create the mbuf pool */
    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
        MBUF_CACHE_SIZE, 0, MBUF_DATA_SZ, rte_socket_id());
    if (pktmbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
        return -1;
    }
    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0)
        rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");
    /* Check if the configured port ID is valid */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++)
        if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
            rte_exit(EXIT_FAILURE, "Configured invalid "
                        "port ID %u\n", i);
    /* Initialize KNI subsystem */
    init_kni();
    init_port(0);
    kni_alloc(0);
    
    check_all_ports_link_status(ports_mask);

    /* create flow for send packet with */
	struct rte_flow *flow;
    struct rte_flow_error error;
    flow = generate_ipv4_flow(0, 1,
				SRC_IP, FULL_MASK ,
				DEST_IP, EMPTY_MASK, &error);
	if (!flow) {
		printf("Flow can't be created %d message: %s\n",
			error.type,
			error.message ? error.message : "(no stated reason)");
		rte_exit(EXIT_FAILURE, "error in creating flow");
	}

    pid = getpid();
    RTE_LOG(INFO, APP, "========================\n");
    RTE_LOG(INFO, APP, "KNI Running\n");
    RTE_LOG(INFO, APP, "kill -SIGUSR1 %d\n", pid);
    RTE_LOG(INFO, APP, "    Show KNI Statistics.\n");
    RTE_LOG(INFO, APP, "kill -SIGUSR2 %d\n", pid);
    RTE_LOG(INFO, APP, "    Zero KNI Statistics.\n");
    RTE_LOG(INFO, APP, "========================\n");
    fflush(stdout);
    ret = rte_ctrl_thread_create(&kni_link_tid,
                     "KNI link status check", NULL,
                     monitor_all_ports_link_status, NULL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
            "Could not create link status thread!\n");
    /* Launch per-lcore function on every lcore */
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(i) {
        if (rte_eal_wait_lcore(i) < 0)
            return -1;
    }
    monitor_links = 0;
    pthread_join(kni_link_tid, &retval);
    /* Release resources */
    RTE_ETH_FOREACH_DEV(port) {
        if (!(ports_mask & (1 << port)))
            continue;
        kni_free_kni(port);
    }
    for (i = 0; i < RTE_MAX_ETHPORTS; i++)
        if (kni_port_params_array[i]) {
            rte_free(kni_port_params_array[i]);
            kni_port_params_array[i] = NULL;
        }
    /* clean up the EAL */
    rte_eal_cleanup();
    return 0;
}