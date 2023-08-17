#include <stdint.h>
#include <rte_mbuf.h>

void* dpdk_init();

void dpdk_destroy();

int get_packets(uint16_t port_id, struct rte_mbuf** pkts_burst);

void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

