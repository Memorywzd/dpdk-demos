#include <stdint.h>
#include <rte_mbuf.h>

void dpdk_init();

void dpdk_destroy();

struct rte_mbuf** get_packets(uint16_t port_id, unsigned *num);

void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

