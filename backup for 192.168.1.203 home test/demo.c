#include "kni_demo.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

int flag = 1;

void signal_handle(int sig)
{
    flag = 0;
}

int main()
{
    signal(SIGINT, signal_handle);
    signal(SIGRTMIN, signal_handle);
    
    pthread_t tid;
    pthread_create(&tid, NULL, dpdk_init, NULL);
    //pthread_join(tid, NULL);
    pthread_detach(tid);
    sleep(5);

    unsigned num = 0, i;
    struct rte_mbuf *packets[32];
    while (flag)
    {
        num = get_packets(0, packets);
        for (i = 0; i < num && num; i++)
    {
        struct rte_mbuf *m = packets[i];
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
    }
        kni_burst_free_mbufs(packets, num);
        
    }
    dpdk_destroy();
    return 0;
}