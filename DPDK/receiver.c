#include <stdio.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <arpa/inet.h>
#include <signal.h>

#define NUM_MBUFS 4095
#define BURST_SIZE 32

#define PORT_ID 0

int running = 1;

void signal_handler(int signum)
{
    running = 0;
}

// 配置网卡默认信息
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

// 初始化网卡 由dpdk替代内核接管
static void init_port(struct rte_mempool *mbuf_poll)
{
    // 获取网卡数量：uio 或 vfio
    int nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
    {
        printf("No Ethernet ports - bye\n");
    }

    // 获取网卡信息
    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(PORT_ID, &dev_info);
    int socket_id = rte_eth_dev_socket_id(PORT_ID);
    if (ret != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               PORT_ID, strerror(-ret));
    }

    // 配置网卡队列
    const int rx_rings = 1, tx_rings = 0;
    struct rte_eth_conf port_conf = port_conf_default;
    ret = rte_eth_dev_configure(PORT_ID, rx_rings, tx_rings, &port_conf);
    if (ret != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               PORT_ID, strerror(-ret));
    }    

    // 启动接收队列
    ret = rte_eth_rx_queue_setup(PORT_ID, 0, 128, 
                           socket_id, NULL, mbuf_poll);
    if (ret != 0)
    {
        printf("Could not setup receive queue for port %u\n", PORT_ID);
    }

    // 启动网卡
    ret = rte_eth_dev_start(PORT_ID);
    if (ret != 0)
    {
        printf("Could not start port %u\n", PORT_ID);
    }
    // 开启混杂模式
    rte_eth_promiscuous_enable(PORT_ID);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);
    // 初始化dpdk环境
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        printf("Error with EAL initialization\n");
    }

    // 创建内存池
    struct rte_mempool *pMbuf_pool;
    pMbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, 0, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pMbuf_pool == NULL)
    {
        printf("Cannot create mbuf pool\n");
    }

    // 初始化网卡
    init_port(pMbuf_pool);

    while (running)
    {
        // 接收数据
        struct rte_mbuf *pBufs[BURST_SIZE];
        unsigned nb_rx = rte_eth_rx_burst(PORT_ID, 0, pBufs, BURST_SIZE);

        if (nb_rx > BURST_SIZE)
        {
            printf("Error: received %u packets, expected no more than %u\n",
                   nb_rx, BURST_SIZE);
        }

        int i;
        for (i = 0; i < nb_rx; i++)
        {
            // 解析以太网头
            struct rte_ether_hdr *pEther_hdr = rte_pktmbuf_mtod(pBufs[i], struct rte_ether_hdr *);
        
            // 解析ip头
            if(pEther_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            {
                printf("Error: received packet with ether_type %u, expected %u\n",
                       pEther_hdr->ether_type, RTE_ETHER_TYPE_IPV4);
                continue;
            }
            struct rte_ipv4_hdr *pIp_hdr = 
            rte_pktmbuf_mtod_offset(pBufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    
            // 解析udp头
            if(pIp_hdr->next_proto_id != IPPROTO_UDP)
            {
                printf("Error: received packet with next_proto_id %u, expected %u\n",
                       pIp_hdr->next_proto_id, IPPROTO_UDP);
                continue;
            }
            struct rte_udp_hdr *pUdp_hdr = 
                rte_pktmbuf_mtod_offset(pBufs[i], struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
        
            struct in_addr addr;
            addr.s_addr = pIp_hdr->src_addr;
            printf("src_addr: %s:%d\n", inet_ntoa(addr), ntohs(pUdp_hdr->src_port));
                addr.s_addr = pIp_hdr->dst_addr;
            printf("dst_addr: %s:%d\n", inet_ntoa(addr), ntohs(pUdp_hdr->dst_port));

            // 解析数据
            uint16_t data_len = ntohs(pUdp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);
            char buff[data_len];
            memset(buff, 0, data_len + 1);
            memcpy(buff, pUdp_hdr + 1, data_len);
            printf("data: %s\n", buff);
        
            // 释放数据包
            rte_pktmbuf_free(pBufs[i]);
        }
    }
    


    return 0;
}
