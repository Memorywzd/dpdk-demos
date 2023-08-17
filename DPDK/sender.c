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

// 指定二层、三层、四层头部信息
//00:80:2f:18:31:e4 enp0s25
uint8_t gDstMac[RTE_ETHER_ADDR_LEN] = {0x00, 0x80, 0x2f, 0x18, 0x31, 0xe4};
//00:80:2f:18:31:e5 enp30s0
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN] = {0x00, 0x80, 0x2f, 0x18, 0x31, 0xe5};

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

// 封装udp包
int make_udp_pkt(unsigned char *pkt, unsigned char *data, uint16_t total_len)
{
    // 造以太网头
    struct rte_ether_hdr *pEther_hdr = (struct rte_ether_hdr *)pkt;
    rte_memcpy(pEther_hdr->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(pEther_hdr->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    pEther_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 造ip头
    struct rte_ipv4_hdr *pIp_hdr = (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));
    pIp_hdr->version_ihl = 0x45;
    pIp_hdr->type_of_service = 0;
    pIp_hdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    pIp_hdr->packet_id = 0;
    pIp_hdr->fragment_offset = 0;
    pIp_hdr->time_to_live = 64;
    pIp_hdr->next_proto_id = IPPROTO_UDP;
    pIp_hdr->src_addr = inet_addr("192.168.1.201");
    pIp_hdr->dst_addr = inet_addr("192.168.1.200");
    pIp_hdr->hdr_checksum = 0;
    pIp_hdr->hdr_checksum = rte_ipv4_cksum(pIp_hdr);

    // 造udp头
    struct rte_udp_hdr *pUdp_hdr = (struct rte_udp_hdr *)(pkt + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    pUdp_hdr->src_port = htons(1234);
    pUdp_hdr->dst_port = htons(5678);
    uint16_t udp_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    pUdp_hdr->dgram_len = htons(udp_len);
    
    // 造数据
    rte_memcpy((uint8_t *)(pUdp_hdr + 1), data, udp_len - sizeof(struct rte_udp_hdr));

    // 计算校验和
    pUdp_hdr->dgram_cksum = 0;
    pUdp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(pIp_hdr, pUdp_hdr);

    // 打印信息
    struct in_addr addr;
    addr.s_addr = pIp_hdr->src_addr;
    printf("src_addr: %s:%d\n", inet_ntoa(addr), ntohs(pUdp_hdr->src_port));
    addr.s_addr = pIp_hdr->dst_addr;
    printf("dst_addr: %s:%d\n", inet_ntoa(addr), ntohs(pUdp_hdr->dst_port));
    
    return 0;
}

// 发送数据
struct rte_mbuf * send_out(struct rte_mbuf *pMbuf_pool, uint8_t *data, int length)
{
    int total_len = length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

    // 开辟内存
    struct rte_mbuf *pMbuf = rte_pktmbuf_alloc(pMbuf_pool);
    if (pMbuf == NULL)
    {
        printf("Error: cannot alloc mbuf\n");
    }

    // 封装数据包
    pMbuf->pkt_len = total_len;
    pMbuf->data_len = total_len;

    uint8_t *pkt = rte_pktmbuf_mtod(pMbuf, uint8_t *);

    make_udp_pkt(pkt, data, total_len);

    return pMbuf;
}

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
    const int rx_rings = 0, tx_rings = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    ret = rte_eth_dev_configure(PORT_ID, rx_rings, tx_rings, &port_conf);
    if (ret != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               PORT_ID, strerror(-ret));
    }
    struct rte_eth_txconf tx_conf = dev_info.default_txconf;
    tx_conf.offloads = port_conf.txmode.offloads;
    
    // 启动发送队列
    ret = rte_eth_tx_queue_setup(PORT_ID, 0, 128, socket_id, &tx_conf);
    if (ret != 0)
    {
        printf("Could not setup transmit queue for port %u\n", PORT_ID);
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
        struct rte_mbuf *pMbuf = send_out(pMbuf_pool, "hello world", 11);
        rte_eth_tx_burst(PORT_ID, 0, &pMbuf, 1);
        rte_pktmbuf_free(pMbuf);
        sleep(5);
    }
    return 0;
}
