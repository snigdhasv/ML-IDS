#ifndef PACKET_GENERATOR_H
#define PACKET_GENERATOR_H

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <time.h>
#include <pcap.h>
#include <rte_mempool.h>

// Packet generation modes enum
typedef enum
{
    NORMAL_TRAFFIC,
    SYN_FLOOD,
    UDP_FLOOD,
    ICMP_FLOOD
} PacketGenerationMode;

// Function declarations
struct rte_mempool *init_mbuf_pool(void);
pcap_t *init_pcap(const char *pcap_file);
struct rte_mbuf **generate_pcap_burst(struct rte_mempool *mbuf_pool, pcap_t *pcap, uint16_t burst_size);
void free_packet_burst(struct rte_mbuf **mbufs, uint16_t count);

#endif // PACKET_GENERATOR_H