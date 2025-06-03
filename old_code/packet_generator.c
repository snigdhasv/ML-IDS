// packet_generator.c
#include "packet_generator.h"
#include <pcap.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> // Add this line for u_char definition

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

// Initialize a memory pool for packet buffers
struct rte_mempool *init_mbuf_pool(void)
{
    return rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                   MBUF_CACHE_SIZE, 0,
                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                   rte_socket_id());
}

// Initialize a PCAP file for reading
pcap_t *init_pcap(const char *pcap_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_offline(pcap_file, errbuf);
    if (!pcap_handle)
    {
        fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
        return NULL;
    }
    return pcap_handle;
}

// Convert a PCAP packet to a DPDK rte_mbuf
struct rte_mbuf *convert_pcap_to_mbuf(struct rte_mempool *mbuf_pool, const unsigned char *packet, uint32_t packet_len)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf)
    {
        fprintf(stderr, "Failed to allocate mbuf for PCAP packet\n");
        return NULL;
    }

    void *mbuf_data = rte_pktmbuf_mtod(mbuf, void *);
    if (packet_len > RTE_MBUF_DEFAULT_BUF_SIZE)
    {
        fprintf(stderr, "Packet size exceeds buffer size\n");
        rte_pktmbuf_free(mbuf);
        return NULL;
    }

    rte_memcpy(mbuf_data, packet, packet_len);
    mbuf->pkt_len = packet_len;
    mbuf->data_len = packet_len;

    return mbuf;
}

// Generate a burst of packets from a PCAP file
struct rte_mbuf **generate_pcap_burst(struct rte_mempool *mbuf_pool, pcap_t *pcap, uint16_t burst_size)
{
    struct rte_mbuf **mbufs = malloc(sizeof(struct rte_mbuf *) * burst_size);
    if (!mbufs)
        return NULL;

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int packet_count = 0;

    while (packet_count < burst_size && pcap_next_ex(pcap, &header, &packet) > 0)
    {
        struct rte_mbuf *mbuf = convert_pcap_to_mbuf(mbuf_pool, packet, header->caplen);
        if (mbuf)
        {
            mbufs[packet_count++] = mbuf;
        }
        else
        {
            fprintf(stderr, "Failed to process PCAP packet\n");
        }
    }

    for (int i = packet_count; i < burst_size; i++)
        mbufs[i] = NULL; // Fill remaining slots with NULLs

    return mbufs;
}

void free_packet_burst(struct rte_mbuf **mbufs, uint16_t count)
{
    if (!mbufs)
        return;

    for (uint16_t i = 0; i < count; i++)
    {
        if (mbufs[i])
        {
            rte_pktmbuf_free(mbufs[i]);
        }
    }
    free(mbufs);
}
