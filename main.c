// main.c
#include "packet_generator.h"
#include "feature_extractor.h"
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PACKETS_BURST 32
#define EXPORT_INTERVAL 10
#define PCAP_FILE "/home/snig/CAPSTONE/sample_pcap/smallFlows.pcap"

volatile sig_atomic_t force_quit = 0;

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = 1;
    }
}

static int packet_processing(pcap_t *pcap_handle, struct rte_mempool *mbuf_pool)
{
    time_t last_export_time = time(NULL);

    printf("Starting PCAP-based packet processing...\n");
    printf("Press Ctrl+C to stop and export final results\n");

    while (!force_quit)
    {
        // Generate and process packet burst
        struct rte_mbuf **mbufs = generate_pcap_burst(mbuf_pool, pcap_handle, MAX_PACKETS_BURST);
        if (mbufs)
        {
            process_packet_burst(mbufs, MAX_PACKETS_BURST);
            free_packet_burst(mbufs, MAX_PACKETS_BURST);
        }

        // Periodic export
        time_t current_time = time(NULL);
        if (current_time - last_export_time >= EXPORT_INTERVAL)
        {
            export_features_to_csv();
            last_export_time = current_time;
        }
    }

    // Final export
    export_features_to_csv();
    return 0;
}

int main(int argc, char *argv[])
{
    // Initialize EAL
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Seed random number generator
    srand(time(NULL));

    // Initialize memory pool
    struct rte_mempool *mbuf_pool = init_mbuf_pool();
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    // Open PCAP file
    pcap_t *pcap_handle = init_pcap(PCAP_FILE);
    if (!pcap_handle)
    {
        fprintf(stderr, "Failed to initialize PCAP\n");
        return -1;
    }

    // Initialize feature extractor
    init_feature_extractor("flow_features.csv");

    // Start packet processing
    packet_processing(pcap_handle, mbuf_pool);

    // Cleanup
    pcap_close(pcap_handle);
    cleanup_feature_extractor();
    rte_eal_cleanup();

    return 0;
}
