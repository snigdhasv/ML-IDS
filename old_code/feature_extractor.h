#ifndef FEATURE_EXTRACTOR_H
#define FEATURE_EXTRACTOR_H

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdio.h>
#include <math.h>
#include <signal.h>
#include <string.h>

// Structure definitions (all the existing structures: bulk_stats, packet_stats, flow_features)
// [Previous structure definitions remain the same]

// Constants
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_PACKETS_BURST 32
#define MAX_FLOW_ARRAY 1024
#define CSV_FILENAME "flow_features.csv"
#define EXPORT_INTERVAL 10
#define ACTIVE_TIMEOUT 120000000 // 120 seconds in microseconds
#define IDLE_TIMEOUT 30000000    // 30 seconds in microseconds

// Bulk statistics structure
struct bulk_stats
{
    uint64_t total_bytes;
    uint32_t total_packets;
    uint32_t bulk_count;
    uint64_t bulk_start_time;
    bool in_bulk;
    double avg_bytes_bulk;
    double avg_packets_bulk;
    double avg_bulk_rate;
};

// Packet statistics structure
struct packet_stats
{
    uint32_t count;
    uint64_t total_length;
    uint16_t max_length;
    uint16_t min_length;
    double mean_length;
    double stddev_length;
    double sum_squared; // For standard deviation calculation

    uint64_t last_arrival;
    uint64_t *iat_times;
    uint64_t iat_total;
    uint32_t iat_count;
    double iat_mean;
    uint64_t iat_max;
    uint64_t iat_min;
    double iat_stddev;
    double packets_per_sec;

    uint32_t psh_count;
    uint32_t urg_count;

    uint32_t header_length;
    uint16_t init_win_bytes;
    uint32_t act_data_pkt;
    uint16_t min_seg_size;
    double avg_segment_size;

    struct bulk_stats bulk;
};

// Flow features structure
struct flow_features
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    uint64_t start_time;
    uint64_t last_seen;
    uint64_t flow_duration;

    struct packet_stats fwd;
    struct packet_stats bwd;

    uint64_t *flow_iat_times;
    uint32_t flow_iat_count;
    double flow_iat_mean;
    double flow_iat_std;
    uint64_t flow_iat_max;
    uint64_t flow_iat_min;

    uint16_t min_packet_length;
    uint16_t max_packet_length;
    double packet_length_mean;
    double packet_length_std;
    double packet_length_variance;

    uint32_t psh_flag_count;
    double down_up_ratio;
    double avg_packet_size;

    uint32_t fin_count;
    uint32_t syn_count;
    uint32_t rst_count;
    uint32_t ack_count;
    uint32_t urg_count;
    uint32_t cwe_count;
    uint32_t ece_count;

    double flow_bytes_per_sec;
    double flow_packets_per_sec;

    uint64_t *active_times;
    uint64_t *idle_times;
    uint32_t active_count;
    uint32_t idle_count;
    double active_mean;
    uint64_t active_max;
    uint64_t active_min;
    double active_stddev;
    double idle_mean;
    uint64_t idle_max;
    uint64_t idle_min;
    double idle_stddev;

    uint32_t subflow_fwd_packets;
    uint64_t subflow_fwd_bytes;
    uint32_t subflow_bwd_packets;
    uint64_t subflow_bwd_bytes;

    uint64_t last_active_time;
    uint8_t is_active;
};

// Global variables
extern struct flow_features flows[MAX_FLOW_ARRAY];
extern int num_flows;

// Function declarations
void init_feature_extractor(const char *csv_filename);
void extract_features(struct rte_mbuf *mbuf);
void export_features_to_csv(void);
void cleanup_feature_extractor(void);
void process_packet_burst(struct rte_mbuf **mbufs, uint16_t count);

// External variables that need to be accessible
extern volatile sig_atomic_t force_quit;

#endif // FEATURE_EXTRACTOR_H