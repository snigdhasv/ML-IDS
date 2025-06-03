#include "feature_extractor.h"

#define MAX_FLOW_ARRAY 1024
#define ACTIVE_TIMEOUT 120000000 // 120 seconds in microseconds
#define IDLE_TIMEOUT 30000000    // 30 seconds in microseconds

// Global variables
struct flow_features flows[MAX_FLOW_ARRAY];
int num_flows = 0;
static char *output_csv_filename;
static int first_export = 1;

void init_feature_extractor(const char *csv_filename)
{
    output_csv_filename = strdup(csv_filename);
    num_flows = 0;
    first_export = 1;
    memset(flows, 0, sizeof(flows));
}

// - calculate_stddev()
// Helper function to calculate standard deviation
static double calculate_stddev(double sum, double sum_squared, uint32_t count)
{
    if (count < 2)
        return 0.0;
    double mean = sum / count;
    return sqrt((sum_squared / count) - (mean * mean));
}

// - update_packet_stats()
// Helper function to update packet statistics
static void update_packet_stats(struct packet_stats *stats, uint16_t length, uint64_t current_time)
{
    // Update packet counts and lengths
    stats->count++;
    stats->total_length += length;
    stats->max_length = (stats->count == 1) ? length : RTE_MAX(stats->max_length, length);
    stats->min_length = (stats->count == 1) ? length : RTE_MIN(stats->min_length, length);

    // Update running mean and standard deviation calculations
    double delta = length - stats->mean_length;
    stats->mean_length += delta / stats->count;
    stats->sum_squared += delta * (length - stats->mean_length);

    // Update IAT statistics if not the first packet
    if (stats->last_arrival != 0)
    {
        uint64_t iat = current_time - stats->last_arrival;
        stats->iat_times = realloc(stats->iat_times, sizeof(uint64_t) * (stats->iat_count + 1));
        stats->iat_times[stats->iat_count++] = iat;

        // Update IAT statistics
        stats->iat_max = (stats->iat_count == 1) ? iat : RTE_MAX(stats->iat_max, iat);
        stats->iat_min = (stats->iat_count == 1) ? iat : RTE_MIN(stats->iat_min, iat);
        stats->iat_mean = ((stats->iat_mean * (stats->iat_count - 1)) + iat) / stats->iat_count;
    }

    stats->last_arrival = current_time;
}

// - update_flow_activity()
// Function to update flow activity statistics
static void update_flow_activity(struct flow_features *flow, uint64_t current_time)
{
    uint64_t time_diff = current_time - flow->last_seen;

    if (time_diff > IDLE_TIMEOUT && flow->is_active)
    {
        // Flow becomes idle
        uint64_t active_time = flow->last_seen - flow->last_active_time;
        flow->active_times = realloc(flow->active_times, sizeof(uint64_t) * (flow->active_count + 1));
        flow->active_times[flow->active_count++] = active_time;
        flow->is_active = 0;

        // Update active time statistics
        flow->active_max = (flow->active_count == 1) ? active_time : RTE_MAX(flow->active_max, active_time);
        flow->active_min = (flow->active_count == 1) ? active_time : RTE_MIN(flow->active_min, active_time);
        flow->active_mean = ((flow->active_mean * (flow->active_count - 1)) + active_time) / flow->active_count;

        // Record idle period
        flow->idle_times = realloc(flow->idle_times, sizeof(uint64_t) * (flow->idle_count + 1));
        flow->idle_times[flow->idle_count++] = time_diff;
    }
    else if (!flow->is_active && time_diff <= IDLE_TIMEOUT)
    {
        // Flow becomes active again
        flow->last_active_time = current_time;
        flow->is_active = 1;
    }

    flow->last_seen = current_time;
}

// - update_bulk_stats()
// Add this function to update bulk statistics
static void update_bulk_stats(struct bulk_stats *bulk, uint16_t pkt_len, uint64_t current_time)
{
    const uint16_t BULK_THRESHOLD = 1000;  // Minimum bytes to consider as bulk
    const uint32_t BULK_TIMEOUT = 1000000; // 1 second in microseconds

    if (!bulk->in_bulk)
    {
        if (pkt_len > BULK_THRESHOLD)
        {
            bulk->in_bulk = true;
            bulk->bulk_start_time = current_time;
            bulk->total_bytes = pkt_len;
            bulk->total_packets = 1;
        }
    }
    else
    {
        uint64_t time_diff = current_time - bulk->bulk_start_time;
        if (time_diff <= BULK_TIMEOUT)
        {
            bulk->total_bytes += pkt_len;
            bulk->total_packets++;
        }
        else
        {
            // End of bulk transfer
            bulk->bulk_count++;
            bulk->avg_bytes_bulk = ((bulk->avg_bytes_bulk * (bulk->bulk_count - 1)) +
                                    bulk->total_bytes) /
                                   bulk->bulk_count;
            bulk->avg_packets_bulk = ((bulk->avg_packets_bulk * (bulk->bulk_count - 1)) +
                                      bulk->total_packets) /
                                     bulk->bulk_count;
            bulk->avg_bulk_rate = ((bulk->avg_bulk_rate * (bulk->bulk_count - 1)) +
                                   (bulk->total_bytes / (double)time_diff)) /
                                  bulk->bulk_count;
            bulk->in_bulk = false;
        }
    }
}

void extract_features(struct rte_mbuf *mbuf)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    uint64_t current_time = rte_get_tsc_cycles();

    // Create flow key based on 5-tuple
    uint32_t src_ip = ip_hdr->src_addr;
    uint32_t dst_ip = ip_hdr->dst_addr;
    uint16_t src_port = 0, dst_port = 0;
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;

    if (ip_hdr->next_proto_id == IPPROTO_TCP)
    {
        tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
        src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
    }
    else if (ip_hdr->next_proto_id == IPPROTO_UDP)
    {
        udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
        src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
    }

    // Find or create flow entry
    int flow_idx = -1;
    for (int i = 0; i < num_flows; i++)
    {
        if (flows[i].src_ip == src_ip && flows[i].dst_ip == dst_ip &&
            flows[i].src_port == src_port && flows[i].dst_port == dst_port &&
            flows[i].protocol == ip_hdr->next_proto_id)
        {
            flow_idx = i;
            break;
        }
    }

    if (flow_idx == -1 && num_flows < MAX_FLOW_ARRAY)
    {
        flow_idx = num_flows++;
        memset(&flows[flow_idx], 0, sizeof(struct flow_features));
        flows[flow_idx].src_ip = src_ip;
        flows[flow_idx].dst_ip = dst_ip;
        flows[flow_idx].src_port = src_port;
        flows[flow_idx].dst_port = dst_port;
        flows[flow_idx].protocol = ip_hdr->next_proto_id;
        flows[flow_idx].start_time = current_time;
        flows[flow_idx].last_active_time = current_time;
        flows[flow_idx].is_active = 1;
        flows[flow_idx].min_packet_length = UINT16_MAX;
        flows[flow_idx].flow_iat_min = UINT64_MAX;
        flows[flow_idx].fwd.min_length = UINT16_MAX;
        flows[flow_idx].bwd.min_length = UINT16_MAX;
        flows[flow_idx].fwd.iat_min = UINT64_MAX;
        flows[flow_idx].bwd.iat_min = UINT64_MAX;
    }

    if (flow_idx != -1)
    {
        struct flow_features *flow = &flows[flow_idx];
        uint16_t pkt_len = mbuf->pkt_len;

        // Update flow duration and activity
        flow->flow_duration = current_time - flow->start_time;
        update_flow_activity(flow, current_time);

        // Update flow IAT statistics
        if (flow->last_seen > 0)
        {
            uint64_t flow_iat = current_time - flow->last_seen;
            flow->flow_iat_times = realloc(flow->flow_iat_times,
                                           sizeof(uint64_t) * (flow->flow_iat_count + 1));
            flow->flow_iat_times[flow->flow_iat_count] = flow_iat;

            // Update running statistics
            if (flow->flow_iat_count == 0)
            {
                flow->flow_iat_mean = flow_iat;
                flow->flow_iat_max = flow_iat;
                flow->flow_iat_min = flow_iat;
            }
            else
            {
                // Update mean and std dev
                double old_mean = flow->flow_iat_mean;
                flow->flow_iat_mean = old_mean + (flow_iat - old_mean) / (flow->flow_iat_count + 1);
                flow->flow_iat_std = sqrt(
                    (flow->flow_iat_std * flow->flow_iat_std * flow->flow_iat_count +
                     (flow_iat - old_mean) * (flow_iat - flow->flow_iat_mean)) /
                    (flow->flow_iat_count + 1));

                // Update min/max
                flow->flow_iat_max = RTE_MAX(flow->flow_iat_max, flow_iat);
                flow->flow_iat_min = RTE_MIN(flow->flow_iat_min, flow_iat);
            }
            flow->flow_iat_count++;
        }

        // Update packet length statistics
        if (flow->fwd.count + flow->bwd.count == 0)
        {
            flow->min_packet_length = pkt_len;
            flow->max_packet_length = pkt_len;
            flow->packet_length_mean = pkt_len;
            flow->packet_length_variance = 0;
        }
        else
        {
            flow->min_packet_length = RTE_MIN(flow->min_packet_length, pkt_len);
            flow->max_packet_length = RTE_MAX(flow->max_packet_length, pkt_len);

            // Update running mean and variance using Welford's online algorithm
            double old_mean = flow->packet_length_mean;
            double n = flow->fwd.count + flow->bwd.count + 1;
            flow->packet_length_mean += (pkt_len - old_mean) / n;
            flow->packet_length_variance += (pkt_len - old_mean) * (pkt_len - flow->packet_length_mean);
        }
        flow->packet_length_std = sqrt(flow->packet_length_variance /
                                       (flow->fwd.count + flow->bwd.count + 1));

        // Determine packet direction and update statistics
        struct packet_stats *dir_stats;
        if (ip_hdr->src_addr == flow->src_ip)
        {
            dir_stats = &flow->fwd;
            update_bulk_stats(&flow->fwd.bulk, pkt_len, current_time);
            flow->fwd.act_data_pkt++;
        }
        else
        {
            dir_stats = &flow->bwd;
            update_bulk_stats(&flow->bwd.bulk, pkt_len, current_time);
        }

        // Update directional statistics
        dir_stats->count++;
        dir_stats->total_length += pkt_len;
        dir_stats->max_length = RTE_MAX(dir_stats->max_length, pkt_len);
        dir_stats->min_length = RTE_MIN(dir_stats->min_length, pkt_len);

        // Update running mean and stddev
        double old_mean = dir_stats->mean_length;
        dir_stats->mean_length += (pkt_len - old_mean) / dir_stats->count;
        dir_stats->sum_squared += (pkt_len - old_mean) * (pkt_len - dir_stats->mean_length);
        dir_stats->stddev_length = sqrt(dir_stats->sum_squared / dir_stats->count);

        // Update IAT statistics
        if (dir_stats->last_arrival > 0)
        {
            uint64_t iat = current_time - dir_stats->last_arrival;
            dir_stats->iat_total += iat;
            dir_stats->iat_times = realloc(dir_stats->iat_times,
                                           sizeof(uint64_t) * (dir_stats->iat_count + 1));
            dir_stats->iat_times[dir_stats->iat_count] = iat;

            if (dir_stats->iat_count == 0)
            {
                dir_stats->iat_mean = iat;
                dir_stats->iat_max = iat;
                dir_stats->iat_min = iat;
            }
            else
            {
                double old_iat_mean = dir_stats->iat_mean;
                dir_stats->iat_mean += (iat - old_iat_mean) / (dir_stats->iat_count + 1);
                dir_stats->iat_max = RTE_MAX(dir_stats->iat_max, iat);
                dir_stats->iat_min = RTE_MIN(dir_stats->iat_min, iat);
            }
            dir_stats->iat_count++;
        }
        dir_stats->last_arrival = current_time;

        // Update segment sizes
        dir_stats->avg_segment_size = dir_stats->total_length / (double)dir_stats->count;

        // Update packets per second
        double duration_sec = flow->flow_duration / (double)rte_get_timer_hz();
        if (duration_sec > 0)
        {
            flow->fwd.packets_per_sec = flow->fwd.count / duration_sec;
            flow->bwd.packets_per_sec = flow->bwd.count / duration_sec;
        }

        // Update down/up ratio
        if (flow->fwd.count > 0)
        {
            flow->down_up_ratio = (double)flow->bwd.count / flow->fwd.count;
        }

        // Update flow-level packet size statistics
        flow->avg_packet_size = (flow->fwd.total_length + flow->bwd.total_length) /
                                (double)(flow->fwd.count + flow->bwd.count);

        // Update TCP-specific features
        if (tcp_hdr != NULL)
        {
            // Update flag counts
            if (tcp_hdr->tcp_flags & RTE_TCP_PSH_FLAG)
            {
                flow->psh_flag_count++;
                if (ip_hdr->src_addr == flow->src_ip)
                {
                    flow->fwd.psh_count++;
                }
                else
                {
                    flow->bwd.psh_count++;
                }
            }
            if (tcp_hdr->tcp_flags & RTE_TCP_URG_FLAG)
            {
                flow->urg_count++;
                if (ip_hdr->src_addr == flow->src_ip)
                {
                    flow->fwd.urg_count++;
                }
                else
                {
                    flow->bwd.urg_count++;
                }
            }
            if (tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG)
                flow->fin_count++;
            if (tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG)
                flow->syn_count++;
            if (tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG)
                flow->rst_count++;
            if (tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG)
                flow->ack_count++;
            if (tcp_hdr->tcp_flags & RTE_TCP_CWR_FLAG)
                flow->cwe_count++;
            if (tcp_hdr->tcp_flags & RTE_TCP_ECE_FLAG)
                flow->ece_count++;

            // Update window sizes and segment sizes
            if (ip_hdr->src_addr == flow->src_ip)
            {
                if (flow->fwd.count == 1)
                {
                    flow->fwd.init_win_bytes = rte_be_to_cpu_16(tcp_hdr->rx_win);
                }
                flow->fwd.min_seg_size = (flow->fwd.count == 1) ? pkt_len : RTE_MIN(flow->fwd.min_seg_size, pkt_len);
            }
            else
            {
                if (flow->bwd.count == 1)
                {
                    flow->bwd.init_win_bytes = rte_be_to_cpu_16(tcp_hdr->rx_win);
                }
                flow->bwd.min_seg_size = (flow->bwd.count == 1) ? pkt_len : RTE_MIN(flow->bwd.min_seg_size, pkt_len);
            }
        }

        flow->last_seen = current_time;
    }
}

void process_packet_burst(struct rte_mbuf **mbufs, uint16_t count)
{
    for (uint16_t i = 0; i < count; i++)
    {
        if (mbufs[i])
        {
            extract_features(mbufs[i]);
        }
    }
}

void export_features_to_csv(void)
{
    static int first_export = 1;
    FILE *fp = fopen(CSV_FILENAME, first_export ? "w" : "a");
    if (fp == NULL)
    {
        printf("Error opening CSV file!\n");
        return;
    }

    if (first_export)
    {
        fprintf(fp, "src_ip,dst_ip,src_port,dst_port,protocol,"
                    "flow_duration,flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,"
                    "fwd_iat_total,bwd_iat_total,"
                    "fwd_packets,bwd_packets,"
                    "fwd_packets_sec,bwd_packets_sec,"
                    "fwd_bytes,bwd_bytes,"
                    "min_packet_length,max_packet_length,packet_length_mean,"
                    "packet_length_std,packet_length_variance,"
                    "fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,"
                    "bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,"
                    "psh_flag_count,down_up_ratio,avg_packet_size,"
                    "avg_fwd_segment_size,avg_bwd_segment_size,"
                    "fwd_avg_bytes_bulk,fwd_avg_packets_bulk,fwd_avg_bulk_rate,"
                    "bwd_avg_bytes_bulk,bwd_avg_packets_bulk,bwd_avg_bulk_rate,"
                    "act_data_pkt_fwd,min_seg_size_forward,"
                    "fwd_psh_flags,bwd_psh_flags,"
                    "fwd_urg_flags,bwd_urg_flags,"
                    "fin_flags,syn_flags,rst_flags,ack_flags,urg_flags,cwe_flags,ece_flags,"
                    "fwd_header_len,bwd_header_len,"
                    "subflow_fwd_pkts,subflow_fwd_bytes,"
                    "subflow_bwd_pkts,subflow_bwd_bytes,"
                    "init_win_bytes_fwd,init_win_bytes_bwd,"
                    "active_mean,active_max,active_min,active_std,"
                    "idle_mean,idle_max,idle_min,idle_std\n");
        first_export = 0;
    }

    char src_ip_str[16], dst_ip_str[16];
    for (int i = 0; i < num_flows; i++)
    {
        struct flow_features *flow = &flows[i];

        // Convert IPs to strings
        snprintf(src_ip_str, sizeof(src_ip_str), "%u.%u.%u.%u",
                 (flow->src_ip >> 24) & 0xFF, (flow->src_ip >> 16) & 0xFF,
                 (flow->src_ip >> 8) & 0xFF, flow->src_ip & 0xFF);
        snprintf(dst_ip_str, sizeof(dst_ip_str), "%u.%u.%u.%u",
                 (flow->dst_ip >> 24) & 0xFF, (flow->dst_ip >> 16) & 0xFF,
                 (flow->dst_ip >> 8) & 0xFF, flow->dst_ip & 0xFF);

        // Calculate final statistics
        double fwd_stddev = calculate_stddev(flow->fwd.mean_length * flow->fwd.count,
                                             flow->fwd.sum_squared, flow->fwd.count);
        double bwd_stddev = calculate_stddev(flow->bwd.mean_length * flow->bwd.count,
                                             flow->bwd.sum_squared, flow->bwd.count);

        // Calculate IAT standard deviations
        double fwd_iat_stddev = 0, bwd_iat_stddev = 0;
        for (uint32_t j = 0; j < flow->fwd.iat_count; j++)
        {
            double diff = flow->fwd.iat_times[j] - flow->fwd.iat_mean;
            fwd_iat_stddev += diff * diff;
        }
        for (uint32_t j = 0; j < flow->bwd.iat_count; j++)
        {
            double diff = flow->bwd.iat_times[j] - flow->bwd.iat_mean;
            bwd_iat_stddev += diff * diff;
        }
        if (flow->fwd.iat_count > 1)
            fwd_iat_stddev = sqrt(fwd_iat_stddev / flow->fwd.iat_count);
        if (flow->bwd.iat_count > 1)
            bwd_iat_stddev = sqrt(bwd_iat_stddev / flow->bwd.iat_count);

        // Write to CSV
        fprintf(fp, "%s,%s,%u,%u,%u,"
                    "%lu,%.2f,%.2f,%lu,%lu,"
                    "%lu,%lu,"
                    "%u,%u,"
                    "%.2f,%.2f,"
                    "%lu,%lu,"
                    "%u,%u,%.2f,%.2f,%.2f,"
                    "%u,%u,%.2f,%.2f,"
                    "%u,%u,%.2f,%.2f,"
                    "%u,%.2f,%.2f,"
                    "%.2f,%.2f,"
                    "%.2f,%.2f,%.2f,"
                    "%.2f,%.2f,%.2f,"
                    "%u,%u,"
                    "%u,%u,"
                    "%u,%u,"
                    "%u,%u,%u,%u,%u,%u,%u,"
                    "%u,%u,"
                    "%u,%lu,"
                    "%u,%lu,"
                    "%u,%u,"
                    "%.2f,%lu,%lu,%.2f,"
                    "%.2f,%lu,%lu,%.2f\n",
                src_ip_str, dst_ip_str, flow->src_port, flow->dst_port, flow->protocol,
                flow->flow_duration, flow->flow_iat_mean, flow->flow_iat_std,
                flow->flow_iat_max, flow->flow_iat_min,
                flow->fwd.iat_total, flow->bwd.iat_total,
                flow->fwd.count, flow->bwd.count,
                flow->fwd.packets_per_sec, flow->bwd.packets_per_sec,
                flow->fwd.total_length, flow->bwd.total_length,
                flow->min_packet_length, flow->max_packet_length,
                flow->packet_length_mean, flow->packet_length_std,
                flow->packet_length_variance,
                flow->fwd.max_length, flow->fwd.min_length, flow->fwd.mean_length, fwd_stddev,
                flow->bwd.max_length, flow->bwd.min_length, flow->bwd.mean_length, bwd_stddev,
                flow->psh_flag_count, flow->down_up_ratio, flow->avg_packet_size,
                flow->fwd.avg_segment_size, flow->bwd.avg_segment_size,
                flow->fwd.bulk.avg_bytes_bulk, flow->fwd.bulk.avg_packets_bulk,
                flow->fwd.bulk.avg_bulk_rate,
                flow->bwd.bulk.avg_bytes_bulk, flow->bwd.bulk.avg_packets_bulk,
                flow->bwd.bulk.avg_bulk_rate,
                flow->fwd.act_data_pkt, flow->fwd.min_seg_size,
                flow->fwd.psh_count, flow->bwd.psh_count,
                flow->fwd.urg_count, flow->bwd.urg_count,
                flow->fin_count, flow->syn_count, flow->rst_count, flow->ack_count,
                flow->urg_count, flow->cwe_count, flow->ece_count,
                flow->fwd.header_length, flow->bwd.header_length,
                flow->subflow_fwd_packets, flow->subflow_fwd_bytes,
                flow->subflow_bwd_packets, flow->subflow_bwd_bytes,
                flow->fwd.init_win_bytes, flow->bwd.init_win_bytes,
                flow->active_mean, flow->active_max, flow->active_min, flow->active_stddev,
                flow->idle_mean, flow->idle_max, flow->idle_min, flow->idle_stddev);
    }

    fclose(fp);
    printf("Exported %d flows to %s\n", num_flows, CSV_FILENAME);
}

void cleanup_feature_extractor(void)
{
    for (int i = 0; i < num_flows; i++)
    {
        free(flows[i].fwd.iat_times);
        free(flows[i].bwd.iat_times);
        free(flows[i].active_times);
        free(flows[i].idle_times);
    }
    free(output_csv_filename);
}