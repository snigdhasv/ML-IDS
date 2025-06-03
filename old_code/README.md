# ML-IDS
In-line network packet processing for Intrusion Detection using ML

#### To Run DPDK files for packet generator and feature extractor
1. create hugepages:
```
sudo sh -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
```

2. Run the files:
```
gcc -o traffic_analyzer main.c packet_generator.c feature_extractor.c -lrte_eal -lrte_ethdev -lrte_mbuf -lrte_mempool -lm -mssse3

sudo ./traffic_analyzer -l 0-3 -n 4
```

