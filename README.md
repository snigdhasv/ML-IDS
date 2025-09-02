# ML-IDS: Machine Learning Intrusion Detection System

A comprehensive network intrusion detection system that combines high-performance packet processing with machine learning for real-time threat detection.

## 🚀 Overview

ML-IDS is a sophisticated intrusion detection system that leverages:
- **DPDK (Data Plane Development Kit)** for high-performance packet processing
- **Suricata** for network traffic analysis and threat detection
- **Apache Kafka** for real-time data streaming
- **Machine Learning** models trained on CICIDS2017 dataset for anomaly detection
- **WSL2** compatibility for development and testing

## 📁 Project Structure

```
ML-IDS/
├── new_code/                    # Python-based pipeline (Current)
│   ├── traffic_simulation.py    # Main traffic simulation and feature extraction
│   ├── kafka_sim.py            # Kafka producer for streaming features
│   ├── ml_integration.py       # ML model integration with Kafka consumer
│   ├── run_pipeline.sh         # Automated pipeline execution script
│   ├── *.pcap                  # Sample traffic capture files
│   └── intrusion_detection_model.joblib  # Trained ML model
├── ML_Model/                   # Model training and development
│   ├── CICIDS2017_RF.ipynb     # Jupyter notebook for model training
│   └── intrusion_detection_model.joblib  # Trained model
└── old_code/                   # Legacy C-based DPDK implementation
    ├── main.c                  # Main application entry point
    ├── packet_generator.c      # DPDK packet generation
    ├── feature_extractor.c     # Feature extraction from packets
    └── traffic_analyzer        # Compiled binary
```

## 🛠️ Prerequisites

### System Requirements
- **WSL2** (Windows Subsystem for Linux 2) - Recommended
- **Ubuntu 20.04+** or similar Linux distribution
- **Python 3.8+**
- **DPDK 21.11+**
- **Suricata 6.0+**
- **Apache Kafka 2.8+**
- **tmux** (for session management)

### Required Packages

```bash
# System packages
sudo apt update
sudo apt install -y python3 python3-pip tmux netcat-openbsd

# Python dependencies
pip install pandas numpy scikit-learn joblib kafka-python pyspark

# DPDK and Suricata (if not already installed)
sudo apt install -y dpdk suricata tcpreplay tcpdump
```

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd ML-IDS

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Set Kafka home (adjust path as needed)
export KAFKA_HOME=/opt/kafka
```

### 2. Run the Complete Pipeline

The easiest way to run the entire system is using the automated script:

```bash
# Make the script executable
chmod +x new_code/run_pipeline.sh

# Run the complete pipeline
./new_code/run_pipeline.sh
```

This script will:
- Start Zookeeper and Kafka servers
- Launch the traffic simulation pipeline
- Begin ML model integration
- Open a tmux session for monitoring

### 3. Manual Execution

If you prefer to run components individually:

```bash
# Terminal 1: Start Zookeeper
$KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties

# Terminal 2: Start Kafka
$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties

# Terminal 3: Run traffic simulation
cd new_code
python3 kafka_sim.py

# Terminal 4: Run ML integration
python3 ml_integration.py
```

## 🔧 Configuration

### Traffic Simulation Configuration

The `traffic_simulation.py` script can be configured via command-line arguments:

```bash
python3 traffic_simulation.py \
    --profiles "normal,dos,ddos,mixed" \
    --time 300 \
    --interface eth0 \
    --output ./output
```

**Available Options:**
- `--profiles`: Traffic profiles to simulate (normal, dos, ddos, portscan, bruteforce, mixed)
- `--time`: Simulation duration in seconds
- `--interface`: Network interface to use
- `--output`: Output directory for results

### Supported Traffic Profiles

1. **Normal**: Regular network traffic patterns
2. **DoS**: Denial of Service attack traffic
3. **DDoS**: Distributed Denial of Service attack traffic
4. **PortScan**: Port scanning activities
5. **BruteForce**: Brute force attack attempts
6. **Mixed**: Combination of normal and attack traffic

## 📊 Feature Extraction

The system extracts 78 features compatible with the CICIDS2017 dataset:

### Flow-based Features
- Destination Port, Flow Duration
- Packet counts (forward/backward)
- Byte counts (forward/backward)
- Packet length statistics (mean, std, min, max)
- Inter-arrival time statistics
- Flow rates (bytes/s, packets/s)

### Statistical Features
- Packet length variance
- TCP flag counts (FIN, RST, PSH, ACK, URG, ECE)
- Window size statistics
- Active/Idle time measurements
- Subflow statistics

## 🤖 Machine Learning Integration

### Model Training

The ML model is trained using the CICIDS2017 dataset in `ML_Model/CICIDS2017_RF.ipynb`:

```python
# Load and preprocess data
# Train Random Forest classifier
# Save model as joblib file
```

### Real-time Prediction

The `ml_integration.py` script:
- Consumes features from Kafka topic `network-traffic`
- Loads the trained model
- Makes real-time predictions
- Outputs classification results

## 🔍 Monitoring and Logging

### Log Files
- `traffic_pipeline.log`: Main pipeline execution logs
- Kafka logs: Available in `$KAFKA_HOME/logs/`

### tmux Session Management

```bash
# Attach to existing session
tmux attach-session -t kafka_pipeline

# List windows
tmux list-windows -t kafka_pipeline

# Switch between windows
# Ctrl+B, then window number (0-3)
```

## 🏗️ Legacy DPDK Implementation

The `old_code/` directory contains the original C-based DPDK implementation:

### Setup Huge Pages
```bash
sudo sh -c 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge
```

### Compile and Run
```bash
cd old_code
gcc -o traffic_analyzer main.c packet_generator.c feature_extractor.c \
    -lrte_eal -lrte_ethdev -lrte_mbuf -lrte_mempool -lm -mssse3

sudo ./traffic_analyzer -l 0-3 -n 4
```

## 🐛 Troubleshooting

### Common Issues

1. **WSL2 Network Issues**
   ```bash
   # Check WSL version
   wsl.exe --version
   
   # Restart WSL networking
   sudo service networking restart
   ```

2. **DPDK Huge Pages**
   ```bash
   # Check huge pages
   cat /proc/meminfo | grep Huge
   
   # Remount if needed
   sudo mount -t hugetlbfs nodev /dev/hugepages
   ```

3. **Kafka Connection Issues**
   ```bash
   # Check if Kafka is running
   nc -z localhost 9092
   
   # Check Kafka logs
   tail -f $KAFKA_HOME/logs/server.log
   ```

4. **Permission Issues**
   ```bash
   # Ensure proper permissions for network interfaces
   sudo setcap cap_net_raw,cap_net_admin=eip /path/to/your/script
   ```

### Performance Optimization

1. **WSL2 Configuration**
   - Increase memory allocation in `.wslconfig`
   - Enable nested virtualization if needed

2. **DPDK Optimization**
   - Bind network interfaces to DPDK-compatible drivers
   - Configure CPU affinity for better performance

3. **Kafka Tuning**
   - Adjust producer/consumer batch sizes
   - Configure appropriate retention policies

## 📈 Performance Metrics

The system is designed to handle:
- **Packet Processing**: 10,000+ packets/second
- **Feature Extraction**: Real-time processing
- **ML Inference**: < 10ms per prediction
- **Kafka Throughput**: 1,000+ messages/second

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **CICIDS2017 Dataset**: For providing the training data
- **DPDK Community**: For high-performance packet processing framework
- **Suricata Team**: For network threat detection engine
- **Apache Kafka**: For real-time data streaming platform

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs in `traffic_pipeline.log`
3. Open an issue on the repository
4. Contact the development team

---

**Note**: This system is designed for research and educational purposes. For production deployment, additional security measures and testing are recommended.
