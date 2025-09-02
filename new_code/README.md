# 🚀 Real-Time Intrusion Detection Pipeline (Linux + DPDK + Suricata + Kafka)

This project implements a **real-time intrusion detection pipeline** using:

* **Pktgen-DPDK** → high-speed traffic generation
* **Suricata (DPDK mode)** → packet capture and flow extraction
* **Feature extraction** → CICIDS2017-style features
* **Apache Kafka** → streaming pipeline
* **Machine Learning model** → intrusion detection (via scikit-learn joblib model)

The pipeline supports multiple profiles (**normal, DoS, DDoS, mixed**) and streams traffic features in real-time for classification.

---

## 📋 Prerequisites

### 1. Operating System

* Linux (Ubuntu 20.04/22.04 recommended)
* Root or `sudo` privileges for DPDK NIC binding and hugepages

### 2. Dependencies

#### Core packages

```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip \
    git cmake meson ninja-build libnuma-dev \
    libpcap-dev zlib1g-dev libpcre3-dev \
    libyaml-dev libjansson-dev pkg-config \
    openjdk-11-jre tmux netcat
```

#### Python packages

```bash
pip install -r requirements.txt
```

`requirements.txt` should contain:

```
pandas
numpy
joblib
kafka-python
```

#### Apache Kafka + Zookeeper

Download and extract Kafka:

```bash
wget https://downloads.apache.org/kafka/3.6.1/kafka_2.13-3.6.1.tgz
tar -xzf kafka_2.13-3.6.1.tgz
export KAFKA_HOME=$PWD/kafka_2.13-3.6.1
```

---

### 3. DPDK + Pktgen-DPDK

#### Install DPDK

```bash
git clone https://github.com/DPDK/dpdk.git
cd dpdk
meson build
ninja -C build
sudo ninja -C build install
```

#### Install Pktgen-DPDK

```bash
git clone https://github.com/pktgen/Pktgen-DPDK.git
cd Pktgen-DPDK
meson build
ninja -C build
```

---

### 4. Suricata (with DPDK enabled)

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata
```

Verify that Suricata supports DPDK:

```bash
suricata --build-info | grep DPDK
```

If not, rebuild Suricata with `--enable-dpdk`.

---

## ⚙️ System Preparation

### Hugepages

```bash
sudo sh -c 'echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
sudo mkdir -p /dev/hugepages
sudo mount -t hugetlbfs nodev /dev/hugepages
```

### Bind NICs to DPDK

Find PCI IDs of NICs:

```bash
lspci | grep Eth
```

Bind to `vfio-pci`:

```bash
sudo modprobe vfio-pci
sudo dpdk-devbind.py -b vfio-pci 0000:03:00.0 0000:03:00.1
```

---

## 📂 Project Structure

```
.
├── traffic_simulation.py   # Linux-native pipeline (DPDK + Suricata)
├── kafka_sim.py            # Kafka producer (streams features)
├── ml_integration.py       # Kafka consumer + ML model
├── run_pipeline.sh         # Orchestration script (tmux)
├── suricata-dpdk.yaml      # Suricata config (DPDK capture)
├── pktgen.lua              # Pktgen traffic script
├── intrusion_detection_model.joblib  # Trained ML model
└── output/                 # Generated features & logs
```

---

## ▶️ Running the Pipeline

### 1. Start Everything

```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

This script will:

1. Start Zookeeper
2. Start Kafka broker
3. Launch traffic simulation (Pktgen + Suricata-DPDK) and stream features into Kafka
4. Launch ML consumer to classify traffic in real-time

---

### 2. Run Components Individually

**Generate & extract features only:**

```bash
python3 traffic_simulation.py --profiles normal,dos,mixed
```

**Stream features to Kafka:**

```bash
python3 kafka_sim.py
```

**Run ML classifier:**

```bash
python3 ml_integration.py
```

---

## 📊 Outputs

* **Suricata logs & eve.json**: in `./output/suricata_dpdk_*`
* **Extracted features**: CSV files in `./output/`
* **Real-time predictions**: printed by `ml_integration.py`

---

## 🔧 Customization

* **NICs / PCI IDs** → edit `traffic_simulation.py` (`pci_devs`)
* **Suricata DPDK config** → `suricata-dpdk.yaml`
* **Traffic generation** → edit `pktgen.lua` (synthetic or PCAP replay)
* **Kafka brokers/topic** → set env vars:

  ```bash
  export KAFKA_BROKERS=127.0.0.1:9092
  export KAFKA_TOPIC=network-traffic
  ```

---

## 🛠 Troubleshooting

* **No eve.json output** → check Suricata logs, ensure NICs bound to DPDK and Suricata started with `--dpdk`.
* **Pktgen fails** → confirm PCI IDs are correct and hugepages mounted.
* **Kafka connection error** → ensure `KAFKA_HOME` is set and broker is running.
* **Permission errors** → you may need `sudo` for DPDK NIC binding or Suricata.

---

## 📌 Notes

* This pipeline is meant as a **research/educational IDS prototype**, not production.
* DPDK requires **dedicated NICs**; don’t bind your primary management interface to DPDK.
* Throughput depends heavily on CPU cores, NIC capabilities, and Suricata tuning.

---
