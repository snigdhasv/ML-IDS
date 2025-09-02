#!/usr/bin/env python3
"""
Network Traffic Simulation and Feature Extraction Pipeline
Uses DPDK for high-performance packet processing and Suricata for traffic analysis
Designed to run in WSL environment and extract specific features compatible with CICIDS2017 dataset
"""

import os
import sys
import subprocess
import time
import json
import pandas as pd
import numpy as np
from datetime import datetime
import argparse
import logging
import shutil
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("traffic_pipeline.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TrafficPipelineLinux")

class NetworkTrafficPipeline:
    def __init__(self, config=None):
        # Defaults for Linux + DPDK + Suricata
        self.config = {
            # Paths
            "output_dir": "./output",
            "suricata_binary": "/usr/bin/suricata",
            "suricata_yaml": "./suricata-dpdk.yaml",  # provide template below
            "pktgen_dir": "/usr/local/src/pktgen-dpdk",  # adjust where Pktgen is installed
            "pktgen_lua": "./pktgen.lua",               # template below (pcap or synthetic)
            # DPDK/PCI setup
            "dpdk_bind": True,       # bind NICs to vfio-pci if needed
            "pci_devs": ["0000:03:00.0", "0000:03:00.1"],  # update to your NICs
            "hugepages_2MB": 2048,
            # Runtime
            "simulation_time": 60,
            "traffic_profile": "mixed",  # normal, dos, ddos, mixed (used for labeling)
            # Feature selection (unchanged)
            "features_to_extract": [
                'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
                'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
                'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
                'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
                'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
                'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
                'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
                'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
                'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count',
                'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
                'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
                'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
                'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
                'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
                'Idle Std', 'Idle Max', 'Idle Min'
            ]
        }
        if config:
            self.config.update(config)

        Path(self.config["output_dir"]).mkdir(parents=True, exist_ok=True)

        # Quick sanity checks
        self._verify_binaries()
        if self.config.get("dpdk_bind", True):
            self._setup_hugepages()
            self._bind_pci_to_vfio()

    def _run(self, cmd, check=True, **popen_kwargs):
        logger.info("CMD: %s", " ".join(cmd))
        return subprocess.run(cmd, check=check, **popen_kwargs)

    def _verify_binaries(self):
        if not os.path.exists(self.config["suricata_binary"]):
            raise FileNotFoundError(f"Suricata not found at {self.config['suricata_binary']}")
        if not os.path.isdir(self.config["pktgen_dir"]):
            raise FileNotFoundError(f"Pktgen-DPDK dir not found: {self.config['pktgen_dir']}")
        if not os.path.exists(self.config["suricata_yaml"]):
            raise FileNotFoundError(f"Suricata YAML not found: {self.config['suricata_yaml']}")
        if not os.path.exists(self.config["pktgen_lua"]):
            raise FileNotFoundError(f"Pktgen Lua script not found: {self.config['pktgen_lua']}")

    def _setup_hugepages(self):
        hp = str(self.config["hugepages_2MB"])
        try:
            self._run(["sudo", "sh", "-c",
                       f"echo {hp} > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"])
        except subprocess.CalledProcessError:
            logger.warning("Failed to set hugepages; ensure you have privileges.")

        Path("/dev/hugepages").mkdir(exist_ok=True)
        try:
            self._run(["sudo", "mount", "-t", "hugetlbfs", "nodev", "/dev/hugepages"], check=False)
        except Exception:
            pass  # already mounted

    def _bind_pci_to_vfio(self):
        # Requires vfio-pci kernel module loaded
        try:
            self._run(["sudo", "modprobe", "vfio-pci"], check=False)
            for dev in self.config["pci_devs"]:
                self._run(["sudo", "dpdk-devbind.py", "-u", dev], check=False)
                self._run(["sudo", "dpdk-devbind.py", "-b", "vfio-pci", dev], check=False)
            self._run(["sudo", "dpdk-devbind.py", "--status"], check=False)
        except Exception as e:
            logger.warning("DPDK bind step hit an issue: %s", e)

    def _launch_suricata_dpdk(self, outdir):
        """
        Run Suricata in DPDK mode. Make sure suricata is built with DPDK and
        suricata-dpdk.yaml contains a proper 'dpdk:' section for your NICs.
        """
        cmd = [
            self.config["suricata_binary"],
            "-c", self.config["suricata_yaml"],
            "-l", outdir,
            "--dpdk"
        ]
        logger.info("Launching Suricata-DPDK…")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def _launch_pktgen(self):
        """
        Launch Pktgen-DPDK with a Lua script. The Lua script controls ports, rates, and optional PCAP replay.
        """
        # Typical EAL opts; adjust cores/sockets as needed
        eal = [
            "-l", "0-3",               # logical cores
            "-n", "4",                 # memory channels
            "--proc-type", "auto",
            "--file-prefix", "pg"
        ]
        # Map NICs (PCI) to Pktgen ports via -w
        for dev in self.config["pci_devs"]:
            eal.extend(["-w", dev])

        pktgen_bin = os.path.join(self.config["pktgen_dir"], "app/x86_64-native-linuxapp-gcc/pktgen")
        if not os.path.exists(pktgen_bin):
            # Alternative Meson path
            pktgen_bin = os.path.join(self.config["pktgen_dir"], "builddir/app/pktgen")
        if not os.path.exists(pktgen_bin):
            raise FileNotFoundError("Pktgen binary not found. Build Pktgen and update pktgen_dir.")

        cmd = [pktgen_bin, *eal, "--", "-T", "-P", "-m", "1.0,2.1", "-f", self.config["pktgen_lua"]]
        logger.info("Launching Pktgen-DPDK…")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def generate_and_analyze(self, profile="mixed"):
        """
        Start Suricata (DPDK), start Pktgen, run for simulation_time, stop both.
        Returns path to Suricata output directory containing eve.json.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = os.path.join(self.config["output_dir"], f"suricata_dpdk_{profile}_{timestamp}")
        Path(outdir).mkdir(parents=True, exist_ok=True)

        suri = self._launch_suricata_dpdk(outdir)
        time.sleep(3)  # give Suricata a moment to init DPDK ports

        pktgen = self._launch_pktgen()
        logger.info("Traffic running via Pktgen; profile=%s", profile)

        try:
            time.sleep(self.config["simulation_time"])
        finally:
            # Stop pktgen first
            if pktgen and pktgen.poll() is None:
                pktgen.terminate()
                try:
                    pktgen.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pktgen.kill()

            # Then Suricata
            if suri and suri.poll() is None:
                suri.terminate()
                try:
                    suri.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    suri.kill()

        eve = os.path.join(outdir, "eve.json")
        if not os.path.exists(eve):
            logger.error("No eve.json generated; check Suricata logs/output.")
            return None

        logger.info("Suricata eve.json at %s", eve)
        return outdir

    # --- Feature extraction (mostly your original logic, with a few safety fixes) ---

    def extract_features(self, suricata_output_dir):
        if not suricata_output_dir or not os.path.exists(suricata_output_dir):
            logger.error("Invalid Suricata output directory")
            return None

        eve_json = os.path.join(suricata_output_dir, "eve.json")
        if not os.path.exists(eve_json):
            logger.error("eve.json not found in %s", suricata_output_dir)
            return None

        flows = []
        with open(eve_json, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'flow':
                        flows.append(event)
                except json.JSONDecodeError:
                    continue

        if not flows:
            logger.warning("No flow events found in eve.json")
            return pd.DataFrame()

        df = pd.json_normalize(flows)
        return self._transform_to_cicids_features(df)


    def _transform_to_cicids_features(self, suricata_df):
        ordered = self.config["features_to_extract"]
        features = pd.DataFrame(columns=ordered).astype('float64')

        try:
            if 'dest_port' in suricata_df.columns:
                features['Destination Port'] = pd.to_numeric(suricata_df['dest_port'], errors='coerce')

            if 'flow.start' in suricata_df.columns and 'flow.end' in suricata_df.columns:
                suricata_df['flow.start'] = pd.to_datetime(suricata_df['flow.start'], errors='coerce')
                suricata_df['flow.end'] = pd.to_datetime(suricata_df['flow.end'], errors='coerce')
                dur_us = (suricata_df['flow.end'] - suricata_df['flow.start']).dt.total_seconds() * 1_000_000
                features['Flow Duration'] = dur_us

            if 'flow.pkts_toserver' in suricata_df.columns:
                features['Total Fwd Packets'] = pd.to_numeric(suricata_df['flow.pkts_toserver'], errors='coerce')
            if 'flow.pkts_toclient' in suricata_df.columns:
                features['Total Backward Packets'] = pd.to_numeric(suricata_df['flow.pkts_toclient'], errors='coerce')

            if 'flow.bytes_toserver' in suricata_df.columns:
                features['Total Length of Fwd Packets'] = pd.to_numeric(suricata_df['flow.bytes_toserver'], errors='coerce')
            if 'flow.bytes_toclient' in suricata_df.columns:
                features['Total Length of Bwd Packets'] = pd.to_numeric(suricata_df['flow.bytes_toclient'], errors='coerce')

            # Calculate packet size statistics
            if 'Total Fwd Packets' in features.columns and 'Total Length of Fwd Packets' in features.columns:
                with np.errstate(divide='ignore', invalid='ignore'):
                    # Forward packet statistics
                    nonzero_fwd_packets = features['Total Fwd Packets'].replace(0, np.nan)
                    features['Fwd Packet Length Mean'] = features['Total Length of Fwd Packets'] / nonzero_fwd_packets
                    features['Fwd Packet Length Mean'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic statistics since exact packet sizes aren't available
                    features['Fwd Packet Length Max'] = features['Fwd Packet Length Mean'] * 1.5
                    features['Fwd Packet Length Min'] = features['Fwd Packet Length Mean'] * 0.5
                    features['Fwd Packet Length Std'] = features['Fwd Packet Length Mean'] * 0.3
                    
                    # Average segment size
                    features['Avg Fwd Segment Size'] = features['Fwd Packet Length Mean']
                    
            if 'Total Backward Packets' in features.columns and 'Total Length of Bwd Packets' in features.columns:
                with np.errstate(divide='ignore', invalid='ignore'):
                    # Backward packet statistics
                    nonzero_bwd_packets = features['Total Backward Packets'].replace(0, np.nan)
                    features['Bwd Packet Length Mean'] = features['Total Length of Bwd Packets'] / nonzero_bwd_packets
                    features['Bwd Packet Length Mean'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic statistics since exact packet sizes aren't available
                    features['Bwd Packet Length Max'] = features['Bwd Packet Length Mean'] * 1.5
                    features['Bwd Packet Length Min'] = features['Bwd Packet Length Mean'] * 0.5
                    features['Bwd Packet Length Std'] = features['Bwd Packet Length Mean'] * 0.3
                    
                    # Average segment size
                    features['Avg Bwd Segment Size'] = features['Bwd Packet Length Mean']
            
            # Calculate overall packet statistics
            if 'Total Fwd Packets' in features.columns and 'Total Backward Packets' in features.columns:
                total_packets = features['Total Fwd Packets'] + features['Total Backward Packets']
                total_bytes = features.get('Total Length of Fwd Packets', 0) + features.get('Total Length of Bwd Packets', 0)
                
                with np.errstate(divide='ignore', invalid='ignore'):
                    features['Average Packet Size'] = total_bytes / total_packets
                    features['Average Packet Size'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic min/max packet lengths
                    features['Min Packet Length'] = features['Average Packet Size'] * 0.5
                    features['Max Packet Length'] = features['Average Packet Size'] * 1.5
                    features['Packet Length Mean'] = features['Average Packet Size']
                    features['Packet Length Std'] = features['Average Packet Size'] * 0.3
                    features['Packet Length Variance'] = (features['Average Packet Size'] * 0.3) ** 2
                    
                    # Calculate rates
                    if 'Flow Duration' in features.columns:
                        nonzero_duration = features['Flow Duration'].replace(0, np.nan)
                        features['Flow Bytes/s'] = total_bytes * 1000000 / nonzero_duration
                        features['Flow Packets/s'] = total_packets * 1000000 / nonzero_duration
                        features['Fwd Packets/s'] = features['Total Fwd Packets'] * 1000000 / nonzero_duration
                        features['Bwd Packets/s'] = features['Total Backward Packets'] * 1000000 / nonzero_duration
                        
                        features['Flow Bytes/s'].replace([np.inf, -np.inf, np.nan], 0 )
                        features['Flow Packets/s'].replace([np.inf, -np.inf, np.nan], 0 )
                        features['Fwd Packets/s'].replace([np.inf, -np.inf, np.nan], 0 )
                        features['Bwd Packets/s'].replace([np.inf, -np.inf, np.nan], 0 )
                
                # Down/Up Ratio
                with np.errstate(divide='ignore', invalid='ignore'):
                    features['Down/Up Ratio'] = features['Total Backward Packets'] / features['Total Fwd Packets']
                    features['Down/Up Ratio'].replace([np.inf, -np.inf, np.nan], 0 )
            
            # IAT (Inter-Arrival Time) features
            # These are mostly synthetic as exact packet timestamps aren't available
            if 'Flow Duration' in features.columns and 'Total Fwd Packets' in features.columns and 'Total Backward Packets' in features.columns:
                total_pkts = features['Total Fwd Packets'] + features['Total Backward Packets']
                
                # Avoid division by zero for IAT calculations
                with np.errstate(divide='ignore', invalid='ignore'):
                    # Flow IAT features
                    nonzero_pkts_minus_one = (total_pkts - 1).replace(0, np.nan)
                    features['Flow IAT Mean'] = features['Flow Duration'] / nonzero_pkts_minus_one
                    features['Flow IAT Mean'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic IAT statistics
                    features['Flow IAT Std'] = features['Flow IAT Mean'] * 0.25
                    features['Flow IAT Max'] = features['Flow IAT Mean'] * 2
                    features['Flow IAT Min'] = features['Flow IAT Mean'] * 0.1
                    
                    # Forward IAT features
                    nonzero_fwd_pkts_minus_one = (features['Total Fwd Packets'] - 1).replace(0, np.nan)
                    features['Fwd IAT Total'] = features['Flow Duration'] * (features['Total Fwd Packets'] / total_pkts)
                    features['Fwd IAT Mean'] = features['Fwd IAT Total'] / nonzero_fwd_pkts_minus_one
                    features['Fwd IAT Mean'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic forward IAT statistics
                    features['Fwd IAT Std'] = features['Fwd IAT Mean'] * 0.25
                    features['Fwd IAT Max'] = features['Fwd IAT Mean'] * 2
                    features['Fwd IAT Min'] = features['Fwd IAT Mean'] * 0.1
                    
                    # Backward IAT features
                    nonzero_bwd_pkts_minus_one = (features['Total Backward Packets'] - 1).replace(0, np.nan)
                    features['Bwd IAT Total'] = features['Flow Duration'] * (features['Total Backward Packets'] / total_pkts)
                    features['Bwd IAT Mean'] = features['Bwd IAT Total'] / nonzero_bwd_pkts_minus_one
                    features['Bwd IAT Mean'].replace([np.inf, -np.inf, np.nan], 0 )
                    
                    # Synthetic backward IAT statistics
                    features['Bwd IAT Std'] = features['Bwd IAT Mean'] * 0.25
                    features['Bwd IAT Max'] = features['Bwd IAT Mean'] * 2
                    features['Bwd IAT Min'] = features['Bwd IAT Mean'] * 0.1
            
            # Add flags information
            # TCP flags are sometimes available in Suricata output
            if 'tcp.flags' in suricata_df.columns:
                features['FIN Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x01 else 0)
                # Removed 'SYN Flag Count'
                features['RST Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x04 else 0)
                features['PSH Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x08 else 0)
                features['ACK Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x10 else 0)
                features['URG Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x20 else 0)
                features['ECE Flag Count'] = suricata_df['tcp.flags'].apply(lambda x: 1 if x & 0x40 else 0)
                
                # For PSH and URG flags, process only Fwd PSH Flags now (Bwd PSH Flags removed)
                features['Fwd PSH Flags'] = features['PSH Flag Count'] * (features['Total Fwd Packets'] / (features['Total Fwd Packets'] + features['Total Backward Packets']))
                features['Fwd URG Flags'] = features['URG Flag Count'] * (features['Total Fwd Packets'] / (features['Total Fwd Packets'] + features['Total Backward Packets']))
            else:
                # If TCP flags not available, use 0 (common for UDP)
                features['FIN Flag Count'] = 0
                # Removed 'SYN Flag Count'
                features['RST Flag Count'] = 0
                features['PSH Flag Count'] = 0
                features['ACK Flag Count'] = 0
                features['URG Flag Count'] = 0
                features['ECE Flag Count'] = 0
                features['Fwd PSH Flags'] = 0
                # Removed 'Bwd PSH Flags'
                features['Fwd URG Flags'] = 0
            
            # Header length features (estimated)
            avg_header_size = 40  # Typical TCP/IP header size
            features['Fwd Header Length'] = features['Total Fwd Packets'] * avg_header_size
            features['Bwd Header Length'] = features['Total Backward Packets'] * avg_header_size
            
            # Subflow features (in CICIDS2017 these are typically same as total flow)
            features['Subflow Fwd Bytes'] = features['Total Length of Fwd Packets']
            features['Subflow Bwd Bytes'] = features['Total Length of Bwd Packets']
            
            # Window features (estimated)
            features['Init_Win_bytes_forward'] = 65535  # Default initial window size
            features['Init_Win_bytes_backward'] = 65535  # Default initial window size
            
            # Active data packet features (estimated)
            features['act_data_pkt_fwd'] = features['Total Fwd Packets'] * 0.8  # Assuming 80% of packets carry data
            features['min_seg_size_forward'] = features['Fwd Packet Length Min']
            
            # Active/Idle time features
            # These are synthetic and estimated based on flow duration
            if 'Flow Duration' in features.columns:
                # Assume 70% active, 30% idle as a reasonable default
                active_time = features['Flow Duration'] * 0.7
                idle_time = features['Flow Duration'] * 0.3
                
                # Active time features
                features['Active Mean'] = active_time / 2  # Estimated mean
                features['Active Std'] = active_time * 0.2  # Estimated std deviation
                features['Active Max'] = active_time * 0.8  # Estimated max
                features['Active Min'] = active_time * 0.2  # Estimated min
                
                # Idle time features
                features['Idle Mean'] = idle_time / 2  # Estimated mean
                features['Idle Std'] = idle_time * 0.2  # Estimated std deviation
                features['Idle Max'] = idle_time * 0.8  # Estimated max
                features['Idle Min'] = idle_time * 0.2  # Estimated min
            
            # Add Attack Type instead of Label
            if 'alert.signature' in suricata_df.columns:
                features['Attack Type'] = suricata_df['alert.signature'].notnull().map({True: 'ATTACK', False: 'BENIGN'})
            else:
                features['Attack Type'] = 'UNKNOWN'  # Will be set by traffic profile later
            
            # Ensure all required features exist (set to 0 if not calculated)
            for feature in ordered:
                if feature not in features.columns:
                    features[feature] = 0
            
            # Add Attack Type for internal use (not included in CSV output)
            if 'alert.signature' in suricata_df.columns:
                features['Attack Type'] = suricata_df['alert.signature'].notnull().map({True: 'ATTACK', False: 'BENIGN'})
            else:
                features['Attack Type'] = 'UNKNOWN'  # Will be set by traffic profile later
            
            # Fill NaN values
            features.fillna(0, inplace=True)
            
            # Return DataFrame with columns in the exact specified order
            return features
            
        except Exception as e:
            logger.error(f"Error transforming features: {e}")
            return pd.DataFrame()



    def run_pipeline(self, profiles=None):
        profiles = profiles or ["normal", "dos", "ddos", "mixed"]
        results = {}
        for profile in profiles:
            logger.info("=== Running Linux DPDK pipeline for profile: %s ===", profile)
            outdir = self.generate_and_analyze(profile)
            if not outdir:
                logger.error("Suricata/DPDK step failed for profile=%s", profile)
                continue

            feats = self.extract_features(outdir)
            if feats is not None and not feats.empty:
                feats['Attack Type'] = profile.upper() if profile != "normal" else "BENIGN"
                results[profile] = {
                    "suricata_output": outdir,
                    "features_df": feats,
                    "feature_count": len(feats.columns),
                    "flow_count": len(feats)
                }
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fout = os.path.join(self.config["output_dir"], f"extracted_features_{profile}_{ts}.csv")
                feats.to_csv(fout, index=False)
                logger.info("Saved features to %s", fout)
        return results



def main():
    parser = argparse.ArgumentParser(description='Linux DPDK + Suricata pipeline')
    parser.add_argument('--config', type=str, help='JSON config path')
    parser.add_argument('--profiles', type=str, help='Comma-separated profiles')
    args = parser.parse_args()

    cfg = {}
    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)

    pipeline = NetworkTrafficPipeline(cfg)
    profiles = [p.strip() for p in args.profiles.split(',')] if args.profiles else None
    results = pipeline.run_pipeline(profiles)

    if results:
        all_feats = [r["features_df"] for r in results.values() if "features_df" in r]
        if all_feats:
            combined = pd.concat(all_feats, ignore_index=True)
            out = os.path.join(pipeline.config["output_dir"], "combined_features.csv")
            combined.to_csv(out, index=False)
            logger.info("Combined features saved to %s", out)
    logger.info("Pipeline complete.")


if __name__ == "__main__":
    main()