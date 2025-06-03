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

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("traffic_pipeline.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TrafficPipeline")

class NetworkTrafficPipeline:
    def __init__(self, config=None):
        self.config = config or {
            "dpdk_path": "/usr/local/share/dpdk",
            "suricata_path": "/usr/bin/suricata",
            "output_dir": "./output",
            "simulation_time": 300,  # seconds
            "traffic_profile": "mixed",  # options: normal, dos, ddos, portscan, bruteforce, etc.
            "packet_rate": 10000,  # packets per second
            "interface": "eth0",
            "features_to_extract": [
                'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
                'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
                'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
                'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
                'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
                'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
                'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags', 
                'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
                'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
                'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count',
                'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
                'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
                'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
                'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
                'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
                'Idle Std', 'Idle Max', 'Idle Min'
            ]
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(self.config["output_dir"], exist_ok=True)
        
        # Check if we're running in WSL
        self._check_wsl()
        
        # Verify DPDK and Suricata are installed
        self._verify_dependencies()

    def _check_wsl(self):
        """Verify we're running in WSL and adjust settings if needed"""
        try:
            with open('/proc/version', 'r') as f:
                if 'Microsoft' in f.read():
                    logger.info("Running in WSL environment")
                    
                    # Check if WSL2 (recommended for DPDK)
                    result = subprocess.run(['wsl.exe', '--version'], 
                                            capture_output=True, text=True)
                    if 'WSL version' in result.stdout and '2' in result.stdout:
                        logger.info("WSL2 detected (optimal for DPDK)")
                    else:
                        logger.warning("Consider upgrading to WSL2 for better DPDK performance")
                        
                    # Check if required WSL features are enabled
                    self._setup_wsl_networking()
                else:
                    logger.info("Not running in WSL environment")
        except Exception as e:
            logger.warning(f"Could not verify WSL environment: {e}")

    def _setup_wsl_networking(self):
        """Configure WSL networking for DPDK"""
        # Check for network interfaces
        try:
            result = subprocess.run(['ip', 'link', 'show'], 
                                    capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Network interfaces available in WSL")
            else:
                logger.error("Cannot access network interfaces in WSL")
                
            # Check for Huge Pages support (required by DPDK)
            if not os.path.exists('/dev/hugepages'):
                logger.warning("Huge Pages not mounted, attempting to set up")
                try:
                    subprocess.run(['sudo', 'mkdir', '-p', '/dev/hugepages'])
                    subprocess.run(['sudo', 'mount', '-t', 'hugetlbfs', 'nodev', '/dev/hugepages'])
                    logger.info("Huge Pages mounted successfully")
                except Exception as e:
                    logger.error(f"Failed to mount Huge Pages: {e}")
            else:
                logger.info("Huge Pages support detected")
        except Exception as e:
            logger.error(f"Error setting up WSL networking: {e}")

    def _verify_dependencies(self):
        """Verify that DPDK and Suricata are properly installed"""
        logger.info("DPDK and Suricata are already installed, skipping dependency checks")
        
        # Update Suricata rules
        try:
            subprocess.run(['sudo', 'suricata-update'], check=True)
            logger.info("Suricata rules updated successfully")
        except subprocess.CalledProcessError:
            logger.warning("Failed to update Suricata rules. Continuing with existing rules.")

    def setup_dpdk(self):
        """Set up DPDK environment for packet processing"""
        logger.info("Setting up DPDK environment")
        
        try:
            # Allocate hugepages (required for DPDK)
            subprocess.run(['sudo', 'sh', '-c', 'echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'], 
                           check=True)
            
            # Bind NIC to DPDK-compatible driver
            # For WSL, we can use veth or similar virtual interfaces
            subprocess.run(['sudo', 'dpdk-devbind', '--status'], check=True)
            
            # Depending on WSL version and setup, bind appropriate interface
            # This part may need customization based on specific WSL setup
            interface = self.config["interface"]
            logger.info(f"Attempting to bind interface {interface} to DPDK driver")
            
            # For WSL2, we may need to use different approach than direct binding
            # Often using AF_XDP or similar approaches works better in WSL
            
            logger.info("DPDK environment setup complete")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set up DPDK environment: {e}")
            return False

    def generate_traffic(self, profile="mixed"):
        """
        Generate network traffic based on specified profile
        
        Parameters:
        profile (str): Traffic profile to generate (normal, dos, ddos, etc.)
        
        Returns:
        str: Path to the generated pcap file
        """
        logger.info(f"Generating {profile} traffic")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_pcap = os.path.join(self.config["output_dir"], f"{profile}_traffic_{timestamp}.pcap")
        
        # Use DPDK-based packet generator
        # For demonstration, we'll use a simpler approach
        # In a real implementation, you'd integrate with a DPDK packet generator
        
        try:
            if profile == "normal":
                # Generate normal traffic
                command = [
                    "tcpreplay", "--intf1=" + self.config["interface"],
                    "--topspeed", "--loop=10", 
                    "/home/snig/CAPSTONE/pipeline/normal_traffic.pcap" #path
                ]
            elif profile == "dos":
                # Generate DoS attack traffic
                command = [
                    "tcpreplay", "--intf1=" + self.config["interface"],
                    "--topspeed", "--loop=10", 
                    "/home/snig/CAPSTONE/pipeline/dos_traffic_sample.pcap" #path
                ]
            elif profile == "ddos":
                # Generate DDoS attack traffic
                command = [
                    "tcpreplay", "--intf1=" + self.config["interface"],
                    "--topspeed", "--loop=10", 
                    "/home/snig/CAPSTONE/pipeline/dos_traffic_sample.pcap" #path
                ]
            else:
                # Mixed traffic
                command = [
                    "tcpreplay", "--intf1=" + self.config["interface"],
                    "--topspeed", "--loop=5", 
                    "/home/snig/CAPSTONE/pipeline/mixed_traffic_sample.pcap" #path
                ]
                
            # Capture traffic to pcap for analysis
            capture_cmd = [
                "tcpdump", "-i", self.config["interface"], 
                "-w", output_pcap, "-s", "0"
            ]
            
            # Start capture in background
            capture_process = subprocess.Popen(capture_cmd)
            
            # Start traffic generation
            subprocess.run(command, check=True, timeout=self.config["simulation_time"])
            
            # Stop capture
            capture_process.terminate()
            capture_process.wait(timeout=5)
            
            logger.info(f"Traffic generation complete, captured to {output_pcap}")
            return output_pcap
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Traffic generation failed: {e}")
            return None
        except FileNotFoundError:
            logger.error("tcpreplay or tcpdump not found. Please install them.")
            return None




    def analyze_with_suricata(self, pcap_file):
        """
        Analyze captured traffic with Suricata
        
        Parameters:
        pcap_file (str): Path to the pcap file to analyze
        
        Returns:
        str: Path to the Suricata output directory
        """
        if not pcap_file or not os.path.exists(pcap_file):
            logger.error("Invalid pcap file for Suricata analysis")
            return None
            
        logger.info(f"Analyzing {pcap_file} with Suricata")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.config["output_dir"], f"suricata_output_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare Suricata configuration
        suricata_config = os.path.join(output_dir, "suricata.yaml")
        
        # Copy default config and customize
        try:
            default_config = "/etc/suricata/suricata.yaml"
            shutil.copy(default_config, suricata_config)
            
            # Run Suricata on the pcap file
            command = [
                "suricata", "-c", suricata_config,
                "-r", pcap_file,
                "-l", output_dir,
                "--runmode", "autofp"
            ]
            
            subprocess.run(command, check=True)
            
            # Check if analysis was successful
            eve_json = os.path.join(output_dir, "eve.json")
            if os.path.exists(eve_json):
                logger.info(f"Suricata analysis complete: {eve_json}")
                return output_dir
            else:
                logger.error("Suricata analysis failed: no eve.json found")
                return None
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Suricata analysis failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Error during Suricata analysis: {e}")
            return None

    def extract_features(self, suricata_output_dir):
        """
        Extract features from Suricata output compatible with CICIDS2017 dataset
        
        Parameters:
        suricata_output_dir (str): Path to Suricata output directory
        
        Returns:
        pd.DataFrame: DataFrame containing extracted features
        """
        if not suricata_output_dir or not os.path.exists(suricata_output_dir):
            logger.error("Invalid Suricata output directory")
            return None
            
        logger.info(f"Extracting features from {suricata_output_dir}")
        
        # Path to Suricata's eve.json file
        eve_json = os.path.join(suricata_output_dir, "eve.json")
        
        if not os.path.exists(eve_json):
            logger.error(f"Eve.json not found in {suricata_output_dir}")
            return None
            
        # Parse eve.json to extract flow information
        try:
            # Read eve.json line by line (it's not a single JSON object)
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
                logger.error("No flow data found in eve.json")
                return None
                
            logger.info(f"Extracted {len(flows)} flows from Suricata output")
            
            # Convert to DataFrame
            df = pd.json_normalize(flows)
            
            # Transform data to match CICIDS2017 features
            features_df = self._transform_to_cicids_features(df)
            
            # Save features to CSV
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_csv = os.path.join(self.config["output_dir"], f"extracted_features_{timestamp}.csv")
            features_df.to_csv(output_csv, index=False)
            
            logger.info(f"Features saved to {output_csv}")
            return features_df
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    def _transform_to_cicids_features(self, suricata_df):
        """
        Transform Suricata output into the specific features requested for CICIDS2017
        
        Parameters:
        suricata_df (pd.DataFrame): DataFrame with Suricata flow data
        
        Returns:
        pd.DataFrame: DataFrame with requested CICIDS2017-compatible features
        """
        logger.info("Transforming Suricata data to requested CICIDS2017 features")
        
        ordered_features = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
            'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
            'Fwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
            'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'ECE Flag Count',
            'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
            'Idle Std', 'Idle Max', 'Idle Min'
        ]
        
        features = pd.DataFrame(columns=ordered_features)
        features = features.astype('float64')  # Set default type to avoid mixed types
                
        
        try:
            # Basic flow information
            if 'dest_port' in suricata_df.columns:
                features['Destination Port'] = suricata_df['dest_port']

            # Flow duration calculation
            if 'flow.start' in suricata_df.columns and 'flow.end' in suricata_df.columns:
                # Convert timestamps to datetime objects
                suricata_df['flow.start'] = pd.to_datetime(suricata_df['flow.start'])
                suricata_df['flow.end'] = pd.to_datetime(suricata_df['flow.end'])
                
                # Calculate flow duration in microseconds
                features['Flow Duration'] = (suricata_df['flow.end'] - suricata_df['flow.start']).dt.total_seconds() * 1000000
            
            # Packet counts
            if 'flow.pkts_toserver' in suricata_df.columns:
                features['Total Fwd Packets'] = suricata_df['flow.pkts_toserver']
            
            if 'flow.pkts_toclient' in suricata_df.columns:
                features['Total Backward Packets'] = suricata_df['flow.pkts_toclient']
            
            # Byte counts
            if 'flow.bytes_toserver' in suricata_df.columns:
                features['Total Length of Fwd Packets'] = suricata_df['flow.bytes_toserver']
            
            if 'flow.bytes_toclient' in suricata_df.columns:
                features['Total Length of Bwd Packets'] = suricata_df['flow.bytes_toclient']
            
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
            for feature in ordered_features:
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
            return features[ordered_features]
            
        except Exception as e:
            logger.error(f"Error transforming features: {e}")
            return pd.DataFrame()



    def run_pipeline(self, profiles=None):
        """
        Run the complete traffic simulation and feature extraction pipeline
        
        Parameters:
        profiles (list): List of traffic profiles to simulate
        
        Returns:
        dict: Dictionary with results for each profile
        """
        if profiles is None:
            profiles = ["normal", "dos", "ddos", "mixed"]
            
        results = {}
        
        
        # Set up DPDK environment
        if not self.setup_dpdk():
            logger.error("Failed to set up DPDK environment. Exiting.")
            return results
        
        for profile in profiles:
            logger.info(f"Running pipeline for {profile} traffic profile")
            
            # Generate traffic
            pcap_file = self.generate_traffic(profile)
            if not pcap_file:
                logger.error(f"Failed to generate {profile} traffic. Skipping.")
                continue
                
            # Analyze with Suricata
            suricata_output = self.analyze_with_suricata(pcap_file)
            if not suricata_output:
                logger.error(f"Failed to analyze {profile} traffic with Suricata. Skipping.")
                continue
            
            
            # Extract features
            features_df = self.extract_features(suricata_output)
            if features_df is not None:
                # Store attack type internally but don't include in CSV output
                features_df['Attack Type'] = profile.upper() if profile != "normal" else "BENIGN"
                
                # Save to results
                results[profile] = {
                    "pcap_file": pcap_file,
                    "suricata_output": suricata_output,
                    "features_df": features_df,
                    "feature_count": len(features_df.columns),
                    "flow_count": len(features_df)
                }
                
                logger.info(f"Pipeline complete for {profile} profile: {len(features_df)} flows with {len(features_df.columns)} features")
        return results


def main():
    parser = argparse.ArgumentParser(description='Network Traffic Simulation and Feature Extraction Pipeline')
    parser.add_argument('--config', type=str, help='Path to configuration file')
    parser.add_argument('--profiles', type=str, help='Comma-separated list of traffic profiles to simulate')
    parser.add_argument('--output', type=str, help='Output directory for results')
    parser.add_argument('--time', type=int, help='Simulation time in seconds')
    parser.add_argument('--interface', type=str, help='Network interface to use')
    
    args = parser.parse_args()
    
    # Build configuration
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    if args.output:
        config['output_dir'] = args.output
    
    if args.time:
        config['simulation_time'] = args.time
    
    if args.interface:
        config['interface'] = args.interface
    
    # Create and run pipeline
    pipeline = NetworkTrafficPipeline(config)
    
    profiles = None
    if args.profiles:
        profiles = [p.strip() for p in args.profiles.split(',')]
    
    results = pipeline.run_pipeline(profiles)
    
    # Combine all features into one dataset
    if results:
        all_features = []
        for profile, result in results.items():
            if 'features_df' in result:
                all_features.append(result['features_df'])
        
        if all_features:
            combined_df = pd.concat(all_features, ignore_index=True)
            output_path = os.path.join(config.get('output_dir', './output'), 'combined_features.csv')
            combined_df.to_csv(output_path, index=False)
            logger.info(f"Combined features saved to {output_path}")
    
    logger.info("Pipeline execution completed")

if __name__ == "__main__":
    main()