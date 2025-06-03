#!/usr/bin/env python3

import os
import json
import time
import logging
import pandas as pd
from kafka import KafkaProducer

# Import the existing Traffic Simulation Pipeline
from traffic_simulation import NetworkTrafficPipeline

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Traffic-Simulation-Kafka")

# Initialize Kafka Producer
producer = KafkaProducer(
    bootstrap_servers="127.0.0.1:9092",  # Force localhost
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)


def stream_features_to_kafka(profile, features_df):
    """
    Streams extracted network traffic features to Kafka in real-time.

    Parameters:
        profile (str): Traffic profile (e.g., 'normal', 'dos', 'ddos', etc.)
        features_df (pd.DataFrame): Extracted feature data
    """
    logger.info(f"Streaming {len(features_df)} feature records from {profile} to Kafka...")

    for _, row in features_df.iterrows():
        record = row.to_dict()
        record["profile"] = profile  # Add traffic profile info
        producer.send("network-traffic", record)
        time.sleep(0.01)  # Simulate real-time streaming delay

def run_traffic_simulation():
    """
    Runs the network traffic simulation and streams extracted features to Kafka.
    """
    # Initialize the pipeline with a default interface
    traffic_pipeline = NetworkTrafficPipeline(config={"output_dir": "./output", "interface": "eth0", "simulation_time": 300})

    # Generate traffic and extract features
    results = traffic_pipeline.run_pipeline(["normal", "dos", "ddos", "mixed"])

    for profile, result in results.items():
        if "features_df" in result:
            stream_features_to_kafka(profile, result["features_df"])

if __name__ == "__main__":
    run_traffic_simulation()
