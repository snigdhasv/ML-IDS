#!/usr/bin/env python3
import os
import json
import time
import logging
import pandas as pd
from kafka import KafkaProducer
from traffic_simulation import NetworkTrafficPipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Traffic-Simulation-Kafka")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKERS.split(","),
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    retries=5
)

def stream_features_to_kafka(profile, features_df):
    logger.info(f"Streaming {len(features_df)} records from {profile} to Kafka topic '{TOPIC}'...")
    for _, row in features_df.iterrows():
        record = row.to_dict()
        record["profile"] = profile
        try:
            producer.send(TOPIC, record)
        except Exception as e:
            logger.error("Kafka send failed: %s", e)
            break
        time.sleep(float(os.getenv("STREAM_DELAY_SEC", "0.005")))

def run_traffic_simulation():
    traffic_pipeline = NetworkTrafficPipeline(config={
        "output_dir": "./output",
        "simulation_time": int(os.getenv("SIM_TIME", "60")),
        # set your PCI/NICs in a JSON config file or env if needed
    })
    results = traffic_pipeline.run_pipeline(["normal", "dos", "ddos", "mixed"])
    for profile, result in results.items():
        if "features_df" in result:
            stream_features_to_kafka(profile, result["features_df"])

if __name__ == "__main__":
    run_traffic_simulation()
