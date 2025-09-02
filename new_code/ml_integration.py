import os
import joblib
import pandas as pd
from kafka import KafkaConsumer
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Kafka-ML")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")
MODEL_PATH = os.getenv("MODEL_PATH", "intrusion_detection_model.joblib")

model = joblib.load(MODEL_PATH)
feature_names = list(getattr(model, "feature_names_in_", []))

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=KAFKA_BROKERS.split(","),
    value_deserializer=lambda x: json.loads(x.decode('utf-8')),
    auto_offset_reset="latest",
    enable_auto_commit=True,
)

for message in consumer:
    traffic_data = message.value
    logger.info("Received traffic data (profile=%s)", traffic_data.get("profile"))
    # Build DF matching model features; fill missing with 0
    if feature_names:
        row = {k: traffic_data.get(k, 0) for k in feature_names}
        traffic_df = pd.DataFrame([row], columns=feature_names)
    else:
        # Fallback (not ideal, but avoids crash)
        traffic_df = pd.DataFrame([traffic_data]).select_dtypes(include="number").fillna(0)

    try:
        pred = model.predict(traffic_df)
        logger.info("Prediction: %s", pred)
    except Exception as e:
        logger.error("Prediction failed: %s", e)

consumer.close()
