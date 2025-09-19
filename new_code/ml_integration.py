import os
import joblib
import pandas as pd
from kafka import KafkaConsumer
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Kafka-ML")

# --- Config ---
KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")
MODEL_PATH = os.getenv("MODEL_PATH", "intrusion_detection_model.joblib")

# --- Load model ---
model = joblib.load(MODEL_PATH)

# --- Expected features (order matters for the trained model) ---
EXPECTED_FEATURES = [
    'Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
    'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
    'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Len',
    'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min',
    'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
    'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts',
    'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts',
    'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max',
    'Idle Min', 'Attack Type'
]

# --- Map pipeline feature names → expected names ---
RENAME_MAP = {
    'Destination Port': 'Dst Port',
    'Flow Duration': 'Flow Duration',
    'Total Fwd Packets': 'Tot Fwd Pkts',
    'Total Backward Packets': 'Tot Bwd Pkts',
    'Total Length of Fwd Packets': 'TotLen Fwd Pkts',
    'Total Length of Bwd Packets': 'TotLen Bwd Pkts',
    'Fwd Packet Length Max': 'Fwd Pkt Len Max',
    'Fwd Packet Length Min': 'Fwd Pkt Len Min',
    'Fwd Packet Length Mean': 'Fwd Pkt Len Mean',
    'Fwd Packet Length Std': 'Fwd Pkt Len Std',
    'Bwd Packet Length Max': 'Bwd Pkt Len Max',
    'Bwd Packet Length Min': 'Bwd Pkt Len Min',
    'Bwd Packet Length Mean': 'Bwd Pkt Len Mean',
    'Bwd Packet Length Std': 'Bwd Pkt Len Std',
    'Flow Bytes/s': 'Flow Byts/s',
    'Flow Packets/s': 'Flow Pkts/s',
    'Flow IAT Mean': 'Flow IAT Mean',
    'Flow IAT Std': 'Flow IAT Std',
    'Flow IAT Max': 'Flow IAT Max',
    'Flow IAT Min': 'Flow IAT Min',
    'Fwd IAT Total': 'Fwd IAT Tot',
    'Fwd IAT Mean': 'Fwd IAT Mean',
    'Fwd IAT Std': 'Fwd IAT Std',
    'Fwd IAT Max': 'Fwd IAT Max',
    'Fwd IAT Min': 'Fwd IAT Min',
    'Bwd IAT Total': 'Bwd IAT Tot',
    'Bwd IAT Mean': 'Bwd IAT Mean',
    'Bwd IAT Std': 'Bwd IAT Std',
    'Bwd IAT Max': 'Bwd IAT Max',
    'Bwd IAT Min': 'Bwd IAT Min',
    'Fwd PSH Flags': 'Fwd PSH Flags',
    'Fwd URG Flags': 'Fwd URG Flags',
    'Fwd Header Length': 'Fwd Header Len',
    'Bwd Header Length': 'Bwd Header Len',
    'Fwd Packets/s': 'Fwd Pkts/s',
    'Bwd Packets/s': 'Bwd Pkts/s',
    'Min Packet Length': 'Pkt Len Min',
    'Max Packet Length': 'Pkt Len Max',
    'Packet Length Mean': 'Pkt Len Mean',
    'Packet Length Std': 'Pkt Len Std',
    'Packet Length Variance': 'Pkt Len Var',
    'FIN Flag Count': 'FIN Flag Cnt',
    'RST Flag Count': 'RST Flag Cnt',
    'PSH Flag Count': 'PSH Flag Cnt',
    'ACK Flag Count': 'ACK Flag Cnt',
    'URG Flag Count': 'URG Flag Cnt',
    'ECE Flag Count': 'ECE Flag Cnt',
    'Down/Up Ratio': 'Down/Up Ratio',
    'Average Packet Size': 'Pkt Size Avg',
    'Avg Fwd Segment Size': 'Fwd Seg Size Avg',
    'Avg Bwd Segment Size': 'Bwd Seg Size Avg',
    'Subflow Fwd Bytes': 'Subflow Fwd Byts',
    'Subflow Bwd Bytes': 'Subflow Bwd Byts',
    'Init_Win_bytes_forward': 'Init Fwd Win Byts',
    'Init_Win_bytes_backward': 'Init Bwd Win Byts',
    'act_data_pkt_fwd': 'Fwd Act Data Pkts',
    'min_seg_size_forward': 'Fwd Seg Size Min',
    'Active Mean': 'Active Mean',
    'Active Std': 'Active Std',
    'Active Max': 'Active Max',
    'Active Min': 'Active Min',
    'Idle Mean': 'Idle Mean',
    'Idle Std': 'Idle Std',
    'Idle Max': 'Idle Max',
    'Idle Min': 'Idle Min',
    'Attack Type': 'Attack Type',
}

# --- Kafka Consumer ---
consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=KAFKA_BROKERS.split(","),
    value_deserializer=lambda x: json.loads(x.decode("utf-8")),
    auto_offset_reset="latest",
    enable_auto_commit=True,
)

# --- Feature Normalization ---
def normalize_record(d: dict) -> pd.DataFrame:
    rec = {}
    for src, dst in RENAME_MAP.items():
        if src in d:
            rec[dst] = d.get(src)
    rec.setdefault("SYN Flag Cnt", 0)
    rec.setdefault("CWE Flag Count", 0)
    if "Tot Fwd Pkts" in rec:
        rec.setdefault("Subflow Fwd Pkts", rec["Tot Fwd Pkts"])
    if "Tot Bwd Pkts" in rec:
        rec.setdefault("Subflow Bwd Pkts", rec["Tot Bwd Pkts"])
    for key in EXPECTED_FEATURES:
        rec.setdefault(key, 0)
    df = pd.DataFrame([rec], columns=EXPECTED_FEATURES)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
    return df

# --- Main Consumer Loop ---
for message in consumer:
    traffic_data = message.value
    logger.info("Received traffic data (profile=%s)", traffic_data.get("profile"))

    traffic_df = normalize_record(traffic_data)

    try:
        if hasattr(model, "predict"):
            pred = model.predict(traffic_df)
        elif hasattr(model, "predict_proba"):
            proba = model.predict_proba(traffic_df)
            pred = proba.argmax(axis=1)
        else:
            raise AttributeError("Loaded model lacks predict/predict_proba")
        logger.info("Prediction: %s", pred)
    except Exception as e:
        logger.error("Prediction failed: %s", e)

consumer.close()
