#!/usr/bin/env python3
"""
Test script to send sample network traffic data to Kafka
This will help verify the ML integration is working
"""
import json
import time
from kafka import KafkaProducer

# Sample network traffic features (similar to what the pipeline would generate)
sample_data = [
    {
        "Destination Port": 80,
        "Flow Duration": 2350000,
        "Total Fwd Packets": 15,
        "Total Backward Packets": 12,
        "Total Length of Fwd Packets": 2340,
        "Total Length of Bwd Packets": 18560,
        "Flow Bytes/s": 8934127.66,
        "Flow Packets/s": 11489361.7,
        "Average Packet Size": 773.5,
        "Fwd Packet Length Mean": 156.0,
        "Bwd Packet Length Mean": 1546.67,
        "Min Packet Length": 773.5,
        "Max Packet Length": 1547.0,
        "Packet Length Mean": 773.5,
        "FIN Flag Count": 1,
        "ACK Flag Count": 1,
        "profile": "normal"
    },
    {
        "Destination Port": 80,
        "Flow Duration": 50000,
        "Total Fwd Packets": 1000,
        "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 60000,
        "Total Length of Bwd Packets": 120,
        "Flow Bytes/s": 1200024000,
        "Flow Packets/s": 20000400,
        "Average Packet Size": 64.95,
        "Fwd Packet Length Mean": 60.0,
        "Bwd Packet Length Mean": 60.0,
        "Min Packet Length": 64.95,
        "Max Packet Length": 129.9,
        "Packet Length Mean": 64.95,
        "FIN Flag Count": 0,
        "ACK Flag Count": 1,
        "profile": "dos"
    },
    {
        "Destination Port": 443,
        "Flow Duration": 2140000,
        "Total Fwd Packets": 45,
        "Total Backward Packets": 38,
        "Total Length of Fwd Packets": 7890,
        "Total Length of Bwd Packets": 45230,
        "Flow Bytes/s": 24813084.11,
        "Flow Packets/s": 38785046.73,
        "Average Packet Size": 982.39,
        "Fwd Packet Length Mean": 175.33,
        "Bwd Packet Length Mean": 1190.79,
        "Min Packet Length": 982.39,
        "Max Packet Length": 1964.79,
        "Packet Length Mean": 982.39,
        "FIN Flag Count": 1,
        "ACK Flag Count": 1,
        "profile": "normal"
    }
]

def send_test_data():
    producer = KafkaProducer(
        bootstrap_servers=['127.0.0.1:9092'],
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        retries=5
    )
    
    print("Sending test network traffic data to Kafka...")
    
    for i, record in enumerate(sample_data):
        try:
            producer.send('network-traffic', record)
            print(f"Sent record {i+1}: {record['profile']} traffic to port {record['Destination Port']}")
            time.sleep(2)  # Send one record every 2 seconds
        except Exception as e:
            print(f"Error sending record: {e}")
    
    producer.flush()
    producer.close()
    print("Test data sent successfully!")

if __name__ == "__main__":
    send_test_data()