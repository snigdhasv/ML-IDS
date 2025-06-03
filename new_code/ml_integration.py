import joblib
import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql.functions import from_json, col
from kafka import KafkaConsumer
import json

# Load the model
model_path = 'intrusion_detection_model.joblib'
model = joblib.load(model_path)

# Extract feature names from the model
feature_names = model.feature_names_in_

# Initialize Spark session
spark = SparkSession.builder.appName("KafkaMLIntegration").getOrCreate()

# Set up Kafka consumer
consumer = KafkaConsumer(
    'network-traffic',
    bootstrap_servers='127.0.0.1:9092',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

for message in consumer:
    traffic_data = message.value
    print("Received traffic data:", traffic_data)

    # Convert to DataFrame with proper feature names
    traffic_df = pd.DataFrame([traffic_data], columns=feature_names)

    # Make predictions
    prediction = model.predict(traffic_df)
    print("Prediction:", prediction)

consumer.close()
