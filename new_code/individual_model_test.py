#!/usr/bin/env python3
"""
Test individual models without ensemble to isolate the issue
"""
import joblib
import pandas as pd
import numpy as np

def test_individual_models():
    """Test each model individually"""
    print("=== INDIVIDUAL MODEL TEST ===\n")
    
    # Load models
    rf_model = joblib.load("rf_model_2017.joblib")
    lgb_model = joblib.load("lgb_model_2018.joblib")
    
    # Create test data with extreme differences
    extreme_attack = {
        'Flow Packets/s': 50000,    # Extremely high
        'Flow Bytes/s': 25000000,  # Extremely high
        'Total Fwd Packets': 10000,
        'Total Backward Packets': 0,
        'Flow Duration': 100000,
        'Down/Up Ratio': 0,
        'Flow IAT Mean': 10,
        'Average Packet Size': 64
    }
    
    normal_traffic = {
        'Flow Packets/s': 5,        # Very low
        'Flow Bytes/s': 3000,      # Very low  
        'Total Fwd Packets': 10,
        'Total Backward Packets': 8,
        'Flow Duration': 2000000,
        'Down/Up Ratio': 0.8,
        'Flow IAT Mean': 200000,
        'Average Packet Size': 600
    }
    
    # Add 50+ more features with different values
    for i in range(50):
        extreme_attack[f'feature_{i}'] = 1000 if i % 2 == 0 else 0
        normal_traffic[f'feature_{i}'] = 1 if i % 2 == 0 else 10
    
    samples = [
        ("Extreme Attack", extreme_attack),
        ("Normal Traffic", normal_traffic)
    ]
    
    for name, sample in samples:
        print(f"\n--- Testing {name} ---")
        df = pd.DataFrame([sample])
        print(f"Sample size: {len(sample)} features")
        print(f"Key values: Packets/s={sample.get('Flow Packets/s')}, Bytes/s={sample.get('Flow Bytes/s')}")
        
        # Test RF
        print("\nRF Model:")
        rf_pred = rf_model.predict(df)
        rf_proba = rf_model.predict_proba(df)
        print(f"Prediction: {rf_pred[0]}")
        print(f"Probabilities: {dict(zip(rf_model.classes_, rf_proba[0]))}")
        
        # Test LGB  
        print("\nLGB Model:")
        lgb_pred = lgb_model.predict(df)
        lgb_proba = lgb_model.predict_proba(df)
        print(f"Prediction: {lgb_pred[0]}")
        print(f"Probabilities: {dict(zip(lgb_model.classes_, lgb_proba[0]))}")

if __name__ == "__main__":
    test_individual_models()