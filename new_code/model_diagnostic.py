#!/usr/bin/env python3
"""
Comprehensive diagnostic tool to identify ML model issues
"""
import joblib
import pandas as pd
import numpy as np
import json

def diagnose_models():
    """Diagnose potential issues with the ML models"""
    print("=== ML MODEL DIAGNOSTIC TOOL ===\n")
    
    try:
        # Load models
        print("1. Loading models...")
        rf_model = joblib.load("rf_model_2017.joblib")
        lgb_model = joblib.load("lgb_model_2018.joblib")
        print("✅ Models loaded successfully")
        
        # Check model properties
        print(f"\n2. Model Properties:")
        print(f"RF Model Type: {type(rf_model)}")
        print(f"RF Classes: {rf_model.classes_}")
        print(f"RF Class Count: {len(rf_model.classes_)}")
        
        print(f"LGB Model Type: {type(lgb_model)}")
        print(f"LGB Classes: {lgb_model.classes_}")
        print(f"LGB Class Count: {len(lgb_model.classes_)}")
        
        # Check feature requirements
        rf_features = None
        lgb_features = None
        
        if hasattr(rf_model, 'feature_names_in_'):
            rf_features = list(rf_model.feature_names_in_)
            print(f"RF Expected Features: {len(rf_features)}")
        else:
            print("RF: No feature_names_in_ found")
            
        if hasattr(lgb_model, 'feature_names_in_'):
            lgb_features = list(lgb_model.feature_names_in_)
            print(f"LGB Expected Features: {len(lgb_features)}")
        else:
            print("LGB: No feature_names_in_ found")
        
        # Test with simple data
        print(f"\n3. Testing with simple data...")
        
        # Create test data with different values
        test_samples = []
        
        # Sample 1: All zeros (should be very different from Sample 2)
        sample1 = {f"feature_{i}": 0 for i in range(60)}
        test_samples.append(("All Zeros", sample1))
        
        # Sample 2: All ones
        sample2 = {f"feature_{i}": 1 for i in range(60)}
        test_samples.append(("All Ones", sample2))
        
        # Sample 3: Very high values (attack-like)
        sample3 = {f"feature_{i}": 10000 if i < 10 else 0 for i in range(60)}
        test_samples.append(("High Values", sample3))
        
        # Sample 4: Random values
        np.random.seed(42)
        sample4 = {f"feature_{i}": np.random.normal(100, 50) for i in range(60)}
        test_samples.append(("Random Values", sample4))
        
        # Test each sample
        for name, sample in test_samples:
            print(f"\n--- Testing: {name} ---")
            df = pd.DataFrame([sample])
            
            # Test RF model
            try:
                rf_pred = rf_model.predict(df)[0]
                rf_proba = rf_model.predict_proba(df)[0]
                print(f"RF Prediction: {rf_pred}")
                print(f"RF Probabilities: {dict(zip(rf_model.classes_, rf_proba))}")
            except Exception as e:
                print(f"RF Error: {e}")
            
            # Test LGB model
            try:
                lgb_pred = lgb_model.predict(df)[0]
                lgb_proba = lgb_model.predict_proba(df)[0]
                print(f"LGB Prediction: {lgb_pred}")
                print(f"LGB Probabilities: {dict(zip(lgb_model.classes_, lgb_proba))}")
            except Exception as e:
                print(f"LGB Error: {e}")
        
        # Test with realistic CICIDS feature names
        print(f"\n4. Testing with CICIDS-like features...")
        cicids_features = [
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
        
        # Test extreme DDoS pattern
        ddos_sample = {
            'Destination Port': 80,
            'Flow Duration': 100000,
            'Total Fwd Packets': 50000,  # Extreme
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': 3200000,
            'Total Length of Bwd Packets': 0,
            'Flow Bytes/s': 32000000,  # Extreme rate
            'Flow Packets/s': 500000,  # Extreme packet rate
            'Flow IAT Mean': 2,  # Extremely small
            'Average Packet Size': 64,
            'Down/Up Ratio': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0
        }
        
        # Fill remaining features with 0
        for feature in cicids_features:
            if feature not in ddos_sample:
                ddos_sample[feature] = 0
        
        # Test normal pattern
        normal_sample = {
            'Destination Port': 443,
            'Flow Duration': 5000000,
            'Total Fwd Packets': 20,
            'Total Backward Packets': 18,
            'Total Length of Fwd Packets': 3200,
            'Total Length of Bwd Packets': 25600,
            'Flow Bytes/s': 5760,
            'Flow Packets/s': 7.6,
            'Flow IAT Mean': 131578,
            'Average Packet Size': 759,
            'Down/Up Ratio': 0.9,
            'PSH Flag Count': 3,
            'ACK Flag Count': 35
        }
        
        # Fill remaining features with reasonable values
        for feature in cicids_features:
            if feature not in normal_sample:
                normal_sample[feature] = 0
        
        realistic_samples = [
            ("Extreme DDoS", ddos_sample),
            ("Normal Traffic", normal_sample)
        ]
        
        for name, sample in realistic_samples:
            print(f"\n--- Testing: {name} ---")
            print(f"Key features: Packets/s={sample.get('Flow Packets/s', 0)}, Duration={sample.get('Flow Duration', 0)}")
            
            df = pd.DataFrame([sample])
            
            # Ensure column order matches model expectations if possible
            if rf_features:
                missing_features = set(rf_features) - set(df.columns)
                if missing_features:
                    print(f"Missing features for RF: {len(missing_features)}")
                    for feat in missing_features:
                        df[feat] = 0
                df = df.reindex(columns=rf_features, fill_value=0)
            
            try:
                rf_pred = rf_model.predict(df)[0]
                rf_proba = rf_model.predict_proba(df)[0]
                print(f"RF: {rf_pred} (proba: {dict(zip(rf_model.classes_, rf_proba))})")
            except Exception as e:
                print(f"RF Error: {e}")
                
            if lgb_features:
                df_lgb = pd.DataFrame([sample])
                missing_features = set(lgb_features) - set(df_lgb.columns)
                if missing_features:
                    print(f"Missing features for LGB: {len(missing_features)}")
                    for feat in missing_features:
                        df_lgb[feat] = 0
                df_lgb = df_lgb.reindex(columns=lgb_features, fill_value=0)
            else:
                df_lgb = df
                
            try:
                lgb_pred = lgb_model.predict(df_lgb)[0]
                lgb_proba = lgb_model.predict_proba(df_lgb)[0]
                print(f"LGB: {lgb_pred} (proba: {dict(zip(lgb_model.classes_, lgb_proba))})")
            except Exception as e:
                print(f"LGB Error: {e}")
        
        # Check for model corruption indicators
        print(f"\n5. Model Health Check:")
        
        # Check if models always return same prediction
        predictions_rf = []
        predictions_lgb = []
        
        for i in range(5):
            random_data = {f"feature_{j}": np.random.normal(i*100, 50) for j in range(60)}
            df = pd.DataFrame([random_data])
            
            try:
                pred_rf = rf_model.predict(df)[0]
                predictions_rf.append(pred_rf)
            except:
                pass
                
            try:
                pred_lgb = lgb_model.predict(df)[0]
                predictions_lgb.append(pred_lgb)
            except:
                pass
        
        print(f"RF predictions on random data: {set(predictions_rf)}")
        print(f"LGB predictions on random data: {set(predictions_lgb)}")
        
        if len(set(predictions_rf)) == 1:
            print("⚠️  WARNING: RF model always returns same prediction - likely corrupted")
        
        if len(set(predictions_lgb)) == 1:
            print("⚠️  WARNING: LGB model always returns same prediction - likely corrupted")
            
        return rf_model, lgb_model, rf_features, lgb_features
        
    except Exception as e:
        print(f"❌ Error during diagnosis: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None

if __name__ == "__main__":
    diagnose_models()