import os
import joblib
import pandas as pd
import numpy as np
from kafka import KafkaConsumer
import json
import logging
from sklearn.ensemble import RandomForestRegressor
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("Kafka-ML-Ensemble")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "127.0.0.1:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "network-traffic")
MODEL1_PATH = os.getenv("MODEL1_PATH", "rf_model_2017.joblib")  # RF(2017)
MODEL2_PATH = os.getenv("MODEL2_PATH", "lgb_model_2018.joblib")  # LGB(2018)
PCA_TRANSFORMER_PATH = os.getenv("PCA_TRANSFORMER_PATH", "pca_transformer.joblib")  # PCA transformer
SCALER_PATH = os.getenv("SCALER_PATH", "scaler.joblib")  # StandardScaler

# Define the expected CICIDS features in order
CICIDS_FEATURES = [
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

class AdaptiveEnsemblePredictor:
    """Adaptive ensemble prediction with confidence-based weighting"""

    def __init__(self):
        self.full_label_space = None
        self.meta_learner = None
        self.confidence_threshold = 0.5
        self.weighting_history = []

    def _setup_label_space(self, model1, model2):
        """Create unified label space from both models"""
        self.full_label_space = sorted(list(set(model1.classes_.tolist() + model2.classes_.tolist())))

    def _align_probabilities(self, model_proba, model_classes):
        """Align model probabilities to full label space"""
        aligned = np.zeros((model_proba.shape[0], len(self.full_label_space)))
        for i, label in enumerate(model_classes):
            if label in self.full_label_space:
                idx = self.full_label_space.index(label)
                aligned[:, idx] = model_proba[:, i]
        return aligned

    def _calculate_confidence_metrics(self, proba_array):
        """Calculate multiple confidence metrics for probability distributions"""
        # Max probability (highest probability)
        max_conf = np.max(proba_array, axis=1)

        # Entropy-based confidence (lower entropy = higher confidence)
        entropy = -np.sum(proba_array * np.log(proba_array + 1e-10), axis=1)
        entropy_conf = 1 - (entropy / np.log(len(self.full_label_space)))  # Normalized

        # Margin confidence (difference between top 2 predictions)
        sorted_proba = np.sort(proba_array, axis=1)
        margin_conf = sorted_proba[:, -1] - sorted_proba[:, -2]

        # Gini coefficient based confidence
        gini_conf = 1 - np.sum(proba_array ** 2, axis=1)
        gini_conf = 1 - gini_conf  # Invert so higher = more confident

        return {
            'max_prob': max_conf,
            'entropy': entropy_conf,
            'margin': margin_conf,
            'gini': gini_conf
        }

    def _confidence_based_weighting(self, conf1, conf2, method='adaptive_ratio'):
        """Calculate adaptive weights based on confidence scores"""
        if method == 'adaptive_ratio':
            # Higher confidence gets higher weight
            total_conf = conf1 + conf2 + 1e-10  # Avoid division by zero
            w1 = conf1 / total_conf
            w2 = conf2 / total_conf

        elif method == 'exponential':
            # Exponential weighting emphasizes high confidence more
            exp_conf1 = np.exp(conf1 * 3)  # Scale factor of 3
            exp_conf2 = np.exp(conf2 * 3)
            total_exp = exp_conf1 + exp_conf2
            w1 = exp_conf1 / total_exp
            w2 = exp_conf2 / total_exp

        elif method == 'threshold_based':
            # If one model is very confident, give it more weight
            w1 = np.where(conf1 > self.confidence_threshold,
                         np.minimum(conf1 * 1.5, 0.9), 0.5)
            w2 = 1 - w1

        elif method == 'softmax':
            # Softmax weighting
            logits = np.column_stack([conf1, conf2])
            softmax_weights = np.exp(logits) / np.sum(np.exp(logits), axis=1, keepdims=True)
            w1 = softmax_weights[:, 0]
            w2 = softmax_weights[:, 1]

        else:  # default to simple ratio
            total_conf = conf1 + conf2 + 1e-10
            w1 = conf1 / total_conf
            w2 = conf2 / total_conf

        return w1, w2

    def predict_ensemble(self, X_input, model1, model2, method='confidence_adaptive', 
                        confidence_metric='max_prob'):
        """
        Enhanced ensemble prediction with adaptive weighting strategies
        
        Parameters:
        - X_input: Input features for prediction (should be PCA features)
        - model1, model2: Trained models (RF and LGB)
        - method: 'average', 'confidence_adaptive'
        - confidence_metric: 'max_prob', 'entropy', 'margin', 'gini'
        """
        try:
            self._setup_label_space(model1, model2)

            # Get probabilities from both models
            proba1 = model1.predict_proba(X_input)
            proba2 = model2.predict_proba(X_input)

            # Align probabilities
            aligned1 = self._align_probabilities(proba1, model1.classes_)
            aligned2 = self._align_probabilities(proba2, model2.classes_)

            # Calculate confidence metrics
            conf_metrics1 = self._calculate_confidence_metrics(aligned1)
            conf_metrics2 = self._calculate_confidence_metrics(aligned2)

            # Select confidence metric
            conf1 = conf_metrics1[confidence_metric]
            conf2 = conf_metrics2[confidence_metric]

            # Calculate weights based on method
            if method == 'average':
                # Simple average
                combined = (aligned1 + aligned2) / 2
                weights_used = np.full((len(X_input), 2), 0.5)

            elif method == 'confidence_adaptive':
                # Adaptive weighting based on confidence
                w1, w2 = self._confidence_based_weighting(conf1, conf2, 'adaptive_ratio')
                combined = (aligned1.T * w1).T + (aligned2.T * w2).T
                weights_used = np.column_stack([w1, w2])

            else:
                # Default to simple average
                combined = (aligned1 + aligned2) / 2
                weights_used = np.full((len(X_input), 2), 0.5)

            # Get final predictions
            predictions = [self.full_label_space[i] for i in np.argmax(combined, axis=1)]
            confidence_scores = np.max(combined, axis=1)

            # Store weighting information for analysis
            self.weighting_history.append({
                'method': method,
                'weights': weights_used,
                'confidences': np.column_stack([conf1, conf2]),
                'predictions': predictions
            })

            return predictions, confidence_scores, weights_used

        except Exception as e:
            logger.error(f"Error in ensemble prediction: {e}")
            return None, None, None

class EnsembleKafkaMLProcessor:
    """Kafka ML processor using adaptive ensemble methods with PCA feature transformation"""
    
    def __init__(self):
        self.ensemble_predictor = AdaptiveEnsemblePredictor()
        self.model1 = None  # RF(2017)
        self.model2 = None  # LGB(2018)
        self.pca_transformer = None
        self.scaler = None
        self.consumer = None
        
    def load_models(self):
        """Load both models and feature transformers for ensemble"""
        try:
            logger.info("Loading RF(2017) model from %s", MODEL1_PATH)
            self.model1 = joblib.load(MODEL1_PATH)
            
            logger.info("Loading LGB(2018) model from %s", MODEL2_PATH)
            self.model2 = joblib.load(MODEL2_PATH)
            
            # Try to load PCA transformer and scaler
            try:
                logger.info("Loading PCA transformer from %s", PCA_TRANSFORMER_PATH)
                self.pca_transformer = joblib.load(PCA_TRANSFORMER_PATH)
            except FileNotFoundError:
                logger.warning("PCA transformer not found. Will create synthetic PCA transformation.")
                self.pca_transformer = None
                
            try:
                logger.info("Loading StandardScaler from %s", SCALER_PATH)
                self.scaler = joblib.load(SCALER_PATH)
            except FileNotFoundError:
                logger.warning("StandardScaler not found. Will create synthetic scaling.")
                self.scaler = None
            
            logger.info("Models loaded successfully. RF classes: %s, LGB classes: %s", 
                       self.model1.classes_, self.model2.classes_)
            return True
            
        except Exception as e:
            logger.error("Failed to load models: %s", e)
            return False
    
    def setup_kafka_consumer(self):
        """Setup Kafka consumer"""
        try:
            self.consumer = KafkaConsumer(
                TOPIC,
                bootstrap_servers=KAFKA_BROKERS.split(","),
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                auto_offset_reset="latest",
                enable_auto_commit=True,
            )
            logger.info("Kafka consumer setup complete for topic: %s", TOPIC)
            return True
        except Exception as e:
            logger.error("Failed to setup Kafka consumer: %s", e)
            return False
    
    def transform_to_pca_features(self, traffic_data):
        """Transform raw CICIDS features to PCA features"""
        try:
            # Create DataFrame with all expected features
            feature_row = {}
            for feature in CICIDS_FEATURES:
                feature_row[feature] = traffic_data.get(feature, 0)
            
            df = pd.DataFrame([feature_row])
            
            if self.pca_transformer is not None and self.scaler is not None:
                # Use the actual PCA transformer from training
                scaled_data = self.scaler.transform(df)
                pca_features = self.pca_transformer.transform(scaled_data)
                
                # Create DataFrame with PCA feature names
                pca_columns = [f'PC{i+1}' for i in range(pca_features.shape[1])]
                pca_df = pd.DataFrame(pca_features, columns=pca_columns)
                
                logger.debug("Used actual PCA transformer: %s features -> %s components", 
                           len(CICIDS_FEATURES), pca_features.shape[1])
                
            else:
                # Create synthetic PCA transformation (fallback)
                logger.warning("Using synthetic PCA transformation - predictions may not be accurate")
                
                # Simple synthetic PCA: use weighted combinations of original features
                synthetic_pca_data = []
                
                # Create 34 synthetic principal components
                for pc_idx in range(34):
                    # Use different combinations for each PC
                    pc_value = 0
                    for i, feature in enumerate(CICIDS_FEATURES[:34]):  # Use first 34 features
                        weight = np.sin(pc_idx + i) * 0.1  # Synthetic weight
                        pc_value += traffic_data.get(feature, 0) * weight
                    synthetic_pca_data.append(pc_value)
                
                # Create PCA DataFrame
                pca_columns = [f'PC{i+1}' for i in range(34)]
                pca_df = pd.DataFrame([synthetic_pca_data], columns=pca_columns)
                
                logger.debug("Used synthetic PCA transformation: %s features -> 34 components", 
                           len(CICIDS_FEATURES))
            
            return pca_df
            
        except Exception as e:
            logger.error("PCA transformation failed: %s", e)
            return None
    
    def make_ensemble_prediction(self, pca_df, method='confidence_adaptive', 
                                confidence_metric='max_prob'):
        """Make prediction using adaptive ensemble on PCA features"""
        try:
            predictions, confidence_scores, weights = self.ensemble_predictor.predict_ensemble(
                pca_df, self.model1, self.model2, 
                method=method, confidence_metric=confidence_metric
            )
            
            if predictions is not None:
                return {
                    'prediction': predictions[0],  # Single prediction
                    'confidence': float(confidence_scores[0]),
                    'rf_weight': float(weights[0][0]),
                    'lgb_weight': float(weights[0][1]),
                    'method': method,
                    'confidence_metric': confidence_metric
                }
            else:
                return None
                
        except Exception as e:
            logger.error("Ensemble prediction failed: %s", e)
            return None
    
    def process_messages(self):
        """Main message processing loop"""
        if not self.load_models():
            logger.error("Failed to load models. Exiting.")
            return
            
        if not self.setup_kafka_consumer():
            logger.error("Failed to setup Kafka consumer. Exiting.")
            return
        
        logger.info("Starting ensemble prediction service...")
        logger.info("Expected input features: %s", ', '.join(CICIDS_FEATURES[:10]) + "...")
        
        try:
            for message in self.consumer:
                traffic_data = message.value
                logger.info("Received traffic data (profile=%s)", traffic_data.get("profile"))
                
                # Transform raw features to PCA
                pca_df = self.transform_to_pca_features(traffic_data)
                if pca_df is None:
                    logger.error("Failed to transform features to PCA")
                    continue
                
                # Make ensemble prediction with different methods
                methods_to_try = [
                    ('confidence_adaptive', 'max_prob'),
                    ('confidence_adaptive', 'entropy'),
                    ('average', 'max_prob')
                ]
                
                results = {}
                for method, conf_metric in methods_to_try:
                    result = self.make_ensemble_prediction(
                        pca_df, method=method, confidence_metric=conf_metric
                    )
                    if result:
                        results[f"{method}_{conf_metric}"] = result
                
                # Log all results
                if results:
                    logger.info("Ensemble Predictions:")
                    for method_name, result in results.items():
                        logger.info("  %s: %s (conf=%.3f, RF=%.3f, LGB=%.3f)", 
                                   method_name, result['prediction'], 
                                   result['confidence'], result['rf_weight'], result['lgb_weight'])
                    
                    # Use the confidence_adaptive with max_prob as primary prediction
                    primary_result = results.get('confidence_adaptive_max_prob', 
                                               list(results.values())[0])
                    
                    self.handle_prediction_result(traffic_data, primary_result, results)
                else:
                    logger.error("All ensemble prediction methods failed")
                    
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error("Error in message processing: %s", e)
        finally:
            if self.consumer:
                self.consumer.close()
                logger.info("Kafka consumer closed")
    
    def handle_prediction_result(self, original_data, primary_result, all_results):
        """Handle the prediction results (customize as needed)"""
        # Example: Log alerts for malicious traffic
        if primary_result['prediction'] != 'BENIGN':
            logger.warning("SECURITY ALERT: Malicious traffic detected!")
            logger.warning("  Type: %s", primary_result['prediction'])
            logger.warning("  Confidence: %.3f", primary_result['confidence'])
            logger.warning("  Model weights - RF: %.3f, LGB: %.3f", 
                          primary_result['rf_weight'], primary_result['lgb_weight'])
            logger.warning("  Original profile: %s", original_data.get('profile', 'unknown'))
    
    def get_ensemble_statistics(self):
        """Get statistics about ensemble performance"""
        if self.ensemble_predictor.weighting_history:
            history = self.ensemble_predictor.weighting_history
            logger.info("Ensemble Statistics:")
            logger.info("  Total predictions: %d", len(history))
            
            # Calculate average weights
            all_weights = np.vstack([h['weights'] for h in history])
            avg_rf_weight = np.mean(all_weights[:, 0])
            avg_lgb_weight = np.mean(all_weights[:, 1])
            
            logger.info("  Average RF weight: %.3f", avg_rf_weight)
            logger.info("  Average LGB weight: %.3f", avg_lgb_weight)
            
            return {
                'total_predictions': len(history),
                'avg_rf_weight': float(avg_rf_weight),
                'avg_lgb_weight': float(avg_lgb_weight)
            }
        return None

def main():
    """Main function"""
    processor = EnsembleKafkaMLProcessor()
    
    try:
        processor.process_messages()
    except Exception as e:
        logger.error("Application error: %s", e)
    finally:
        # Print final statistics
        stats = processor.get_ensemble_statistics()
        if stats:
            logger.info("Final ensemble statistics: %s", stats)

if __name__ == "__main__":
    main()