import tensorflow as tf
from tensorflow.keras import layers, Model
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
import numpy as np
from typing import Dict, List, Tuple
import json

class ThreatDetectionModel:
    def __init__(self, config_path: str = 'config/model_config.json'):
        self.load_config(config_path)
        self.setup_models()
        
    def load_config(self, config_path: str):
        with open(config_path) as f:
            self.config = json.load(f)
        
    def setup_models(self):
        # Text-based threat detection model (Transformer)
        self.text_model = self.build_transformer_model()
        
        # Anomaly detection model
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        
        # Load pre-trained weights if available
        self.load_weights()
        
    def build_transformer_model(self) -> Model:
        # Simple transformer model for sequence classification
        inputs = layers.Input(shape=(self.config['max_sequence_length'],))
        embedding = layers.Embedding(
            self.config['vocab_size'],
            self.config['embedding_dim']
        )(inputs)
        
        # Transformer block
        transformer_block = self.build_transformer_block(embedding)
        
        # Classification head
        pooled = layers.GlobalAveragePooling1D()(transformer_block)
        dropout = layers.Dropout(0.1)(pooled)
        outputs = layers.Dense(1, activation='sigmoid')(dropout)
        
        return Model(inputs=inputs, outputs=outputs)
    
    def build_transformer_block(self, inputs):
        # Multi-head attention
        attention = layers.MultiHeadAttention(
            num_heads=8,
            key_dim=64
        )(inputs, inputs)
        
        # Add & normalize
        attention = layers.LayerNormalization()(inputs + attention)
        
        # Feed forward network
        ffn = layers.Dense(512, activation='relu')(attention)
        ffn = layers.Dense(self.config['embedding_dim'])(ffn)
        
        return layers.LayerNormalization()(attention + ffn)
    
    def load_weights(self):
        try:
            self.text_model.load_weights(self.config['model_weights_path'])
        except:
            print("No pre-trained weights found. Using initialized weights.")
    
    def predict_threat(self, features: Dict) -> Dict:
        # Combine predictions from different models
        text_score = self.predict_text_threat(features['text_features'])
        anomaly_score = self.predict_anomaly(features)
        rule_based_score = self.apply_rules(features)
        
        # Weighted combination of scores
        final_score = (
            self.config['weights']['text'] * text_score +
            self.config['weights']['anomaly'] * anomaly_score +
            self.config['weights']['rules'] * rule_based_score
        )
        
        return {
            'threat_score': float(final_score),
            'component_scores': {
                'text_based': float(text_score),
                'anomaly': float(anomaly_score),
                'rule_based': float(rule_based_score)
            },
            'threat_level': self.get_threat_level(final_score),
            'confidence': self.calculate_confidence([
                text_score, anomaly_score, rule_based_score
            ])
        }
    
    def predict_text_threat(self, text_features: Dict) -> float:
        # Use the transformer model to predict text-based threats
        embeddings = np.array(text_features['bert_embeddings'])
        return float(self.text_model.predict(embeddings)[0])
    
    def predict_anomaly(self, features: Dict) -> float:
        # Convert features to flat array for anomaly detection
        feature_vector = self.flatten_features(features)
        
        # Get anomaly score (-1 for anomalies, 1 for normal)
        score = self.anomaly_detector.score_samples([feature_vector])[0]
        
        # Normalize to [0,1] where 1 indicates high anomaly
        return float(1 - (score + 1) / 2)
    
    def apply_rules(self, features: Dict) -> float:
        score = 0.0
        
        # Check suspicious patterns in text
        if features['text_features']['suspicious_patterns_found']:
            score += 0.3
            
        # Check URL features
        url_features = features['url_features']
        if url_features['contains_ip']:
            score += 0.2
        if url_features['suspicious_patterns']:
            score += 0.2
        if url_features['subdomain_count'] >



if url_features['subdomain_count'] > 2:
            score += 0.1
            
        # Check image features
        for image in features['image_features']['images']:
            if image['analysis']['is_suspicious']:
                score += 0.1
            if image['analysis']['has_logo']:
                score += 0.1
                
        return min(score, 1.0)
    
    def flatten_features(self, features: Dict) -> np.ndarray:
        """Convert nested feature dictionary to flat array for anomaly detection"""
        flat_features = []
        
        # Add text embeddings
        flat_features.extend(features['text_features']['bert_embeddings'][0])
        
        # Add URL features
        flat_features.extend([
            features['url_features']['length'],
            len(features['url_features']['suspicious_patterns']),
            int(features['url_features']['contains_ip']),
            features['url_features']['subdomain_count']
        ])
        
        # Add image features
        img_features = features['image_features']['images']
        flat_features.extend([
            len(img_features),
            sum(1 for img in img_features if img['analysis']['is_suspicious']),
            sum(1 for img in img_features if img['analysis']['has_logo'])
        ])
        
        return np.array(flat_features)
    
    def get_threat_level(self, score: float) -> str:
        """Convert numerical score to threat level category"""
        if score < 0.2:
            return 'LOW'
        elif score < 0.5:
            return 'MEDIUM'
        elif score < 0.8:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def calculate_confidence(self, scores: List[float]) -> float:
        """Calculate confidence score based on agreement between models"""
        # Standard deviation of scores - lower means higher confidence
        std_dev = np.std(scores)
        # Convert to confidence score (1 - normalized std dev)
        return float(1.0 - (std_dev / np.mean(scores)))
    
    def update_model(self, features: Dict, is_threat: bool):
        """Update the model with new labeled data"""
        # Update text model
        embeddings = np.array(features['text_features']['bert_embeddings'])
        self.text_model.fit(
            embeddings,
            np.array([int(is_threat)]),
            epochs=1,
            verbose=0
        )
        
        # Update anomaly detector
        feature_vector = self.flatten_features(features)
        self.anomaly_detector.fit([feature_vector])
    
    def save_weights(self):
        """Save model weights to disk"""
        self.text_model.save_weights(self.config['model_weights_path'])
