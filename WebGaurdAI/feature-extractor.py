import spacy
import tensorflow as tf
import cv2
import numpy as np
from transformers import BertTokenizer, BertModel
import re
from typing import Dict, List, Tuple
import torch
from PIL import Image
import io

class FeatureExtractor:
    def __init__(self):
        self.nlp = spacy.load('en_core_web_lg')
        self.bert_tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
        self.bert_model = BertModel.from_pretrained('bert-base-uncased')
        self.suspicious_patterns = self.load_suspicious_patterns()
        
    def load_suspicious_patterns(self) -> Dict[str, List[str]]:
        return {
            'phishing_keywords': [
                'verify.*account',
                'confirm.*password',
                'security.*update',
                'login.*expired'
            ],
            'suspicious_urls': [
                r'bit\.ly',
                r'tiny\.cc',
                r'(?!www\.|(?:http|ftp)s?://|[A-Za-z]:\\|//).*\.[A-Za-z]{2,6}',
            ]
        }
    
    def extract_features(self, html_content: str, url: str) -> Dict:
        text_features = self.extract_text_features(html_content)
        image_features = self.extract_image_features(html_content)
        url_features = self.analyze_url(url)
        
        return {
            'text_features': text_features,
            'image_features': image_features,
            'url_features': url_features,
            'combined_risk_score': self.calculate_risk_score(
                text_features, image_features, url_features
            )
        }
    
    def extract_text_features(self, html_content: str) -> Dict:
        # Extract clean text from HTML
        doc = self.nlp(html_content)
        
        # Get BERT embeddings
        inputs = self.bert_tokenizer(
            html_content,
            return_tensors="pt",
            max_length=512,
            truncation=True,
            padding=True
        )
        
        with torch.no_grad():
            bert_output = self.bert_model(**inputs)
            embeddings = bert_output.last_hidden_state.mean(dim=1)
        
        # Check for suspicious patterns
        suspicious_matches = []
        for pattern_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)
                suspicious_matches.extend([m.group() for m in matches])
        
        return {
            'bert_embeddings': embeddings.numpy().tolist(),
            'suspicious_patterns_found': suspicious_matches,
            'named_entities': [(ent.text, ent.label_) for ent in doc.ents],
            'text_length': len(doc),
            'sentence_count': len(list(doc.sents))
        }
    
    def extract_image_features(self, html_content: str) -> Dict:
        # Extract image tags and analyze them
        image_tags = re.findall(r'<img[^>]+src="([^">]+)"', html_content)
        
        image_features = []
        for img_src in image_tags:
            try:
                # In practice, you would download and process the image here
                # This is a placeholder for the image analysis logic
                image_features.append({
                    'src': img_src,
                    'analysis': {
                        'has_logo': self.detect_logo(img_src),
                        'is_suspicious': self.check_image_manipulation(img_src)
                    }
                })
            except Exception as e:
                continue
                
        return {'images': image_features}
    
    def detect_logo(self, image_path: str) -> bool:
        # Placeholder for logo detection logic
        # In practice, you would use a trained model here
        return False
    
    def check_image_manipulation(self, image_path: str) -> bool:
        # Placeholder for image manipulation detection
        # In practice, you would implement ELA or similar techniques
        return False
    
    def analyze_url(self, url: str) -> Dict:
        return {
            'length': len(url),
            'suspicious_patterns': [
                pattern for pattern in self.suspicious_patterns['suspicious_urls']
                if re.search(pattern, url, re.IGNORECASE)
            ],
            'contains_ip': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
            'subdomain_count': len(re.findall(r'\.', url)) - 1
        }
    
    def calculate_risk_score(
        self,
        text_features: Dict,
        image_features: Dict,
        url_features: Dict
    ) -> float:
        # Implement risk score calculation based on all features
        # This is a simplified version
        risk_score = 0.0
        
        # Add risk from suspicious patterns in text
        risk_score += len(text_features['suspicious_patterns_found']) * 0.1
        
        # Add risk from suspicious URL patterns
        risk_score += len(url_features['suspicious_patterns']) * 0.2
        
        # Add risk from suspicious images
        risk_score += sum(
            1 for img in image_features['images']
            if img['analysis']['is_suspicious']
        ) * 0.15
        
        return min(risk_score, 1.0)  # Normalize to [0,1]
