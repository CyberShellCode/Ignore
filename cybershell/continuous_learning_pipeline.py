import json
import pickle
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import logging
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
import joblib
import threading
import queue

logger = logging.getLogger(__name__)

@dataclass
class ExploitAttempt:
    """Records details of exploitation attempts for learning"""
    timestamp: datetime
    target: str
    vulnerability_type: str
    plugin_used: str
    success: bool
    confidence_score: float
    evidence_score: float
    execution_time: float
    error_details: Optional[str]
    environmental_factors: Dict[str, Any]
    payload_characteristics: Dict[str, Any]
    
class ContinuousLearningPipeline:
    """
    Implements continuous learning from exploitation attempts
    to improve success rates and reduce false positives
    """
    
    def __init__(self, model_dir: str = "models/adaptive"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Multiple models for different aspects
        self.models = {
            'vulnerability_classifier': None,
            'success_predictor': None,
            'payload_optimizer': None,
            'false_positive_detector': None
        }
        
        self.scalers = {}
        self.feature_importance = {}
        self.learning_history = []
        self.experience_buffer = queue.Queue(maxsize=10000)
        self.training_threshold = 100  # Retrain after N new experiences
        
        # Initialize or load existing models
        self._initialize_models()
        
        # Start background training thread
        self.training_thread = threading.Thread(target=self._background_training, daemon=True)
        self.training_thread.start()
        
    def _initialize_models(self):
        """Initialize or load existing models"""
        for model_name in self.models.keys():
            model_path = self.model_dir / f"{model_name}.pkl"
            scaler_path = self.model_dir / f"{model_name}_scaler.pkl"
            
            if model_path.exists():
                self.models[model_name] = joblib.load(model_path)
                if scaler_path.exists():
                    self.scalers[model_name] = joblib.load(scaler_path)
                logger.info(f"Loaded existing model: {model_name}")
            else:
                # Initialize new models based on type
                if model_name == 'vulnerability_classifier':
                    self.models[model_name] = RandomForestClassifier(
                        n_estimators=100, 
                        max_depth=10,
                        min_samples_split=5,
                        random_state=42
                    )
                elif model_name == 'success_predictor':
                    self.models[model_name] = GradientBoostingClassifier(
                        n_estimators=100,
                        learning_rate=0.1,
                        max_depth=5,
                        random_state=42
                    )
                else:
                    self.models[model_name] = RandomForestClassifier(
                        n_estimators=50,
                        random_state=42
                    )
                
                self.scalers[model_name] = StandardScaler()
                logger.info(f"Initialized new model: {model_name}")
    
    def record_exploitation_attempt(self, attempt: ExploitAttempt):
        """Record an exploitation attempt for learning"""
        self.experience_buffer.put(attempt)
        
        # Save to persistent storage
        self._save_experience(attempt)
        
        # Update feature importance if we have enough data
        if self.experience_buffer.qsize() >= self.training_threshold:
            self._trigger_retraining()
    
    def _save_experience(self, attempt: ExploitAttempt):
        """Save experience to persistent storage"""
        experience_file = self.model_dir / "experiences.jsonl"
        
        with open(experience_file, 'a') as f:
            experience_dict = asdict(attempt)
            experience_dict['timestamp'] = attempt.timestamp.isoformat()
            json.dump(experience_dict, f)
            f.write('\n')
    
    def _extract_features(self, attempt: ExploitAttempt) -> np.ndarray:
        """Extract features from exploitation attempt"""
        features = []
        
        # Basic features
        features.append(attempt.confidence_score)
        features.append(attempt.evidence_score)
        features.append(attempt.execution_time)
        
        # Vulnerability type encoding (one-hot)
        vuln_types = ['SQLI', 'XSS', 'RCE', 'IDOR', 'SSRF', 'XXE', 'SSTI', 'LFI']
        for vt in vuln_types:
            features.append(1.0 if attempt.vulnerability_type == vt else 0.0)
        
        # Environmental factors
        env_factors = attempt.environmental_factors or {}
        features.append(env_factors.get('response_time', 0))
        features.append(env_factors.get('server_type_score', 0))
        features.append(env_factors.get('waf_detected', 0))
        features.append(env_factors.get('rate_limit_encountered', 0))
        
        # Payload characteristics
        payload_chars = attempt.payload_characteristics or {}
        features.append(payload_chars.get('length', 0))
        features.append(payload_chars.get('complexity_score', 0))
        features.append(payload_chars.get('encoding_layers', 0))
        features.append(payload_chars.get('obfuscation_level', 0))
        
        # Time-based features
        hour = attempt.timestamp.hour
        features.append(np.sin(2 * np.pi * hour / 24))  # Cyclical encoding
        features.append(np.cos(2 * np.pi * hour / 24))
        
        return np.array(features)
    
    def _background_training(self):
        """Background thread for continuous model training"""
        while True:
            try:
                # Collect experiences for batch training
                experiences = []
                while len(experiences) < self.training_threshold:
                    attempt = self.experience_buffer.get(timeout=60)
                    experiences.append(attempt)
                
                if experiences:
                    self._train_models(experiences)
                    
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in background training: {e}")
    
    def _train_models(self, experiences: List[ExploitAttempt]):
        """Train models on new experiences"""
        logger.info(f"Training models on {len(experiences)} new experiences")
        
        # Prepare training data
        X = np.array([self._extract_features(exp) for exp in experiences])
        
        # Train vulnerability classifier
        y_vuln = [exp.vulnerability_type for exp in experiences]
        self._train_single_model('vulnerability_classifier', X, y_vuln)
        
        # Train success predictor
        y_success = [exp.success for exp in experiences]
        self._train_single_model('success_predictor', X, y_success)
        
        # Train false positive detector
        y_fp = [exp.evidence_score < 0.3 and exp.confidence_score > 0.7 for exp in experiences]
        self._train_single_model('false_positive_detector', X, y_fp)
        
        # Update feature importance
        self._update_feature_importance()
        
        # Save models
        self._save_models()
        
        # Record training history
        self.learning_history.append({
            'timestamp': datetime.now(),
            'samples_trained': len(experiences),
            'model_performance': self._evaluate_models(X, experiences)
        })
    
    def _train_single_model(self, model_name: str, X: np.ndarray, y: List):
        """Train a single model"""
        try:
            # Scale features
            X_scaled = self.scalers[model_name].fit_transform(X)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42
            )
            
            # Train model
            self.models[model_name].fit(X_train, y_train)
            
            # Evaluate
            score = self.models[model_name].score(X_test, y_test)
            logger.info(f"Model {model_name} accuracy: {score:.3f}")
            
        except Exception as e:
            logger.error(f"Error training {model_name}: {e}")
    
    def _update_feature_importance(self):
        """Update feature importance scores"""
        for model_name, model in self.models.items():
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[model_name] = model.feature_importances_
    
    def _save_models(self):
        """Save all models to disk"""
        for model_name, model in self.models.items():
            if model is not None:
                model_path = self.model_dir / f"{model_name}.pkl"
                scaler_path = self.model_dir / f"{model_name}_scaler.pkl"
                
                joblib.dump(model, model_path)
                if model_name in self.scalers:
                    joblib.dump(self.scalers[model_name], scaler_path)
    
    def _evaluate_models(self, X: np.ndarray, experiences: List[ExploitAttempt]) -> Dict:
        """Evaluate model performance"""
        performance = {}
        
        for model_name, model in self.models.items():
            if model is None:
                continue
                
            try:
                X_scaled = self.scalers[model_name].transform(X)
                
                # Get appropriate labels
                if model_name == 'vulnerability_classifier':
                    y_true = [exp.vulnerability_type for exp in experiences]
                elif model_name == 'success_predictor':
                    y_true = [exp.success for exp in experiences]
                elif model_name == 'false_positive_detector':
                    y_true = [exp.evidence_score < 0.3 and exp.confidence_score > 0.7 
                              for exp in experiences]
                else:
                    continue
                
                # Cross-validation score
                cv_scores = cross_val_score(model, X_scaled, y_true, cv=3)
                performance[model_name] = {
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std()
                }
                
            except Exception as e:
                logger.error(f"Error evaluating {model_name}: {e}")
                
        return performance
    
    def predict_success_probability(self, 
                                   vulnerability_type: str,
                                   target_characteristics: Dict,
                                   payload_characteristics: Dict) -> float:
        """Predict probability of successful exploitation"""
        
        # Create mock attempt for feature extraction
        mock_attempt = ExploitAttempt(
            timestamp=datetime.now(),
            target="",
            vulnerability_type=vulnerability_type,
            plugin_used="",
            success=False,
            confidence_score=target_characteristics.get('confidence', 0.5),
            evidence_score=0,
            execution_time=0,
            error_details=None,
            environmental_factors=target_characteristics,
            payload_characteristics=payload_characteristics
        )
        
        features = self._extract_features(mock_attempt).reshape(1, -1)
        
        if self.models['success_predictor'] is not None:
            try:
                features_scaled = self.scalers['success_predictor'].transform(features)
                prob = self.models['success_predictor'].predict_proba(features_scaled)[0, 1]
                return float(prob)
            except:
                pass
        
        return 0.5  # Default probability
    
    def detect_false_positive(self, 
                             confidence_score: float,
                             evidence_score: float,
                             exploit_details: Dict) -> Tuple[bool, float]:
        """Detect potential false positives"""
        
        mock_attempt = ExploitAttempt(
            timestamp=datetime.now(),
            target="",
            vulnerability_type=exploit_details.get('type', 'UNKNOWN'),
            plugin_used="",
            success=True,
            confidence_score=confidence_score,
            evidence_score=evidence_score,
            execution_time=exploit_details.get('execution_time', 0),
            error_details=None,
            environmental_factors=exploit_details.get('environmental_factors', {}),
            payload_characteristics=exploit_details.get('payload_characteristics', {})
        )
        
        features = self._extract_features(mock_attempt).reshape(1, -1)
        
        if self.models['false_positive_detector'] is not None:
            try:
                features_scaled = self.scalers['false_positive_detector'].transform(features)
                is_fp = self.models['false_positive_detector'].predict(features_scaled)[0]
                fp_prob = self.models['false_positive_detector'].predict_proba(features_scaled)[0, 1]
                return bool(is_fp), float(fp_prob)
            except:
                pass
        
        # Fallback heuristic
        if evidence_score < 0.3 and confidence_score > 0.7:
            return True, 0.8
        return False, 0.2
    
    def get_optimal_payload_characteristics(self, 
                                           vulnerability_type: str,
                                           target_info: Dict) -> Dict:
        """Get optimal payload characteristics based on learning"""
        
        # Load historical successes
        successful_attempts = self._load_successful_attempts(vulnerability_type)
        
        if not successful_attempts:
            # Return defaults
            return {
                'encoding_layers': 1,
                'obfuscation_level': 2,
                'complexity_score': 0.5,
                'recommended_techniques': []
            }
        
        # Analyze successful payloads
        optimal_chars = {
            'encoding_layers': np.median([a.payload_characteristics.get('encoding_layers', 1) 
                                         for a in successful_attempts]),
            'obfuscation_level': np.median([a.payload_characteristics.get('obfuscation_level', 1)
                                           for a in successful_attempts]),
            'complexity_score': np.mean([a.payload_characteristics.get('complexity_score', 0.5)
                                        for a in successful_attempts]),
            'recommended_techniques': self._extract_successful_techniques(successful_attempts)
        }
        
        return optimal_chars
    
    def _load_successful_attempts(self, vulnerability_type: str) -> List[ExploitAttempt]:
        """Load successful exploitation attempts from history"""
        attempts = []
        experience_file = self.model_dir / "experiences.jsonl"
        
        if experience_file.exists():
            with open(experience_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if (data.get('vulnerability_type') == vulnerability_type and 
                            data.get('success', False)):
                            # Reconstruct ExploitAttempt
                            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
                            attempts.append(ExploitAttempt(**data))
                    except:
                        continue
        
        return attempts[-100:]  # Return last 100 successful attempts
    
    def _extract_successful_techniques(self, attempts: List[ExploitAttempt]) -> List[str]:
        """Extract commonly successful techniques"""
        techniques = {}
        
        for attempt in attempts:
            if attempt.payload_characteristics:
                for technique in attempt.payload_characteristics.get('techniques', []):
                    techniques[technique] = techniques.get(technique, 0) + 1
        
        # Sort by frequency and return top techniques
        sorted_techniques = sorted(techniques.items(), key=lambda x: x[1], reverse=True)
        return [tech for tech, _ in sorted_techniques[:5]]
    
    def _trigger_retraining(self):
        """Trigger model retraining"""
        logger.info("Triggering model retraining due to new experiences")
        # The background thread will handle the actual training
    
    def get_learning_insights(self) -> Dict:
        """Get insights from the learning system"""
        return {
            'total_experiences': self.experience_buffer.qsize(),
            'model_performance': self.learning_history[-1] if self.learning_history else {},
            'feature_importance': self.feature_importance,
            'training_history': self.learning_history[-10:],  # Last 10 training sessions
            'recommended_retraining': self.experience_buffer.qsize() >= self.training_threshold
        }
