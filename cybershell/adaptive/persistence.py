"""
Model persistence module for CyberShell adaptive learning.
Provides atomic file operations and type-safe model storage.
"""

from dataclasses import dataclass
from typing import Optional, TypeVar, Generic
from pathlib import Path
import os
import tempfile
import joblib
import logging

logger = logging.getLogger(__name__)

# Generic type variable for model storage
T = TypeVar('T')


@dataclass
class ModelStore(Generic[T]):
    """
    Type-safe model storage with atomic file operations.
    
    WARNING: This class uses joblib which relies on pickle for serialization.
    Loading models from untrusted sources is a security risk as pickle can
    execute arbitrary code during deserialization. Only load models from
    trusted sources that you have created yourself.
    
    Args:
        path: Path to store the model file
        
    Example:
        store: ModelStore[MyModel] = ModelStore("models/my_model.joblib")
        store.save(my_model)
        loaded_model = store.load()  # Returns Optional[MyModel]
    """
    path: str = "cybershell_mapper.joblib"
    
    def save(self, model: T) -> None:
        """
        Save model to disk using atomic write operation.
        
        This method ensures the write is atomic by:
        1. Writing to a temporary file in the same directory
        2. Fsyncing the data to ensure it's written to disk
        3. Atomically replacing the target file
        
        Args:
            model: The model object to save
            
        Raises:
            OSError: If file operations fail
            Exception: If serialization fails
        """
        target_path = Path(self.path)
        
        # Ensure parent directory exists
        parent_dir = target_path.parent
        os.makedirs(parent_dir, exist_ok=True)
        
        # Create temporary file in the same directory for atomic rename
        # Same directory ensures we're on the same filesystem
        try:
            with tempfile.NamedTemporaryFile(
                mode='wb',
                dir=parent_dir,
                prefix='.tmp_',
                suffix='.joblib',
                delete=False
            ) as tmp_file:
                temp_path = tmp_file.name
                
                # Write model to temporary file
                joblib.dump(model, tmp_file)
                
                # Ensure data is written to disk
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            
            # Atomically replace the target file
            # os.replace is atomic on POSIX systems
            os.replace(temp_path, self.path)
            
            logger.debug(f"Model saved successfully to {self.path}")
            
        except Exception as e:
            # Clean up temporary file if it exists
            try:
                if 'temp_path' in locals() and os.path.exists(temp_path):
                    os.unlink(temp_path)
            except OSError:
                pass  # Ignore cleanup errors
            
            logger.error(f"Failed to save model to {self.path}: {e}")
            raise
    
    def load(self) -> Optional[T]:
        """
        Load model from disk if it exists.
        
        WARNING: This method uses joblib.load which uses pickle internally.
        Only load model files from trusted sources as pickle can execute
        arbitrary code during deserialization. Never load models from
        untrusted or unverified sources.
        
        Returns:
            The loaded model if successful, None if file doesn't exist
            or loading fails
            
        Security Note:
            - Only load models you created yourself
            - Verify file integrity if loading from shared storage
            - Consider using cryptographic signatures for model files
            - Never load models downloaded from untrusted sources
        """
        model_path = Path(self.path)
        
        # Check if file exists
        if not model_path.exists():
            logger.debug(f"Model file does not exist: {self.path}")
            return None
        
        try:
            # Load model from file
            # WARNING: joblib uses pickle - only load trusted files
            model = joblib.load(model_path)
            logger.debug(f"Model loaded successfully from {self.path}")
            return model
            
        except Exception as e:
            logger.warning(f"Failed to load model from {self.path}: {e}")
            return None
    
    def exists(self) -> bool:
        """Check if the model file exists."""
        return Path(self.path).exists()
    
    def delete(self) -> bool:
        """
        Delete the model file if it exists.
        
        Returns:
            True if file was deleted, False if it didn't exist
        """
        model_path = Path(self.path)
        if model_path.exists():
            try:
                model_path.unlink()
                logger.debug(f"Model file deleted: {self.path}")
                return True
            except OSError as e:
                logger.error(f"Failed to delete model file {self.path}: {e}")
                raise
        return False
    
    def get_file_info(self) -> Optional[dict]:
        """
        Get information about the stored model file.
        
        Returns:
            Dictionary with file info or None if file doesn't exist
        """
        model_path = Path(self.path)
        if not model_path.exists():
            return None
        
        stat = model_path.stat()
        return {
            'path': str(model_path.absolute()),
            'size_bytes': stat.st_size,
            'modified_time': stat.st_mtime,
            'created_time': stat.st_ctime,
            'is_file': model_path.is_file(),
            'is_symlink': model_path.is_symlink()
        }


# Specialized model stores for common model types
class SklearnModelStore(ModelStore):
    """Specialized store for scikit-learn models."""
    pass


class TensorModelStore(ModelStore):
    """Specialized store for TensorFlow/PyTorch models."""
    
    def save_with_metadata(self, model: T, metadata: dict) -> None:
        """Save model with additional metadata."""
        bundle = {
            'model': model,
            'metadata': metadata
        }
        super().save(bundle)
    
    def load_with_metadata(self) -> Optional[tuple[T, dict]]:
        """Load model and metadata."""
        bundle = super().load()
        if bundle and isinstance(bundle, dict) and 'model' in bundle:
            return bundle['model'], bundle.get('metadata', {})
        return None


def create_model_store(model_type: str, path: str) -> ModelStore:
    """
    Factory function to create appropriate model store.
    
    Args:
        model_type: Type of model ('sklearn', 'tensor', 'generic')
        path: Path to store the model
        
    Returns:
        Appropriate ModelStore instance
    """
    if model_type == 'sklearn':
        return SklearnModelStore(path)
    elif model_type == 'tensor':
        return TensorModelStore(path)
    else:
        return ModelStore(path)
