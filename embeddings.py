#!/usr/bin/env python3
"""Multi-backend embedding engine.

Provides unified interface for generating text embeddings.
Backends:
- Local: sentence-transformers (default, no API needed)
- OpenAI: text-embedding-3-small model
- Anthropic: Voyage AI fallback (Anthropic has no native embedding API)

Graceful fallback ensures the module works even when optional dependencies
are not installed.

Example:
    >>> from embeddings import get_embeddings, cosine_similarity
    >>> texts = ["reentrancy vulnerability", "access control issue"]
    >>> embeddings = get_embeddings(texts, backend="local")
    >>> similarity = cosine_similarity(embeddings[0], embeddings[1])
"""

from __future__ import annotations

import os
import math
import re
from typing import List, Optional, Any
from collections import Counter

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import CounterscarpError, CounterscarpConfigError
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None  # type: ignore[assignment]
    CounterscarpError = Exception  # type: ignore[misc,assignment]
    CounterscarpConfigError = Exception  # type: ignore[misc,assignment]

# Initialize logger
if LOGGER_AVAILABLE and get_logger is not None:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Optional dependency flags
SENTENCE_TRANSFORMERS_AVAILABLE = False
SKLEARN_AVAILABLE = False
NUMPY_AVAILABLE = False
OPENAI_AVAILABLE = False

# Try importing optional dependencies with graceful fallback
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SentenceTransformer = None

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    SKLEARN_AVAILABLE = True
except ImportError:
    TfidfVectorizer = None

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    openai = None

# Default model configurations
DEFAULT_LOCAL_MODEL = "all-MiniLM-L6-v2"
DEFAULT_OPENAI_MODEL = "text-embedding-3-small"
DEFAULT_VOYAGE_MODEL = "voyage-3-lite"

# Embedding dimensions
EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 dimension


class EmbeddingError(CounterscarpError):
    """Raised when embedding generation fails."""
    pass


class SimpleBagOfWords:
    """Pure Python bag-of-words vectorizer as ultimate fallback.

    Creates simple frequency-based embeddings when no ML libraries available.
    Uses feature hashing to produce fixed-dimension embeddings regardless
    of input text, ensuring consistent dimensions for indexing and querying.
    """

    def __init__(self, max_features: int = 384):
        """Initialize the bag-of-words vectorizer.

        Args:
            max_features: Fixed dimension of output vectors (default: 384).
        """
        self.max_features = max_features

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization - lowercase and extract words.

        Args:
            text: Input text to tokenize.

        Returns:
            List of tokens.
        """
        # Lowercase and extract alphanumeric sequences
        return re.findall(r'\b[a-z0-9]+\b', text.lower())

    def _hash_token(self, token: str) -> int:
        """Hash a token to a fixed bucket index.

        Args:
            token: The token to hash.

        Returns:
            Bucket index in range [0, max_features).
        """
        # Use Python's built-in hash with a fixed seed approach
        # Combine with a simple string hash for consistency
        hash_val = hash(token) % self.max_features
        return hash_val

    def fit_transform(self, texts: List[str]) -> List[List[float]]:
        """Transform texts to fixed-dimension vectors.

        Args:
            texts: List of texts to vectorize.

        Returns:
            List of vector representations with fixed dimension.
        """
        return self.transform(texts)

    def transform(self, texts: List[str]) -> List[List[float]]:
        """Transform texts to fixed-dimension vectors using feature hashing.

        Args:
            texts: List of texts to vectorize.

        Returns:
            List of vector representations with fixed dimension.
        """
        vectors = []

        for text in texts:
            tokens = self._tokenize(text)
            token_counts = Counter(tokens)

            # Create frequency vector using feature hashing
            vector = [0.0] * self.max_features
            for token, count in token_counts.items():
                idx = self._hash_token(token)
                vector[idx] += float(count)

            # Normalize to unit length (L2 norm)
            norm = math.sqrt(sum(x * x for x in vector))
            if norm > 0:
                vector = [x / norm for x in vector]

            vectors.append(vector)

        return vectors


# Global cache for models
_local_model_cache: Optional[Any] = None


def _get_local_model() -> Optional[Any]:
    """Get or load the local sentence-transformers model.
    
    Returns:
        Loaded SentenceTransformer model or None if not available.
    """
    global _local_model_cache
    
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    
    if _local_model_cache is None:
        try:
            logger.info(
                f"Loading local embedding model: {DEFAULT_LOCAL_MODEL}"
            )
            _local_model_cache = SentenceTransformer(DEFAULT_LOCAL_MODEL)
            logger.debug("Local embedding model loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load sentence-transformers model: {e}")
            return None
    
    return _local_model_cache


def embed_local(texts: List[str]) -> List[List[float]]:
    """Generate embeddings using local sentence-transformers model.
    
    Falls back to TF-IDF if sentence-transformers not available,
    then to pure Python bag-of-words if sklearn not available.
    
    Args:
        texts: List of texts to embed.
        
    Returns:
        List of embedding vectors.
        
    Raises:
        EmbeddingError: If embedding generation fails.
    """
    if not texts:
        return []
    
    # Try sentence-transformers first
    if SENTENCE_TRANSFORMERS_AVAILABLE:
        model = _get_local_model()
        if model is not None:
            try:
                logger.debug(
                    f"Generating embeddings for {len(texts)} texts"
                )
                embeddings = model.encode(
                    texts, convert_to_numpy=True, show_progress_bar=False
                )
                
                # Convert numpy arrays to Python lists
                if NUMPY_AVAILABLE:
                    return [emb.tolist() for emb in embeddings]
                else:
                    return [list(emb) for emb in embeddings]
                    
            except Exception as e:
                logger.warning(
                    f"sentence-transformers failed: {e}, trying fallback"
                )
    
    # Fall back to TF-IDF
    if SKLEARN_AVAILABLE:
        try:
            logger.debug(
                f"Generating embeddings for {len(texts)} texts using TF-IDF"
            )
            vectorizer = TfidfVectorizer(
                max_features=EMBEDDING_DIM, stop_words='english'
            )
            tfidf_matrix = vectorizer.fit_transform(texts)
            
            # Convert to dense list format
            if NUMPY_AVAILABLE:
                dense = tfidf_matrix.toarray()
                return [row.tolist() for row in dense]
            else:
                # Manual conversion if numpy not available
                dense = tfidf_matrix.toarray()
                return [list(row) for row in dense]
                
        except Exception as e:
            logger.warning(f"TF-IDF failed: {e}, trying bag-of-words")
    
    # Ultimate fallback: pure Python bag-of-words
    logger.debug(f"Generating embeddings for {len(texts)} texts")
    bow = SimpleBagOfWords(max_features=EMBEDDING_DIM)
    return bow.fit_transform(texts)


def embed_openai(
    texts: List[str], api_key: Optional[str] = None
) -> List[List[float]]:
    """Generate embeddings using OpenAI API.
    
    Args:
        texts: List of texts to embed.
        api_key: OpenAI API key. If not provided, reads from OPENAI_API_KEY
            environment variable.
        
    Returns:
        List of embedding vectors.
        
    Raises:
        EmbeddingError: If embedding generation fails or API key is missing.
    """
    if not texts:
        return []
    
    if not OPENAI_AVAILABLE:
        raise EmbeddingError(
            "OpenAI library not installed. Install with: pip install openai"
        )
    
    # Get API key
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise EmbeddingError(
            "OpenAI API key not provided. Set OPENAI_API_KEY "
            "environment variable or pass api_key parameter."
        )
    
    try:
        logger.debug(f"Generating embeddings for {len(texts)} texts")
        client = openai.OpenAI(api_key=key)
        
        # OpenAI has a limit of 2048 texts per request
        all_embeddings = []
        batch_size = 100  # Conservative batch size
        
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            response = client.embeddings.create(
                model=DEFAULT_OPENAI_MODEL,
                input=batch
            )
            batch_embeddings = [item.embedding for item in response.data]
            all_embeddings.extend(batch_embeddings)
        
        return all_embeddings
        
    except Exception as e:
        logger.error(f"OpenAI embedding failed: {e}")
        raise EmbeddingError(f"OpenAI embedding failed: {e}") from e


def embed_anthropic(
    texts: List[str], api_key: Optional[str] = None
) -> List[List[float]]:
    """Generate embeddings using Anthropic/Voyage AI.
    
    Note: Anthropic doesn't have a native embedding API, so this uses
    Voyage AI embeddings which is the recommended provider for Anthropic users.
    Falls back to local embeddings if Voyage AI is not available.
    
    Args:
        texts: List of texts to embed.
        api_key: Voyage AI API key. If not provided, reads from VOYAGE_API_KEY
            environment variable.
        
    Returns:
        List of embedding vectors.
        
    Raises:
        EmbeddingError: If embedding generation fails.
    """
    if not texts:
        return []
    
    # Try Voyage AI first
    key = api_key or os.getenv("VOYAGE_API_KEY") or \
        os.getenv("ANTHROPIC_API_KEY")
    
    if key:
        try:
            # Try importing voyageai
            try:
                import voyageai
                VOYAGE_AVAILABLE = True
            except ImportError:
                VOYAGE_AVAILABLE = False
            
            if VOYAGE_AVAILABLE:
                logger.debug(
                    f"Generating embeddings for {len(texts)} texts"
                )
                client = voyageai.Client(api_key=key)
                
                all_embeddings = []
                batch_size = 72  # Voyage AI batch limit
                
                for i in range(0, len(texts), batch_size):
                    batch = texts[i:i + batch_size]
                    result = client.embed(
                        batch,
                        model=DEFAULT_VOYAGE_MODEL,
                        input_type="document"
                    )
                    all_embeddings.extend(result.embeddings)
                
                return all_embeddings
                
        except Exception as e:
            logger.warning(f"Voyage AI failed: {e}, falling back to local")
    else:
        logger.debug("No Voyage AI API key found, using local")
    
    # Fall back to local embeddings
    logger.info("Falling back to local embeddings for Anthropic backend")
    return embed_local(texts)


def get_embeddings(
    texts: List[str],
    backend: str = "local",
    api_key: Optional[str] = None
) -> List[List[float]]:
    """Unified interface for generating text embeddings.
    
    Routes to the appropriate backend based on the backend parameter.
    Falls back gracefully if the preferred backend is unavailable.
    
    Args:
        texts: List of texts to embed.
        backend: Backend to use ("local", "openai", "anthropic").
        api_key: Optional API key for cloud backends.
        
    Returns:
        List of embedding vectors.
        
    Raises:
        EmbeddingError: If all backends fail.
        
    Example:
        >>> texts = ["reentrancy attack", "access control vulnerability"]
        >>> embeddings = get_embeddings(texts, backend="local")
        >>> len(embeddings)
        2
    """
    if not texts:
        return []
    
    backend = backend.lower()
    errors = []
    
    # Try requested backend first
    if backend == "local":
        try:
            return embed_local(texts)
        except Exception as e:
            errors.append(f"Local backend failed: {e}")
            logger.warning(f"Local embedding failed: {e}")
    
    elif backend == "openai":
        try:
            return embed_openai(texts, api_key)
        except Exception as e:
            errors.append(f"OpenAI backend failed: {e}")
            logger.warning(f"OpenAI failed: {e}, trying local fallback")
            try:
                return embed_local(texts)
            except Exception as e2:
                errors.append(f"Local fallback failed: {e2}")
    
    elif backend == "anthropic":
        try:
            return embed_anthropic(texts, api_key)
        except Exception as e:
            errors.append(f"Anthropic backend failed: {e}")
            logger.warning(f"Anthropic failed: {e}, trying local fallback")
            try:
                return embed_local(texts)
            except Exception as e2:
                errors.append(f"Local fallback failed: {e2}")
    
    else:
        raise EmbeddingError(
            f"Unknown backend: {backend}. "
            f"Use 'local', 'openai', or 'anthropic'."
        )
    
    # If we get here, all backends failed
    raise EmbeddingError(
        f"All embedding backends failed for backend '{backend}'",
        details={"errors": errors, "backend": backend}
    )


def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Calculate cosine similarity between two vectors.
    
    Args:
        vec_a: First vector.
        vec_b: Second vector.
        
    Returns:
        Cosine similarity score between -1 and 1.
        
    Example:
        >>> a = [1.0, 0.0, 0.0]
        >>> b = [1.0, 0.0, 0.0]
        >>> cosine_similarity(a, b)
        1.0
    """
    if not vec_a or not vec_b:
        return 0.0
    
    if len(vec_a) != len(vec_b):
        raise ValueError(
            f"Vectors must have same dimension: {len(vec_a)} vs {len(vec_b)}"
        )
    
    # Calculate dot product
    dot_product = sum(a * b for a, b in zip(vec_a, vec_b))
    
    # Calculate magnitudes
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))
    
    # Handle zero vectors
    if mag_a == 0 or mag_b == 0:
        return 0.0
    
    return dot_product / (mag_a * mag_b)


def batch_cosine_similarity(
    query_vec: List[float],
    vectors: List[List[float]]
) -> List[float]:
    """Calculate cosine similarity between a query and multiple vectors.
    
    Args:
        query_vec: The query vector.
        vectors: List of vectors to compare against.
        
    Returns:
        List of similarity scores.
    """
    return [cosine_similarity(query_vec, vec) for vec in vectors]


if __name__ == "__main__":
    # Demo/test code
    print("Testing Embedding Engine\n")
    
    test_texts = [
        "Reentrancy vulnerability in withdraw function",
        "Access control missing on critical function",
        "Integer overflow in token calculation",
        "Oracle price manipulation vulnerability",
        "Reentrant call pattern detected in contract",
    ]
    
    # Test local embeddings
    print("1. Testing local embeddings:")
    try:
        embeddings = embed_local(test_texts)
        print(f"   Generated {len(embeddings)} embeddings")
        print(f"   Dimension: {len(embeddings[0])}")
        
        # Test similarity
        sim = cosine_similarity(embeddings[0], embeddings[4])
        print(f"   Similarity (reentrancy vs reentrancy): {sim:.4f}")
        
        sim2 = cosine_similarity(embeddings[0], embeddings[1])
        print(f"   Similarity (reentrancy vs access control): {sim2:.4f}")
        
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test unified interface
    print("\n2. Testing unified interface (local backend):")
    try:
        embeddings = get_embeddings(test_texts, backend="local")
        print(f"   Generated {len(embeddings)} embeddings")
    except Exception as e:
        print(f"   Error: {e}")
    
    # Test OpenAI (if key available)
    if os.getenv("OPENAI_API_KEY"):
        print("\n3. Testing OpenAI backend:")
        try:
            embeddings = embed_openai(test_texts[:2])
            print(f"   Generated {len(embeddings)} embeddings")
            print(f"   Dimension: {len(embeddings[0])}")
        except Exception as e:
            print(f"   Error: {e}")
    else:
        print("\n3. Skipping OpenAI test (no API key)")
    
    print("\n4. Testing bag-of-words fallback:")
    bow = SimpleBagOfWords(max_features=100)
    vectors = bow.fit_transform(test_texts)
    print(f"   Generated {len(vectors)} vectors")
    print(f"   Vocabulary size: {bow.max_features}")
    print(f"   Dimension: {len(vectors[0])}")
