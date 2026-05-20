#!/usr/bin/env python3
"""Optimized multi-backend embedding engine.

Provides unified interface for generating text embeddings.
Backends:
- Local: sentence-transformers (default, no API needed)
- OpenAI: text-embedding-3-small model
- Anthropic: Voyage AI fallback (Anthropic has no native embedding API)

Graceful fallback ensures the module works even when optional dependencies
are not installed.
"""

from __future__ import annotations

import importlib.util as _ilu
import math
import os
import re
from collections import Counter
from functools import lru_cache
from typing import TYPE_CHECKING, Any, List, Optional

from exceptions import CounterscarpError

if TYPE_CHECKING:
    import numpy as _np_typing  # noqa: F401

try:
    from logger import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


def _module_available(name: str) -> bool:
    """Return True if module spec is resolvable without import side effects."""
    try:
        return _ilu.find_spec(name) is not None
    except (ValueError, ModuleNotFoundError):
        return False


NUMPY_AVAILABLE = _module_available("numpy")
SENTENCE_TRANSFORMERS_AVAILABLE = _module_available("sentence_transformers")
SKLEARN_AVAILABLE = _module_available("sklearn")
OPENAI_AVAILABLE = _module_available("openai")
VOYAGE_AVAILABLE = _module_available("voyageai")

# Keep module-level names for test monkeypatch compatibility.
openai: Any = None
voyageai: Any = None
SentenceTransformer: Any = None
TfidfVectorizer: Any = None

DEFAULT_LOCAL_MODEL = "all-MiniLM-L6-v2"
DEFAULT_OPENAI_MODEL = "text-embedding-3-small"
DEFAULT_VOYAGE_MODEL = "voyage-3-lite"
EMBEDDING_DIM = 384
_TOKEN_RX = re.compile(r"\b[a-z0-9]+\b")


class EmbeddingError(CounterscarpError):
    """Raised when embedding generation fails."""


class SimpleBagOfWords:
    """Pure Python bag-of-words vectorizer as final fallback."""

    def __init__(self, max_features: int = EMBEDDING_DIM):
        self.max_features = max_features

    def _tokenize(self, text: str) -> List[str]:
        return _TOKEN_RX.findall(text.lower())

    def _hash_token(self, token: str) -> int:
        return hash(token) % self.max_features

    def fit_transform(self, texts: List[str]) -> List[List[float]]:
        return self.transform(texts)

    def transform(self, texts: List[str]) -> List[List[float]]:
        dim = self.max_features

        if NUMPY_AVAILABLE:
            import numpy as np

            output: List[List[float]] = []
            for text in texts:
                tokens = self._tokenize(text)
                if not tokens:
                    output.append([0.0] * dim)
                    continue
                vec = np.zeros(dim, dtype=np.float64)
                for token, count in Counter(tokens).items():
                    vec[self._hash_token(token)] += count
                norm = float(np.linalg.norm(vec))
                if norm > 0.0:
                    vec /= norm
                output.append(vec.tolist())
            return output

        output = []
        for text in texts:
            tokens = self._tokenize(text)
            if not tokens:
                output.append([0.0] * dim)
                continue

            sparse: dict[int, float] = {}
            for token, count in Counter(tokens).items():
                idx = self._hash_token(token)
                sparse[idx] = sparse.get(idx, 0.0) + float(count)

            norm_sq = 0.0
            for value in sparse.values():
                norm_sq += value * value
            if norm_sq > 0.0:
                inv = 1.0 / math.sqrt(norm_sq)
                for idx in sparse:
                    sparse[idx] *= inv

            vec = [0.0] * dim
            for idx, value in sparse.items():
                vec[idx] = value
            output.append(vec)
        return output


@lru_cache(maxsize=1)
def _get_local_model() -> Optional[Any]:
    """Get or load sentence-transformers model lazily."""
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None
    try:
        logger.info("Loading local embedding model: %s", DEFAULT_LOCAL_MODEL)
        global SentenceTransformer
        if SentenceTransformer is None:
            from sentence_transformers import (
                SentenceTransformer as _SentenceTransformer,
            )

            SentenceTransformer = _SentenceTransformer
        model = SentenceTransformer(DEFAULT_LOCAL_MODEL)
        logger.debug("Local embedding model loaded successfully")
        return model
    except Exception as exc:
        logger.warning("Failed to load sentence-transformers model: %s", exc)
        return None


def embed_local(texts: List[str]) -> List[List[float]]:
    """Generate embeddings locally with graceful degradation."""
    if not texts:
        return []

    if SENTENCE_TRANSFORMERS_AVAILABLE:
        model = _get_local_model()
        if model is not None:
            try:
                logger.debug("Generating embeddings for %d texts", len(texts))
                embeddings = model.encode(
                    texts,
                    convert_to_numpy=True,
                    show_progress_bar=False,
                )
                return [emb.tolist() for emb in embeddings]
            except Exception as exc:
                logger.warning(
                    "sentence-transformers failed: %s, trying fallback",
                    exc,
                )

    if SKLEARN_AVAILABLE:
        try:
            global TfidfVectorizer
            if TfidfVectorizer is None:
                from sklearn.feature_extraction.text import (
                    TfidfVectorizer as _TfidfVectorizer,
                )

                TfidfVectorizer = _TfidfVectorizer
            logger.debug(
                "Generating embeddings for %d texts using TF-IDF",
                len(texts),
            )
            vectorizer = TfidfVectorizer(
                max_features=EMBEDDING_DIM,
                stop_words="english",
            )
            dense = vectorizer.fit_transform(texts).toarray()
            return [row.tolist() for row in dense]
        except Exception as exc:
            logger.warning("TF-IDF failed: %s, trying bag-of-words", exc)

    logger.debug("Generating embeddings for %d texts", len(texts))
    return SimpleBagOfWords(max_features=EMBEDDING_DIM).fit_transform(texts)


def embed_openai(
    texts: List[str],
    api_key: Optional[str] = None,
) -> List[List[float]]:
    """Generate embeddings using OpenAI API."""
    if not texts:
        return []
    if not OPENAI_AVAILABLE:
        raise EmbeddingError(
            "OpenAI library not installed. Install with: pip install openai",
        )

    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise EmbeddingError(
            "OpenAI API key not provided. Set OPENAI_API_KEY "
            "environment variable or pass api_key parameter.",
        )

    try:
        global openai
        if openai is None:
            import openai as _openai_real

            openai = _openai_real
        logger.debug("Generating embeddings for %d texts", len(texts))
        client = openai.OpenAI(api_key=key)

        all_embeddings: List[List[float]] = []
        batch_size = 100
        for idx in range(0, len(texts), batch_size):
            batch = texts[idx:idx + batch_size]
            response = client.embeddings.create(
                model=DEFAULT_OPENAI_MODEL,
                input=batch,
            )
            all_embeddings.extend(item.embedding for item in response.data)
        return all_embeddings
    except Exception as exc:
        logger.error("OpenAI embedding failed: %s", exc)
        raise EmbeddingError(f"OpenAI embedding failed: {exc}") from exc


def embed_anthropic(
    texts: List[str],
    api_key: Optional[str] = None,
) -> List[List[float]]:
    """Generate embeddings using Voyage AI (Anthropic-compatible path)."""
    if not texts:
        return []

    key = (
        api_key
        or os.getenv("VOYAGE_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
    )
    if key and VOYAGE_AVAILABLE:
        try:
            global voyageai
            if voyageai is None:
                import voyageai as _voyageai_real

                voyageai = _voyageai_real
            logger.debug("Generating embeddings for %d texts", len(texts))
            client = voyageai.Client(api_key=key)

            all_embeddings: List[List[float]] = []
            batch_size = 72
            for idx in range(0, len(texts), batch_size):
                batch = texts[idx:idx + batch_size]
                result = client.embed(
                    batch,
                    model=DEFAULT_VOYAGE_MODEL,
                    input_type="document",
                )
                all_embeddings.extend(result.embeddings)
            return all_embeddings
        except Exception as exc:
            logger.warning("Voyage AI failed: %s, falling back to local", exc)
    else:
        logger.debug("No Voyage AI API key found, using local")

    logger.info("Falling back to local embeddings for Anthropic backend")
    return embed_local(texts)


def get_embeddings(
    texts: List[str],
    backend: str = "local",
    api_key: Optional[str] = None,
) -> List[List[float]]:
    """Unified interface for generating text embeddings."""
    if not texts:
        return []

    backend = backend.lower()
    errors: List[str] = []

    if backend == "local":
        try:
            return embed_local(texts)
        except Exception as exc:
            errors.append(f"Local backend failed: {exc}")
            logger.warning("Local embedding failed: %s", exc)
    elif backend == "openai":
        try:
            return embed_openai(texts, api_key)
        except Exception as exc:
            errors.append(f"OpenAI backend failed: {exc}")
            logger.warning("OpenAI failed: %s, trying local fallback", exc)
            try:
                return embed_local(texts)
            except Exception as fallback_exc:
                errors.append(f"Local fallback failed: {fallback_exc}")
    elif backend == "anthropic":
        try:
            return embed_anthropic(texts, api_key)
        except Exception as exc:
            errors.append(f"Anthropic backend failed: {exc}")
            logger.warning("Anthropic failed: %s, trying local fallback", exc)
            try:
                return embed_local(texts)
            except Exception as fallback_exc:
                errors.append(f"Local fallback failed: {fallback_exc}")
    else:
        raise EmbeddingError(
            f"Unknown backend: {backend}. "
            "Use 'local', 'openai', or 'anthropic'.",
        )

    raise EmbeddingError(
        f"All embedding backends failed for backend '{backend}'",
        details={"errors": errors, "backend": backend},
    )


def cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if not vec_a or not vec_b:
        return 0.0
    if len(vec_a) != len(vec_b):
        raise ValueError(
            f"Vectors must have same dimension: {len(vec_a)} vs {len(vec_b)}",
        )

    if NUMPY_AVAILABLE:
        import numpy as np

        arr_a = np.asarray(vec_a, dtype=np.float64)
        arr_b = np.asarray(vec_b, dtype=np.float64)
        mag_a = float(np.linalg.norm(arr_a))
        mag_b = float(np.linalg.norm(arr_b))
        if mag_a == 0.0 or mag_b == 0.0:
            return 0.0
        return float(np.dot(arr_a, arr_b) / (mag_a * mag_b))

    dot_product = 0.0
    mag_a_sq = 0.0
    mag_b_sq = 0.0
    for aval, bval in zip(vec_a, vec_b):
        dot_product += aval * bval
        mag_a_sq += aval * aval
        mag_b_sq += bval * bval
    if mag_a_sq == 0.0 or mag_b_sq == 0.0:
        return 0.0
    return dot_product / (math.sqrt(mag_a_sq) * math.sqrt(mag_b_sq))


def batch_cosine_similarity(
    query_vec: List[float],
    vectors: List[List[float]],
) -> List[float]:
    """Calculate cosine similarity between a query and multiple vectors."""
    if not vectors:
        return []

    if NUMPY_AVAILABLE:
        import numpy as np

        query = np.asarray(query_vec, dtype=np.float64)
        matrix = np.asarray(vectors, dtype=np.float64)
        query_norm = float(np.linalg.norm(query))
        if query_norm == 0.0:
            return [0.0] * len(vectors)

        row_norms = np.linalg.norm(matrix, axis=1)
        safe_norms = row_norms.copy()
        safe_norms[safe_norms == 0.0] = 1.0
        scores = (matrix @ query) / (safe_norms * query_norm)
        scores[row_norms == 0.0] = 0.0
        return scores.tolist()

    return [cosine_similarity(query_vec, vec) for vec in vectors]


if __name__ == "__main__":
    print("Testing Embedding Engine\n")

    test_texts = [
        "Reentrancy vulnerability in withdraw function",
        "Access control missing on critical function",
        "Integer overflow in token calculation",
        "Oracle price manipulation vulnerability",
        "Reentrant call pattern detected in contract",
    ]

    print("1. Testing local embeddings:")
    try:
        embeddings = embed_local(test_texts)
        print(f"   Generated {len(embeddings)} embeddings")
        print(f"   Dimension: {len(embeddings[0])}")

        sim = cosine_similarity(embeddings[0], embeddings[4])
        print(f"   Similarity (reentrancy vs reentrancy): {sim:.4f}")

        sim2 = cosine_similarity(embeddings[0], embeddings[1])
        print(f"   Similarity (reentrancy vs access control): {sim2:.4f}")
    except Exception as exc:
        print(f"   Error: {exc}")

    print("\n2. Testing unified interface (local backend):")
    try:
        embeddings = get_embeddings(test_texts, backend="local")
        print(f"   Generated {len(embeddings)} embeddings")
    except Exception as exc:
        print(f"   Error: {exc}")

    if os.getenv("OPENAI_API_KEY"):
        print("\n3. Testing OpenAI backend:")
        try:
            embeddings = embed_openai(test_texts[:2])
            print(f"   Generated {len(embeddings)} embeddings")
            print(f"   Dimension: {len(embeddings[0])}")
        except Exception as exc:
            print(f"   Error: {exc}")
    else:
        print("\n3. Skipping OpenAI test (no API key)")

    print("\n4. Testing bag-of-words fallback:")
    bow = SimpleBagOfWords(max_features=100)
    vectors = bow.fit_transform(test_texts)
    print(f"   Generated {len(vectors)} vectors")
    print(f"   Vocabulary size: {bow.max_features}")
    print(f"   Dimension: {len(vectors[0])}")
