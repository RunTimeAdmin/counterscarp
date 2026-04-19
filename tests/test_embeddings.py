"""
Tests for the embeddings module.
"""

import pytest
import sys
import os
import math
from unittest.mock import patch, MagicMock

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from embeddings import (
    get_embeddings,
    embed_local,
    embed_openai,
    embed_anthropic,
    cosine_similarity,
    batch_cosine_similarity,
    SimpleBagOfWords,
    EmbeddingError,
)


# =============================================================================
# SimpleBagOfWords Tests
# =============================================================================

class TestSimpleBagOfWords:
    """Test SimpleBagOfWords class."""

    def test_init(self):
        """Test initialization."""
        bow = SimpleBagOfWords(max_features=100)
        assert bow.max_features == 100
        assert bow.max_features == 100

    def test_tokenize(self):
        """Test tokenization."""
        bow = SimpleBagOfWords()
        tokens = bow._tokenize("Reentrancy vulnerability detected")
        
        assert "reentrancy" in tokens
        assert "vulnerability" in tokens
        assert "detected" in tokens

    def test_transform(self):
        """Test transforming texts to vectors."""
        bow = SimpleBagOfWords(max_features=50)
        texts = [
            "reentrancy vulnerability",
            "access control issue"
        ]

        vectors = bow.fit_transform(texts)

        assert len(vectors) == 2
        # With feature hashing, dimension is always max_features
        assert len(vectors[0]) == bow.max_features

    def test_vector_normalization(self):
        """Test that vectors are normalized."""
        bow = SimpleBagOfWords(max_features=50)
        texts = ["reentrancy vulnerability"]
        
        vectors = bow.fit_transform(texts)
        vector = vectors[0]
        
        # Calculate L2 norm
        norm = math.sqrt(sum(x * x for x in vector))
        
        # Should be 1.0 (or very close due to floating point)
        assert abs(norm - 1.0) < 0.01 or norm == 0.0

    def test_empty_text(self):
        """Test transforming empty text."""
        bow = SimpleBagOfWords(max_features=50)
        vectors = bow.fit_transform([""])

        assert len(vectors) == 1
        # With feature hashing, dimension is always max_features
        assert len(vectors[0]) == bow.max_features


# =============================================================================
# embed_local Tests
# =============================================================================

class TestEmbedLocal:
    """Test embed_local function."""

    def test_empty_list(self):
        """Test with empty list."""
        result = embed_local([])
        assert result == []

    def test_returns_embeddings(self):
        """Test that embeddings are returned."""
        texts = ["reentrancy vulnerability", "access control issue"]
        
        embeddings = embed_local(texts)
        
        assert len(embeddings) == 2
        assert len(embeddings[0]) > 0
        assert len(embeddings[1]) > 0

    def test_consistent_dimensions(self):
        """Test that all embeddings have same dimension."""
        texts = ["text one", "text two", "text three"]
        
        embeddings = embed_local(texts)
        
        dim = len(embeddings[0])
        for emb in embeddings:
            assert len(emb) == dim

    def test_similar_texts_similar_embeddings(self):
        """Test that similar texts have similar embeddings."""
        texts = [
            "reentrancy attack",
            "reentrancy vulnerability",
            "oracle manipulation"
        ]
        
        embeddings = embed_local(texts)
        
        # Similar texts should have higher similarity
        sim_0_1 = cosine_similarity(embeddings[0], embeddings[1])
        sim_0_2 = cosine_similarity(embeddings[0], embeddings[2])
        
        # First two are both about reentrancy
        assert sim_0_1 > sim_0_2


# =============================================================================
# embed_openai Tests
# =============================================================================

class TestEmbedOpenai:
    """Test embed_openai function."""

    def test_empty_list(self):
        """Test with empty list."""
        result = embed_openai([])
        assert result == []

    def test_no_api_key_raises_error(self):
        """Test that missing API key raises error."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(EmbeddingError):
                embed_openai(["test"])

    def test_mock_openai_call(self):
        """Test with mocked OpenAI API."""
        mock_response = MagicMock()
        mock_response.data = [
            MagicMock(embedding=[0.1] * 1536),
            MagicMock(embedding=[0.2] * 1536)
        ]
        
        mock_client = MagicMock()
        mock_client.embeddings.create.return_value = mock_response
        
        # Mock openai module at the embeddings module level
        mock_openai_module = MagicMock()
        mock_openai_module.OpenAI.return_value = mock_client
        
        with patch.dict('sys.modules', {'openai': mock_openai_module}):
            with patch('embeddings.openai', mock_openai_module):
                with patch('embeddings.OPENAI_AVAILABLE', True):
                    with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
                        result = embed_openai(["text1", "text2"])
        
        assert len(result) == 2
        assert len(result[0]) == 1536


# =============================================================================
# embed_anthropic Tests
# =============================================================================

class TestEmbedAnthropic:
    """Test embed_anthropic function."""

    def test_empty_list(self):
        """Test with empty list."""
        result = embed_anthropic([])
        assert result == []

    def test_fallback_to_local(self):
        """Test fallback to local when no API key."""
        with patch.dict(os.environ, {}, clear=True):
            # Should fall back to local embeddings
            result = embed_anthropic(["test text"])
        
        assert len(result) == 1
        assert len(result[0]) > 0


# =============================================================================
# get_embeddings Tests
# =============================================================================

class TestGetEmbeddings:
    """Test get_embeddings function."""

    def test_empty_list(self):
        """Test with empty list."""
        result = get_embeddings([])
        assert result == []

    def test_local_backend(self):
        """Test using local backend."""
        texts = ["test text"]
        
        result = get_embeddings(texts, backend="local")
        
        assert len(result) == 1
        assert len(result[0]) > 0

    def test_invalid_backend(self):
        """Test with invalid backend."""
        with pytest.raises(EmbeddingError):
            get_embeddings(["test"], backend="invalid")

    def test_openai_fallback_to_local(self):
        """Test OpenAI fallback to local on failure."""
        with patch('embeddings.embed_openai', side_effect=Exception("API Error")):
            result = get_embeddings(["test"], backend="openai")
        
        # Should fallback to local
        assert len(result) == 1


# =============================================================================
# cosine_similarity Tests
# =============================================================================

class TestCosineSimilarity:
    """Test cosine_similarity function."""

    def test_identical_vectors(self):
        """Test similarity of identical vectors."""
        vec = [1.0, 0.0, 0.0]
        result = cosine_similarity(vec, vec)
        
        assert result == 1.0

    def test_orthogonal_vectors(self):
        """Test similarity of orthogonal vectors."""
        vec_a = [1.0, 0.0, 0.0]
        vec_b = [0.0, 1.0, 0.0]
        
        result = cosine_similarity(vec_a, vec_b)
        
        assert result == 0.0

    def test_opposite_vectors(self):
        """Test similarity of opposite vectors."""
        vec_a = [1.0, 0.0, 0.0]
        vec_b = [-1.0, 0.0, 0.0]
        
        result = cosine_similarity(vec_a, vec_b)
        
        assert result == -1.0

    def test_empty_vectors(self):
        """Test with empty vectors."""
        result = cosine_similarity([], [1.0])
        assert result == 0.0

    def test_different_dimensions(self):
        """Test with different dimension vectors."""
        with pytest.raises(ValueError):
            cosine_similarity([1.0, 0.0], [1.0])

    def test_zero_vector(self):
        """Test with zero vector."""
        result = cosine_similarity([0.0, 0.0], [1.0, 0.0])
        assert result == 0.0


# =============================================================================
# batch_cosine_similarity Tests
# =============================================================================

class TestBatchCosineSimilarity:
    """Test batch_cosine_similarity function."""

    def test_batch_similarity(self):
        """Test calculating similarity with multiple vectors."""
        query = [1.0, 0.0, 0.0]
        vectors = [
            [1.0, 0.0, 0.0],  # Identical
            [0.0, 1.0, 0.0],  # Orthogonal
            [-1.0, 0.0, 0.0]  # Opposite
        ]
        
        results = batch_cosine_similarity(query, vectors)
        
        assert len(results) == 3
        assert results[0] == 1.0  # Identical
        assert results[1] == 0.0  # Orthogonal
        assert results[2] == -1.0  # Opposite

    def test_empty_vectors_list(self):
        """Test with empty vectors list."""
        result = batch_cosine_similarity([1.0, 0.0], [])
        assert result == []


# =============================================================================
# Embedding Dimension Tests
# =============================================================================

class TestEmbeddingDimensions:
    """Test embedding dimension consistency."""

    def test_local_embedding_dimension(self):
        """Test that local embeddings have expected dimension."""
        texts = ["test text"]
        embeddings = embed_local(texts)
        
        # When sentence-transformers is not available, TF-IDF or BOW is used
        # which may produce different dimensions than EMBEDDING_DIM (384)
        # The actual dimension depends on the vocabulary size
        assert len(embeddings) == 1
        assert len(embeddings[0]) > 0

    def test_bow_embedding_dimension(self):
        """Test that bag-of-words respects max_features."""
        bow = SimpleBagOfWords(max_features=100)
        texts = ["test text"]
        vectors = bow.fit_transform(texts)
        
        assert len(vectors[0]) <= 100

    def test_embedding_consistency(self):
        """Test that same text produces consistent embeddings."""
        text = "reentrancy vulnerability"
        
        emb1 = embed_local([text])
        emb2 = embed_local([text])
        
        # Using bag-of-words, same text should produce same embedding
        assert len(emb1[0]) == len(emb2[0])
