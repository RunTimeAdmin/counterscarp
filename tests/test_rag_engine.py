"""
Tests for the rag_engine module.
"""

import pytest
import sys
import os
import json
from unittest.mock import patch

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from rag_engine import (
    VectorStore,
    KnowledgeBaseBuilder,
    AuditCopilot,
    IndexEntry,
    RAGError,
    DEFAULT_INDEX_PATH,
    DEFAULT_TOP_K,
)


# =============================================================================
# VectorStore Tests
# =============================================================================

class TestVectorStore:
    """Test VectorStore class."""

    def test_init_default_dimension(self):
        """Test VectorStore initializes with default dimension."""
        store = VectorStore()
        assert store.embedding_dim == 384
        assert store.entries == []
        assert store._embeddings_cache is None

    def test_init_custom_dimension(self):
        """Test VectorStore initializes with custom dimension."""
        store = VectorStore(embedding_dim=768)
        assert store.embedding_dim == 768

    def test_add_single_entry(self):
        """Test adding a single entry to the store."""
        store = VectorStore()
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Test text", {"source": "test", "severity": "HIGH"})
        
        assert len(store.entries) == 1
        assert store.entries[0].text == "Test text"
        assert store.entries[0].metadata["source"] == "test"
        assert len(store.entries[0].embedding) == 384

    def test_add_batch_entries(self):
        """Test adding multiple entries in batch."""
        store = VectorStore()
        
        items = [
            {"text": "Text 1", "metadata": {"source": "test1"}},
            {"text": "Text 2", "metadata": {"source": "test2"}},
            {"text": "Text 3", "metadata": {"source": "test3"}},
        ]
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384, [0.2] * 384, [0.3] * 384]
            store.add_batch(items)
        
        assert len(store.entries) == 3
        assert store.entries[0].text == "Text 1"
        assert store.entries[1].text == "Text 2"
        assert store.entries[2].text == "Text 3"

    def test_add_batch_empty_list(self):
        """Test adding empty batch does nothing."""
        store = VectorStore()
        store.add_batch([])
        assert len(store.entries) == 0

    def test_query_returns_ranked_results(self):
        """Test query returns results ranked by similarity."""
        store = VectorStore()
        
        # Add entries with different embeddings
        with patch('rag_engine.embed_local') as mock_embed:
            # First call for adding entries
            mock_embed.return_value = [[1.0, 0.0] + [0.0] * 382]
            store.add("Reentrancy vulnerability", {"source": "db1"})
            
            mock_embed.return_value = [[0.0, 1.0] + [0.0] * 382]
            store.add("Access control issue", {"source": "db2"})
            
            mock_embed.return_value = [[0.9, 0.1] + [0.0] * 382]
            store.add("Reentrant attack pattern", {"source": "db3"})
        
        # Query for reentrancy
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[1.0, 0.0] + [0.0] * 382]
            results = store.query("reentrancy", top_k=2)
        
        assert len(results) == 2
        # Most similar should be first
        assert results[0]["similarity"] >= results[1]["similarity"]

    def test_query_empty_store(self):
        """Test query on empty store returns empty list."""
        store = VectorStore()
        results = store.query("test")
        assert results == []

    def test_save_to_json(self, tmp_path):
        """Test saving index to JSON file."""
        store = VectorStore()
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Test entry", {"source": "test"})
        
        json_path = str(tmp_path / "test_index.json")
        store.save(json_path)
        
        assert os.path.exists(json_path)
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        assert data["version"] == "2.0"
        assert data["embedding_dim"] == 384
        assert len(data["entries"]) == 1
        assert data["entries"][0]["text"] == "Test entry"
        assert "saved_at" in data

    def test_load_from_json(self, tmp_path):
        """Test loading index from JSON file."""
        store = VectorStore()
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Test entry", {"source": "test"})
        
        json_path = str(tmp_path / "test_index.json")
        store.save(json_path)
        
        # Create new store and load
        new_store = VectorStore()
        new_store.load(json_path)
        
        assert len(new_store.entries) == 1
        assert new_store.entries[0].text == "Test entry"
        assert new_store.entries[0].metadata["source"] == "test"
        assert new_store.embedding_dim == 384

    def test_load_missing_file_creates_empty(self, tmp_path):
        """Test loading from missing file creates empty store."""
        store = VectorStore()
        json_path = str(tmp_path / "nonexistent.json")
        
        store.load(json_path)
        
        assert store.entries == []

    def test_pkl_file_logs_warning(self, tmp_path):
        """Test that a .pkl file alongside the index path logs a warning."""
        pkl_path = str(tmp_path / "legacy_index.pkl")
        json_path = str(tmp_path / "legacy_index.json")

        # Create a dummy .pkl file (content doesn't matter)
        with open(pkl_path, 'wb') as f:
            f.write(b"")

        store = VectorStore()

        # Load from JSON path (which doesn't exist) — should log a warning
        # and then raise FileNotFoundError (caught internally → empty store)
        with patch('rag_engine.logger') as mock_logger:
            store.load(json_path)
            # Warning should mention the .pkl path
            assert mock_logger.warning.called, "Expected a warning about legacy .pkl file"
            call_args = mock_logger.warning.call_args
            # The pkl_path should appear in one of the positional args (format string args)
            assert any(
                pkl_path in str(arg) for arg in call_args[0]
            ), f"Expected warning to reference {pkl_path}"

        assert store.entries == []

    def test_get_stats(self):
        """Test getting store statistics."""
        store = VectorStore()
        
        with patch('embeddings.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Entry 1", {"source": "db1", "severity": "HIGH"})
            store.add("Entry 2", {"source": "db1", "severity": "MEDIUM"})
            store.add("Entry 3", {"source": "db2", "severity": "HIGH"})
        
        stats = store.get_stats()
        
        assert stats["total_entries"] == 3
        assert stats["embedding_dim"] == 384
        assert stats["sources"]["db1"] == 2
        assert stats["sources"]["db2"] == 1
        assert stats["severities"]["HIGH"] == 2
        assert stats["severities"]["MEDIUM"] == 1

    def test_clear(self):
        """Test clearing all entries."""
        store = VectorStore()
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Test entry")
        
        assert len(store.entries) == 1
        
        store.clear()
        
        assert store.entries == []
        assert store._embeddings_cache is None


# =============================================================================
# KnowledgeBaseBuilder Tests
# =============================================================================

class TestKnowledgeBaseBuilder:
    """Test KnowledgeBaseBuilder class."""

    def test_init_creates_vector_store(self):
        """Test builder initializes with VectorStore."""
        builder = KnowledgeBaseBuilder()
        assert isinstance(builder.vector_store, VectorStore)

    def test_init_with_custom_store(self):
        """Test builder initializes with custom VectorStore."""
        custom_store = VectorStore(embedding_dim=768)
        builder = KnowledgeBaseBuilder(custom_store)
        assert builder.vector_store is custom_store
        assert builder.vector_store.embedding_dim == 768

    def test_build_from_remediation_db(self):
        """Test building from remediation database."""
        builder = KnowledgeBaseBuilder()
        
        remediation_db = {
            "REENTRANCY": "Use checks-effects-interactions pattern",
            "TX_ORIGIN": "Use msg.sender instead of tx.origin",
        }
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384, [0.2] * 384]
            count = builder.build_from_remediation_db(remediation_db)
        
        assert count == 2
        assert len(builder.vector_store.entries) == 2
        
        # Check metadata
        entry = builder.vector_store.entries[0]
        assert entry.metadata["source"] == "remediation_db"
        assert "rule_id" in entry.metadata
        assert "remediation" in entry.metadata

    def test_build_from_findings(self):
        """Test building from historical findings."""
        builder = KnowledgeBaseBuilder()
        
        findings = [
            {
                "rule_id": "REENTRANCY",
                "severity": "CRITICAL",
                "title": "Reentrancy Bug",
                "description": "External call before state update",
                "file": "Vault.sol",
                "line_no": 45,
                "remediation": "Use checks-effects-interactions",
                "url": "https://example.com"
            },
            {
                "rule_id": "TX_ORIGIN",
                "severity": "HIGH",
                "title": "Tx Origin Usage",
                "description": "Uses tx.origin for auth",
                "file": "Auth.sol",
                "line_no": 20,
            }
        ]
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384, [0.2] * 384]
            count = builder.build_from_findings(findings)
        
        assert count == 2
        assert len(builder.vector_store.entries) == 2
        
        # Check metadata
        entry = builder.vector_store.entries[0]
        assert entry.metadata["source"] == "historical_finding"
        assert entry.metadata["severity"] == "CRITICAL"

    def test_build_from_findings_skips_empty_text(self):
        """Test that findings with empty text are skipped."""
        builder = KnowledgeBaseBuilder()
        
        findings = [
            {
                "rule_id": "",
                "severity": "HIGH",
                # No title, description, or message
            }
        ]
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = []
            count = builder.build_from_findings(findings)
        
        assert count == 0

    def test_build_from_threat_intel_code4rena(self):
        """Test building from Code4rena threat intel."""
        builder = KnowledgeBaseBuilder()
        
        intel_results = [
            {
                "title": "Reentrancy in Vault",
                "body": "External call before state update",
                "html_url": "https://code4rena.com/report/123"
            }
        ]
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            count = builder.build_from_threat_intel(intel_results)
        
        assert count == 1
        entry = builder.vector_store.entries[0]
        assert entry.metadata["source"] == "threat_intel_c4"
        assert entry.metadata["severity"] == "HIGH"

    def test_build_from_threat_intel_immunefi(self):
        """Test building from Immunefi threat intel."""
        builder = KnowledgeBaseBuilder()
        
        intel_results = [
            {
                "source": "Immunefi",
                "title": "Flash Loan Attack",
                "url": "https://immunefi.com/report/456"
            }
        ]
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            count = builder.build_from_threat_intel(intel_results)
        
        assert count == 1
        entry = builder.vector_store.entries[0]
        assert entry.metadata["source"] == "threat_intel_immunefi"
        assert entry.metadata["severity"] == "CRITICAL"

    def test_build_from_audit_reports(self, tmp_path):
        """Test building from audit report files."""
        builder = KnowledgeBaseBuilder()
        
        # Create test report files
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()
        
        report_content = """
# Security Audit Report

## Finding 1: Reentrancy Vulnerability

Severity: High

External call before state update in withdraw function.

## Finding 2: Access Control Issue

Severity: Medium

Missing access control on critical function.
"""
        
        (reports_dir / "audit_report.md").write_text(report_content)
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384, [0.2] * 384]
            count = builder.build_from_audit_reports(str(reports_dir))
        
        assert count >= 1

    def test_build_from_audit_reports_missing_dir(self):
        """Test building from non-existent directory."""
        builder = KnowledgeBaseBuilder()
        
        count = builder.build_from_audit_reports("/nonexistent/path")
        assert count == 0


# =============================================================================
# AuditCopilot Tests
# =============================================================================

class TestAuditCopilot:
    """Test AuditCopilot class."""

    def test_init_default_config(self):
        """Test initialization with default config."""
        copilot = AuditCopilot()
        assert copilot.embedding_backend == "local"
        assert copilot.index_path == DEFAULT_INDEX_PATH
        assert copilot.top_k == DEFAULT_TOP_K
        assert copilot.auto_enrich is False

    def test_init_custom_config(self):
        """Test initialization with custom config."""
        config = {
            "embedding_backend": "openai",
            "rag_index_path": ".scarpshield/custom_index.json",
            "top_k": 10,
            "auto_enrich": True
        }
        copilot = AuditCopilot(config)
        assert copilot.embedding_backend == "openai"
        assert copilot.index_path == ".scarpshield/custom_index.json"
        assert copilot.top_k == 10
        assert copilot.auto_enrich is True

    def test_load_index_falls_back_to_legacy_path(self, tmp_path):
        """Test legacy .counterscarp index is used when preferred is absent."""
        legacy_dir = tmp_path / ".counterscarp"
        legacy_dir.mkdir(parents=True, exist_ok=True)
        legacy_index = legacy_dir / "rag_index.json"
        legacy_index.write_text(
            json.dumps(
                {
                    "entries": [],
                    "embedding_dim": 384,
                    "saved_at": "2026-01-01T00:00:00",
                    "version": "2.0",
                }
            ),
            encoding="utf-8",
        )
        preferred_index = tmp_path / ".scarpshield" / "rag_index.json"

        copilot = AuditCopilot(config={"rag_index_path": str(preferred_index)})
        resolved = copilot._resolve_legacy_index_path(str(preferred_index))

        assert resolved == str(legacy_index)

    def test_enrich_finding_no_index(self):
        """Test enriching finding when no index is loaded."""
        copilot = AuditCopilot()
        copilot.vector_store.entries = []  # Ensure empty
        
        finding = {
            "rule_id": "REENTRANCY",
            "severity": "HIGH",
            "title": "Reentrancy Bug",
            "description": "External call before state update"
        }
        
        enriched = copilot.enrich_finding(finding)
        
        assert enriched["rag_similar_findings"] == []
        assert enriched["rag_remediation"] == ""
        assert enriched["rag_references"] == []

    def test_enrich_finding_with_results(self):
        """Test enriching finding with similar results."""
        copilot = AuditCopilot()
        
        # Add entries to vector store
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            copilot.vector_store.add(
                "Reentrancy vulnerability fix",
                {"source": "historical_finding",
                 "remediation": "Use checks-effects-interactions",
                 "url": "https://example.com"}
            )
        
        finding = {
            "rule_id": "REENTRANCY",
            "severity": "HIGH",
            "title": "Reentrancy Bug",
            "description": "External call before state update"
        }
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            enriched = copilot.enrich_finding(finding)
        
        assert "rag_similar_findings" in enriched
        assert "rag_remediation" in enriched
        assert "rag_references" in enriched

    def test_enrich_finding_empty_query(self):
        """Test enriching finding with empty query text."""
        copilot = AuditCopilot()
        
        finding = {
            "rule_id": "",
            "severity": "HIGH",
            # No title, description, or message
        }
        
        enriched = copilot.enrich_finding(finding)
        
        assert enriched["rag_similar_findings"] == []
        assert enriched["rag_remediation"] == ""
        assert enriched["rag_references"] == []

    def test_enrich_findings_batch(self):
        """Test batch enriching findings."""
        copilot = AuditCopilot()
        
        findings = [
            {"rule_id": "REENTRANCY", "severity": "HIGH", "title": "Bug 1"},
            {"rule_id": "TX_ORIGIN", "severity": "MEDIUM", "title": "Bug 2"},
        ]
        
        enriched = copilot.enrich_findings_batch(findings)
        
        assert len(enriched) == 2
        assert "rag_similar_findings" in enriched[0]
        assert "rag_similar_findings" in enriched[1]

    def test_rebuild_index(self):
        """Test rebuilding the RAG index."""
        copilot = AuditCopilot()
        
        sources = {
            "remediation_db": {
                "REENTRANCY": "Fix reentrancy",
                "TX_ORIGIN": "Fix tx.origin"
            },
            "findings": [
                {"rule_id": "TEST", "severity": "HIGH", "title": "Test"}
            ],
            "threat_intel": []
        }
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            counts = copilot.rebuild_index(sources)
        
        assert "remediation_db" in counts
        assert "findings" in counts
        assert counts["remediation_db"] == 2
        assert counts["findings"] == 1

    def test_get_stats(self):
        """Test getting RAG system statistics."""
        # Use a temporary index path to avoid loading existing data
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            index_path = os.path.join(tmpdir, "test_rag_index.json")
            copilot = AuditCopilot(config={"rag_index_path": index_path})
            
            with patch('embeddings.embed_local') as mock_embed:
                mock_embed.return_value = [[0.1] * 384]
                copilot.vector_store.add("Test", {"source": "test"})
            
            stats = copilot.get_stats()
            
            assert stats["index_path"] == index_path
            assert stats["embedding_backend"] == "local"
            assert stats["top_k"] == DEFAULT_TOP_K
            assert stats["total_entries"] == 1


# =============================================================================
# IndexEntry Tests
# =============================================================================

class TestIndexEntry:
    """Test IndexEntry dataclass."""

    def test_creation(self):
        """Test creating an IndexEntry."""
        entry = IndexEntry(
            text="Test text",
            embedding=[0.1, 0.2, 0.3],
            metadata={"source": "test"}
        )
        
        assert entry.text == "Test text"
        assert entry.embedding == [0.1, 0.2, 0.3]
        assert entry.metadata == {"source": "test"}

    def test_default_metadata(self):
        """Test IndexEntry with default metadata."""
        entry = IndexEntry(
            text="Test",
            embedding=[0.1]
        )
        
        assert entry.metadata == {}


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Test error handling in RAG engine."""

    def test_rag_error_creation(self):
        """Test RAGError exception creation."""
        error = RAGError("Test error")
        assert str(error) == "Test error"

    def test_rag_error_with_cause(self):
        """Test RAGError with cause."""
        cause = ValueError("Original error")
        error = RAGError("Test error")
        
        try:
            raise error from cause
        except RAGError as e:
            assert str(e) == "Test error"

    def test_vector_store_add_embedding_failure(self):
        """Test handling of embedding generation failure."""
        store = VectorStore()
        
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = []
            
            with pytest.raises(RAGError):
                store.add("Test text")

    def test_vector_store_query_embedding_failure(self):
        """Test handling of query embedding failure."""
        store = VectorStore()
        
        # Add an entry first
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = [[0.1] * 384]
            store.add("Test")
        
        # Then fail the query
        with patch('rag_engine.embed_local') as mock_embed:
            mock_embed.return_value = []
            
            with pytest.raises(RAGError):
                store.query("test")
