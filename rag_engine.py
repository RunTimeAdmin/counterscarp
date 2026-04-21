#!/usr/bin/env python3
"""RAG pipeline for Garrison Engine.

Provides vector storage, knowledge base building, and audit copilot
for enriching security findings with historical context.

Example:
    >>> from rag_engine import AuditCopilot, VectorStore
    >>> copilot = AuditCopilot()
    >>> enriched = copilot.enrich_finding(finding)
"""

from __future__ import annotations

import json
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

# Network error types for graceful offline handling
try:
    import requests.exceptions as _req_exc
    _NETWORK_ERRORS = (
        _req_exc.ConnectionError,
        _req_exc.Timeout,
        _req_exc.RequestException,
        ConnectionError,
        TimeoutError,
        OSError,
    )
except ImportError:
    _NETWORK_ERRORS = (ConnectionError, TimeoutError, OSError)

_OFFLINE_RESULT: Dict[str, Any] = {
    "rag_status": "offline",
    "rag_message": (
        "AI enrichment unavailable — scan continues without LLM analysis"
    ),
    "rag_similar_findings": [],
    "rag_remediation": "",
    "rag_references": [],
}

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import GarrisonError, GarrisonConfigError
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None
    GarrisonError = Exception
    GarrisonConfigError = Exception

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Try importing embeddings module
try:
    from embeddings import (
        get_embeddings,
        cosine_similarity,
        embed_local,
        NUMPY_AVAILABLE
    )
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    get_embeddings = None
    cosine_similarity = None
    embed_local = None
    NUMPY_AVAILABLE = False

# Try importing numpy
if NUMPY_AVAILABLE:
    import numpy as np
else:
    np = None

# Default configuration
DEFAULT_INDEX_PATH = ".garrison/rag_index.json"
DEFAULT_TOP_K = 5


class RAGError(GarrisonError):
    """Raised when RAG operations fail."""
    pass


@dataclass
class IndexEntry:
    """Single entry in the RAG vector index.
    
    Attributes:
        text: Searchable text content.
        embedding: Vector embedding of the text.
        metadata: Associated metadata (source, severity, etc.).
    """
    text: str
    embedding: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)


class VectorStore:
    """Simple vector store for RAG with similarity search.
    
    Stores text entries with their embeddings and supports similarity-based
    retrieval. Uses pickle for serialization.
    
    Attributes:
        entries: List of indexed entries.
        embedding_dim: Dimension of embedding vectors.
    """
    
    def __init__(self, embedding_dim: int = 384):
        """Initialize the vector store.
        
        Args:
            embedding_dim: Expected dimension of embedding vectors.
        """
        self.entries: List[IndexEntry] = []
        self.embedding_dim = embedding_dim
        self._embeddings_cache: Optional[List[List[float]]] = None
        logger.debug(
            f"VectorStore initialized with dim={embedding_dim}"
        )
    
    def add(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a single entry to the store.
        
        Args:
            text: Text content to store.
            metadata: Optional metadata dictionary.
            
        Raises:
            RAGError: If embedding generation fails.
        """
        if not EMBEDDINGS_AVAILABLE:
            raise RAGError("Embeddings module not available")
        
        try:
            embeddings = embed_local([text])
            if not embeddings:
                raise RAGError("Failed to generate embedding")
            
            entry = IndexEntry(
                text=text,
                embedding=embeddings[0],
                metadata=metadata or {}
            )
            self.entries.append(entry)
            self._embeddings_cache = None  # Invalidate cache
            
            logger.debug(f"Added entry to VectorStore: {text[:50]}...")
            
        except Exception as e:
            raise RAGError(f"Failed to add entry: {e}") from e
    
    def add_batch(self, items: List[Dict[str, Any]]) -> None:
        """Add multiple entries in batch.
        
        Args:
            items: List of dicts with 'text' and 'metadata' keys.
            
        Raises:
            RAGError: If embedding generation fails.
        """
        if not items:
            return
        
        if not EMBEDDINGS_AVAILABLE:
            raise RAGError("Embeddings module not available")
        
        try:
            texts = [item.get("text", "") for item in items]
            embeddings = embed_local(texts)
            
            for item, emb in zip(items, embeddings):
                entry = IndexEntry(
                    text=item.get("text", ""),
                    embedding=emb,
                    metadata=item.get("metadata", {})
                )
                self.entries.append(entry)
            
            self._embeddings_cache = None  # Invalidate cache
            logger.debug(f"Added {len(items)} entries to VectorStore")
            
        except Exception as e:
            raise RAGError(f"Failed to add batch: {e}") from e
    
    def query(
        self,
        query_text: str,
        top_k: int = DEFAULT_TOP_K
    ) -> List[Dict[str, Any]]:
        """Query the store for most similar entries.
        
        Args:
            query_text: Query text to search for.
            top_k: Number of top results to return.
            
        Returns:
            List of result dicts with 'text', 'metadata', 'similarity'.
            
        Raises:
            RAGError: If embedding generation fails.
        """
        if not self.entries:
            return []
        
        if not EMBEDDINGS_AVAILABLE:
            raise RAGError("Embeddings module not available")
        
        try:
            # Generate query embedding
            query_embeddings = embed_local([query_text])
            if not query_embeddings:
                raise RAGError("Failed to generate query embedding")
            query_vec = query_embeddings[0]
            
            # Calculate similarities
            results = []
            for entry in self.entries:
                sim = cosine_similarity(query_vec, entry.embedding)
                results.append({
                    "text": entry.text,
                    "metadata": entry.metadata,
                    "similarity": sim
                })
            
            # Sort by similarity (descending)
            results.sort(key=lambda x: x["similarity"], reverse=True)
            
            return results[:top_k]
            
        except Exception as e:
            raise RAGError(f"Query failed: {e}") from e
    
    def save(self, path: str) -> None:
        """Serialize the index to a JSON file.

        Args:
            path: Path to save the index.

        Raises:
            RAGError: If serialization fails.
        """
        try:
            data = {
                "entries": [
                    {
                        "text": entry.text,
                        # List[float] is JSON-native
                        "embedding": entry.embedding,
                        "metadata": entry.metadata,
                    }
                    for entry in self.entries
                ],
                "embedding_dim": self.embedding_dim,
                "saved_at": datetime.now().isoformat(),
                "version": "2.0",
            }
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            logger.info(
                f"VectorStore saved to {path} ({len(self.entries)} entries)"
            )

        except Exception as e:
            raise RAGError(f"Failed to save index: {e}") from e
    
    def load(self, path: str) -> None:
        """Deserialize the index from a JSON file.

        Args:
            path: Path to load the index from.

        Raises:
            RAGError: If deserialization fails.
        """
        try:
            # Backward-compatible migration from pickle
            pkl_path = path.replace('.json', '.pkl')
            if not Path(path).exists() and Path(pkl_path).exists():
                logger.warning(
                    "Found legacy pickle index at %s — "
                    "migrating to JSON format. "
                    "The .pkl file will be preserved but is no longer used.",
                    pkl_path,
                )
                self._migrate_from_pickle(pkl_path, path)

            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.entries = [
                IndexEntry(
                    text=e["text"],
                    embedding=e["embedding"],
                    metadata=e.get("metadata", {}),
                )
                for e in data["entries"]
            ]
            self.embedding_dim = data.get("embedding_dim", self.embedding_dim)
            self._embeddings_cache = None

            saved_at = data.get("saved_at", "unknown")
            logger.info(
                f"VectorStore loaded from {path} "
                f"({len(self.entries)} entries, saved: {saved_at})"
            )

        except FileNotFoundError:
            logger.info(f"No existing index found at {path}")
            self.entries = []
        except Exception as e:
            raise RAGError(f"Failed to load index: {e}") from e

    def _migrate_from_pickle(self, pkl_path: str, json_path: str) -> None:
        """One-time migration from legacy pickle format to JSON."""
        import pickle  # Only imported for migration
        with open(pkl_path, 'rb') as f:
            data = pickle.load(f)
        # Convert dict entries to IndexEntry objects
        raw_entries = data.get("entries", [])
        self.entries = []
        for entry in raw_entries:
            if isinstance(entry, dict):
                self.entries.append(IndexEntry(
                    text=entry.get("text", ""),
                    embedding=entry.get("embedding", []),
                    metadata=entry.get("metadata", {})
                ))
            else:
                # Already an IndexEntry
                self.entries.append(entry)
        self.embedding_dim = data.get("embedding_dim", self.embedding_dim)
        self.save(json_path)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the store.
        
        Returns:
            Dict with index statistics.
        """
        sources = {}
        severities = {}
        
        for entry in self.entries:
            source = entry.metadata.get("source", "unknown")
            severity = entry.metadata.get("severity", "unknown")
            sources[source] = sources.get(source, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1
        
        return {
            "total_entries": len(self.entries),
            "embedding_dim": self.embedding_dim,
            "sources": sources,
            "severities": severities
        }
    
    def clear(self) -> None:
        """Clear all entries from the store."""
        self.entries = []
        self._embeddings_cache = None
        logger.debug("VectorStore cleared")


class KnowledgeBaseBuilder:
    """Builds RAG knowledge base from various sources.
    
    Indexes remediation guidance, historical findings, threat intel,
    and audit reports for retrieval during analysis.
    """
    
    def __init__(self, vector_store: Optional[VectorStore] = None):
        """Initialize the knowledge base builder.
        
        Args:
            vector_store: Optional VectorStore instance to use.
        """
        self.vector_store = vector_store or VectorStore()
        logger.debug("KnowledgeBaseBuilder initialized")
    
    def build_from_remediation_db(
        self,
        remediation_db: Dict[str, str]
    ) -> int:
        """Index the remediation database.
        
        Args:
            remediation_db: Dict mapping rule_id to remediation text.
            
        Returns:
            Number of entries indexed.
        """
        items = []
        for rule_id, remediation in remediation_db.items():
            text = f"{rule_id}: {remediation}"
            items.append({
                "text": text,
                "metadata": {
                    "source": "remediation_db",
                    "rule_id": rule_id,
                    "remediation": remediation,
                    "severity": "unknown"
                }
            })
        
        self.vector_store.add_batch(items)
        logger.info(f"Indexed {len(items)} remediation entries")
        return len(items)
    
    def build_from_findings(self, findings: List[Dict[str, Any]]) -> int:
        """Index historical findings with context.
        
        Args:
            findings: List of finding dictionaries.
            
        Returns:
            Number of entries indexed.
        """
        items = []
        for finding in findings:
            # Create searchable text from finding
            text_parts = [
                finding.get("rule_id", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("message", ""),
            ]
            text = " ".join(filter(None, text_parts))
            
            if not text.strip():
                continue
            
            items.append({
                "text": text,
                "metadata": {
                    "source": "historical_finding",
                    "rule_id": finding.get("rule_id", "unknown"),
                    "severity": finding.get("severity", "unknown"),
                    "file": finding.get("file", ""),
                    "line_no": finding.get("line_no", 0),
                    "remediation": finding.get("remediation", ""),
                    "url": finding.get("url", "")
                }
            })
        
        self.vector_store.add_batch(items)
        logger.info(f"Indexed {len(items)} historical findings")
        return len(items)
    
    def build_from_threat_intel(
        self,
        intel_results: List[Dict[str, Any]]
    ) -> int:
        """Index threat intelligence data.
        
        Args:
            intel_results: List of threat intel result dicts.
            
        Returns:
            Number of entries indexed.
        """
        items = []
        for intel in intel_results:
            # Handle different intel formats
            if isinstance(intel, dict):
                # Code4rena format
                if "title" in intel and "html_url" in intel:
                    text = f"{intel.get('title', '')} {intel.get('body', '')}"
                    items.append({
                        "text": text,
                        "metadata": {
                            "source": "threat_intel_c4",
                            "title": intel.get("title", ""),
                            "url": intel.get("html_url", ""),
                            "severity": "HIGH"
                        }
                    })
                # Immunefi format
                elif intel.get("source") == "Immunefi":
                    text = intel.get("title", "")
                    items.append({
                        "text": text,
                        "metadata": {
                            "source": "threat_intel_immunefi",
                            "title": text,
                            "url": intel.get("url", ""),
                            "severity": "CRITICAL"
                        }
                    })
        
        self.vector_store.add_batch(items)
        logger.info(f"Indexed {len(items)} threat intel entries")
        return len(items)
    
    def build_from_audit_reports(self, reports_dir: str) -> int:
        """Scan and index audit reports from a directory.
        
        Args:
            reports_dir: Directory containing markdown/text reports.
            
        Returns:
            Number of entries indexed.
        """
        items = []
        reports_path = Path(reports_dir)
        
        if not reports_path.exists():
            logger.warning(f"Reports directory not found: {reports_dir}")
            return 0
        
        # Find all markdown and text files
        report_files = list(reports_path.rglob("*.md"))
        report_files.extend(reports_path.rglob("*.txt"))
        
        for report_file in report_files:
            try:
                content = report_file.read_text(encoding='utf-8')
                
                # Extract findings sections (simple heuristic)
                # Look for patterns like "## Finding" or "### Vulnerability"
                sections = self._extract_findings_sections(content)
                
                for section in sections:
                    items.append({
                        "text": section["text"],
                        "metadata": {
                            "source": "audit_report",
                            "report_file": str(report_file),
                            "title": section.get("title", ""),
                            "severity": section.get("severity", "unknown"),
                            "url": str(report_file)
                        }
                    })
                
                # If no sections found, index the whole report
                if not sections:
                    items.append({
                        "text": content[:2000],  # First 2000 chars
                        "metadata": {
                            "source": "audit_report",
                            "report_file": str(report_file),
                            "title": report_file.stem,
                            "severity": "unknown",
                            "url": str(report_file)
                        }
                    })
                    
            except Exception as e:
                logger.warning(f"Failed to read report {report_file}: {e}")
        
        self.vector_store.add_batch(items)
        logger.info(
            f"Indexed {len(items)} entries from {len(report_files)} reports"
        )
        return len(items)
    
    def _extract_findings_sections(
        self,
        content: str
    ) -> List[Dict[str, Any]]:
        """Extract finding sections from report content.
        
        Args:
            content: Report content.
            
        Returns:
            List of section dicts with 'text', 'title', 'severity'.
        """
        sections = []
        
        # Simple regex patterns for finding sections
        patterns = [
            r'#{2,4}\s*(?:Finding|Vulnerability|Issue)'
            r'\s*[#\s]*([^\n]+)',
            r'#{2,4}\s*(?:High|Medium|Low|Critical|Informational)'
            r'\s*[#\s]*([^\n]+)',
        ]
        
        import re
        for pattern in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for i, match in enumerate(matches):
                start = match.start()
                if i + 1 < len(matches):
                    end = matches[i + 1].start()
                else:
                    end = len(content)
                section_text = content[start:end].strip()
                
                title = match.group(1).strip() if match.groups() else "Finding"
                
                # Try to extract severity
                severity = "unknown"
                severity_match = re.search(
                    r'(?:severity|risk)\s*[:\-]?\s*(critical|high|medium|low)',
                    section_text,
                    re.IGNORECASE
                )
                if severity_match:
                    severity = severity_match.group(1).upper()
                
                sections.append({
                    "text": section_text[:1500],  # Limit length
                    "title": title,
                    "severity": severity
                })
        
        return sections


class AuditCopilot:
    """Main interface for AI-powered audit assistance.
    
    Provides RAG-based enrichment of findings with similar past findings,
    aggregated remediation guidance, and reference links.
    
    Attributes:
        config: Configuration dictionary.
        vector_store: VectorStore instance for retrieval.
        knowledge_builder: KnowledgeBaseBuilder for indexing.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the audit copilot.
        
        Args:
            config: Optional configuration dictionary with keys:
                - embedding_backend: "local", "openai", or "anthropic"
                - rag_index_path: Path to the RAG index file
                - top_k: Number of similar findings to retrieve
                - auto_enrich: Whether to auto-enrich findings
        """
        self.config = config or {}
        self.embedding_backend = self.config.get("embedding_backend", "local")
        self.index_path = self.config.get("rag_index_path", DEFAULT_INDEX_PATH)
        self.top_k = self.config.get("top_k", DEFAULT_TOP_K)
        self.auto_enrich = self.config.get("auto_enrich", False)
        
        self.vector_store = VectorStore()
        self.knowledge_builder = KnowledgeBaseBuilder(self.vector_store)
        
        # Try to load existing index
        self._load_index()
        
        logger.info(
            f"AuditCopilot initialized (backend={self.embedding_backend}, "
            f"top_k={self.top_k})"
        )
    
    def _load_index(self) -> None:
        """Load existing RAG index if available."""
        try:
            self.vector_store.load(self.index_path)
        except Exception as e:
            logger.warning(f"Could not load RAG index: {e}")
    
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single finding with RAG context.
        
        Args:
            finding: Finding dictionary to enrich.
            
        Returns:
            Enriched finding with added RAG fields:
                - rag_similar_findings: Top-K similar past findings
                - rag_remediation: Aggregated remediation guidance
                - rag_references: Related audit reports/disclosures
            On network/API failure returns a dict with rag_status="offline"
            so callers can short-circuit without raising.
        """
        if not self.vector_store.entries:
            logger.debug("No RAG index loaded, skipping enrichment")
            finding["rag_similar_findings"] = []
            finding["rag_remediation"] = ""
            finding["rag_references"] = []
            return finding
        
        # Create query text from finding
        query_parts = [
            finding.get("rule_id", ""),
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("message", ""),
        ]
        query_text = " ".join(filter(None, query_parts))
        
        if not query_text.strip():
            finding["rag_similar_findings"] = []
            finding["rag_remediation"] = ""
            finding["rag_references"] = []
            return finding
        
        try:
            # Query for similar findings
            similar = self.vector_store.query(query_text, top_k=self.top_k)
            
            # Aggregate remediation guidance
            remediations = []
            references = []
            
            for result in similar:
                metadata = result.get("metadata", {})
                
                # Collect remediation
                rem = metadata.get("remediation", "")
                if rem and rem not in remediations:
                    remediations.append(rem)
                
                # Collect references
                url = metadata.get("url", "")
                source = metadata.get("source", "")
                if url and {"url": url, "source": source} not in references:
                    references.append({"url": url, "source": source})
            
            # Add RAG fields to finding
            enriched = finding.copy()
            enriched["rag_similar_findings"] = similar
            enriched["rag_remediation"] = "\n\n".join(remediations[:3])
            enriched["rag_references"] = references[:5]
            
            logger.debug(
                f"Enriched finding {finding.get('rule_id', 'unknown')} with "
                f"{len(similar)} similar findings"
            )
            
            return enriched

        except _NETWORK_ERRORS as e:  # type: ignore[misc]
            logger.warning(
                f"AI Copilot unavailable (offline mode): {e}"
            )
            offline = dict(_OFFLINE_RESULT)
            offline.update(
                {k: finding.get(k) for k in finding if k not in offline}
            )
            return offline

        except Exception as e:
            logger.warning(f"Failed to enrich finding: {e}")
            finding["rag_similar_findings"] = []
            finding["rag_remediation"] = ""
            finding["rag_references"] = []
            return finding
    
    def enrich_findings_batch(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enrich multiple findings with RAG context.

        Short-circuits the loop if an API is unreachable (offline mode),
        so subsequent findings are returned un-enriched rather than causing
        repeated timeout delays.
        
        Args:
            findings: List of finding dictionaries.
            
        Returns:
            List of enriched findings (some may have rag_status='offline').
        """
        enriched = []
        copilot_offline = False
        for finding in findings:
            if copilot_offline:
                # API already confirmed unreachable — skip remainder
                offline = dict(_OFFLINE_RESULT)
                offline.update(
                    {k: finding.get(k)
                     for k in finding if k not in offline}
                )
                enriched.append(offline)
                continue
            result = self.enrich_finding(finding)
            if result.get("rag_status") == "offline":
                copilot_offline = True
                logger.info(
                    "AI Copilot offline — skipping enrichment"
                    " for remaining findings"
                )
            enriched.append(result)
        
        logger.info(f"Enriched {len(findings)} findings with RAG context")
        return enriched
    
    def rebuild_index(self, sources: Dict[str, Any]) -> Dict[str, int]:
        """Rebuild the RAG index from specified sources.

        Network/API failures during index building are caught and logged;
        the build continues with whatever local sources are available.
        
        Args:
            sources: Dict specifying sources to index:
                - remediation_db: Dict of rule_id -> remediation
                - findings: List of historical findings
                - threat_intel: List of threat intel results
                - audit_reports_dir: Directory of audit reports
                
        Returns:
            Dict with counts of indexed items per source.
        """
        # Clear existing index
        self.vector_store.clear()
        
        counts = {}
        
        # Index remediation database
        if "remediation_db" in sources:
            try:
                count = self.knowledge_builder.build_from_remediation_db(
                    sources["remediation_db"]
                )
                counts["remediation_db"] = count
            except _NETWORK_ERRORS as e:  # type: ignore[misc]
                logger.warning(
                    "AI Copilot unavailable (offline mode)"
                    f" during index build: {e}"
                )
                counts["remediation_db"] = 0
            except Exception as e:
                logger.warning(f"Failed to index remediation_db: {e}")
                counts["remediation_db"] = 0
        
        # Index historical findings
        if "findings" in sources:
            try:
                count = self.knowledge_builder.build_from_findings(
                    sources["findings"]
                )
                counts["findings"] = count
            except _NETWORK_ERRORS as e:  # type: ignore[misc]
                logger.warning(
                    "AI Copilot unavailable (offline mode)"
                    f" during index build: {e}"
                )
                counts["findings"] = 0
            except Exception as e:
                logger.warning(f"Failed to index findings: {e}")
                counts["findings"] = 0
        
        # Index threat intel
        if "threat_intel" in sources:
            try:
                count = self.knowledge_builder.build_from_threat_intel(
                    sources["threat_intel"]
                )
                counts["threat_intel"] = count
            except _NETWORK_ERRORS as e:  # type: ignore[misc]
                logger.warning(
                    "AI Copilot unavailable (offline mode)"
                    f" during index build: {e}"
                )
                counts["threat_intel"] = 0
            except Exception as e:
                logger.warning(f"Failed to index threat_intel: {e}")
                counts["threat_intel"] = 0
        
        # Index audit reports
        if "audit_reports_dir" in sources:
            try:
                count = self.knowledge_builder.build_from_audit_reports(
                    sources["audit_reports_dir"]
                )
                counts["audit_reports"] = count
            except _NETWORK_ERRORS as e:  # type: ignore[misc]
                logger.warning(
                    "AI Copilot unavailable (offline mode)"
                    f" during index build: {e}"
                )
                counts["audit_reports"] = 0
            except Exception as e:
                logger.warning(f"Failed to index audit_reports: {e}")
                counts["audit_reports"] = 0
        
        # Save the new index
        try:
            self.vector_store.save(self.index_path)
        except Exception as e:
            logger.warning(f"Failed to save RAG index: {e}")
        
        logger.info(f"Rebuilt RAG index: {counts}")
        return counts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get RAG system statistics.
        
        Returns:
            Dict with index size, coverage, last updated.
        """
        stats = self.vector_store.get_stats()
        stats["index_path"] = self.index_path
        stats["embedding_backend"] = self.embedding_backend
        stats["top_k"] = self.top_k
        stats["auto_enrich"] = self.auto_enrich
        
        # Check if index file exists
        stats["index_exists"] = Path(self.index_path).exists()
        
        return stats


def main():
    """CLI entry point for RAG engine."""
    parser = argparse.ArgumentParser(
        description="RAG Engine for Garrison - Build and query knowledge base"
    )
    parser.add_argument(
        "--build-index",
        action="store_true",
        help="Build the RAG index from sources"
    )
    parser.add_argument(
        "--sources",
        default="remediation",
        help="Sources: remediation,threat_intel,findings,reports"
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_INDEX_PATH,
        help=f"Output path for index (default: {DEFAULT_INDEX_PATH})"
    )
    parser.add_argument(
        "--query",
        help="Query text to search the index"
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=DEFAULT_TOP_K,
        help=f"Number of results (default: {DEFAULT_TOP_K})"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show index statistics"
    )
    
    args = parser.parse_args()
    
    # Initialize copilot
    config = {
        "rag_index_path": args.output,
        "top_k": args.top_k
    }
    copilot = AuditCopilot(config)
    
    if args.stats:
        stats = copilot.get_stats()
        print("\n=== RAG Index Statistics ===")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        return
    
    if args.build_index:
        print("\n=== Building RAG Index ===")
        
        sources = {}
        source_list = [s.strip() for s in args.sources.split(",")]
        
        # Import REMEDIATION_DB from orchestrator if available
        if "remediation" in source_list:
            try:
                from orchestrator import REMEDIATION_DB
                sources["remediation_db"] = REMEDIATION_DB
                count = len(REMEDIATION_DB)
                print(f"  - Including remediation_db ({count} entries)")
            except ImportError:
                print("  - Warning: Could not import REMEDIATION_DB")
        
        if "threat_intel" in source_list:
            sources["threat_intel"] = []
            print("  - Including threat_intel (empty - add manually)")
        
        if "findings" in source_list:
            sources["findings"] = []
            print("  - Including findings (empty - add manually)")
        
        if "reports" in source_list:
            sources["audit_reports_dir"] = "."
            print("  - Including audit reports from current directory")
        
        counts = copilot.rebuild_index(sources)
        print(f"\nIndex built successfully: {counts}")
        print(f"Index saved to: {args.output}")
        return
    
    if args.query:
        print(f"\n=== Query: '{args.query}' ===")
        
        # Load index if exists
        if not copilot.vector_store.entries:
            print("No index loaded. Build index first with --build-index")
            return
        
        results = copilot.vector_store.query(args.query, top_k=args.top_k)
        
        print(f"\nTop {len(results)} results:")
        for i, result in enumerate(results, 1):
            print(f"\n{i}. Similarity: {result['similarity']:.4f}")
            print(f"   Source: {result['metadata'].get('source', 'unknown')}")
            print(f"   Text: {result['text'][:150]}...")
        
        return
    
    # Default: show help
    parser.print_help()


if __name__ == "__main__":
    main()
