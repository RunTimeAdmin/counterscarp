#!/usr/bin/env python3
"""RAG pipeline for Counterscarp Engine.

Provides vector storage, knowledge base building, and audit copilot
for enriching security findings with historical context.

Example:
    >>> from rag_engine import AuditCopilot, VectorStore
    >>> copilot = AuditCopilot()
    >>> enriched = copilot.enrich_finding(finding)
"""

from __future__ import annotations

import json
import os
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Tuple, Type, Union, cast, TYPE_CHECKING
from logging import Logger
if TYPE_CHECKING:
    from exceptions import CounterscarpError as _CounterscarpErrorType
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Network error types for graceful offline handling
_NETWORK_ERRORS: Tuple[Type[Exception], ...] = (ConnectionError, TimeoutError, OSError)
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
    pass

_OFFLINE_RESULT: Dict[str, Any] = {
    "rag_status": "offline",
    "rag_message": (
        "AI enrichment unavailable — scan continues without LLM analysis"
    ),
    "rag_similar_findings": [],
    "rag_remediation": "",
    "rag_references": [],
}

# Import exceptions (core module — must always be available)
from exceptions import CounterscarpError, CounterscarpConfigError
from counterscarp_core.severity import SEVERITY_RANK

# Import logger with fallback
get_logger: Optional[Callable[[str], Logger]] = None
LOGGER_AVAILABLE = False
try:
    from logger import get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    pass

# Initialize logger
if LOGGER_AVAILABLE and get_logger is not None:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Try importing embeddings module
get_embeddings: Optional[Callable[..., Any]] = None
cosine_similarity: Optional[Callable[[List[float], List[float]], float]] = None
embed_local: Optional[Callable[[List[str]], List[List[float]]]] = None
EMBEDDINGS_AVAILABLE = False
NUMPY_AVAILABLE = False
try:
    from embeddings import (
        get_embeddings,
        cosine_similarity,
        embed_local,
        NUMPY_AVAILABLE
    )
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    pass

# Try importing numpy
import types as _types
np: Optional[_types.ModuleType] = None
if NUMPY_AVAILABLE:
    import numpy as _np  # noqa
    np = _np

# Default configuration
DEFAULT_INDEX_PATH = ".scarpshield/rag_index.json"
DEFAULT_TOP_K = 5


class RAGError(CounterscarpError):
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
    retrieval. Uses JSON for serialization.
    
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
        self._embeddings_cache: Optional[Any] = None
        self._embedding_norms: Optional[Any] = None
        self._cache_dirty = True
        logger.debug(
            f"VectorStore initialized with dim={embedding_dim}"
        )

    def _invalidate_cache(self) -> None:
        """Mark matrix cache dirty and drop cached arrays."""
        self._embeddings_cache = None
        self._embedding_norms = None
        self._cache_dirty = True
    
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
        assert embed_local is not None
        
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
            self._cache_dirty = True
            
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
        assert embed_local is not None
        
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

            self._cache_dirty = True
            logger.debug(f"Added {len(items)} entries to VectorStore")
            
        except Exception as e:
            raise RAGError(f"Failed to add batch: {e}") from e

    def _ensure_embeddings_cache(self) -> None:
        """Lazily build normalized matrix cache for NumPy query path."""
        if not self._cache_dirty and self._embeddings_cache is not None:
            return
        if not NUMPY_AVAILABLE or np is None:
            self._invalidate_cache()
            self._cache_dirty = False
            return
        if not self.entries:
            self._embeddings_cache = np.zeros((0, self.embedding_dim), dtype=np.float32)
            self._embedding_norms = np.zeros((0,), dtype=np.float32)
            self._cache_dirty = False
            return

        matrix = np.asarray(
            [entry.embedding for entry in self.entries],
            dtype=np.float32,
        )
        if matrix.ndim != 2:
            self._invalidate_cache()
            self._cache_dirty = False
            return
        norms = np.linalg.norm(matrix, axis=1)
        safe_norms = norms.copy()
        safe_norms[safe_norms == 0.0] = 1.0
        self._embeddings_cache = matrix / safe_norms[:, None]
        self._embedding_norms = norms
        self._cache_dirty = False
    
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
        assert embed_local is not None
        assert cosine_similarity is not None
        
        try:
            # Generate query embedding
            query_embeddings = embed_local([query_text])
            if not query_embeddings:
                raise RAGError("Failed to generate query embedding")
            query_vec = query_embeddings[0]

            if NUMPY_AVAILABLE and np is not None:
                self._ensure_embeddings_cache()
                if self._embeddings_cache is not None and self._embeddings_cache.size:
                    query_arr = np.asarray(query_vec, dtype=np.float32)
                    query_norm = float(np.linalg.norm(query_arr))
                    if query_norm == 0.0:
                        return []

                    sims = self._embeddings_cache @ (query_arr / query_norm)
                    if self._embedding_norms is not None:
                        sims = np.where(self._embedding_norms > 0.0, sims, 0.0)

                    limit = min(max(1, top_k), len(sims))
                    if limit >= len(sims):
                        order = np.argsort(-sims)
                    else:
                        partition = np.argpartition(-sims, limit - 1)[:limit]
                        order = partition[np.argsort(-sims[partition])]
                    return [
                        {
                            "text": self.entries[int(idx)].text,
                            "metadata": self.entries[int(idx)].metadata,
                            "similarity": float(sims[int(idx)]),
                        }
                        for idx in order
                    ]

            results = []
            for entry in self.entries:
                sim = cosine_similarity(query_vec, entry.embedding)
                results.append(
                    {
                        "text": entry.text,
                        "metadata": entry.metadata,
                        "similarity": sim,
                    }
                )

            # Sort by similarity (descending)
            results.sort(key=lambda x: float(cast(Any, x["similarity"])), reverse=True)

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
            pkl_path = path.replace('.json', '.pkl')
            if Path(pkl_path).exists():
                logger.warning(
                    "Legacy .pkl index found at %s — manual migration required. "
                    "Convert to JSON format. See documentation for details.", pkl_path
                )

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
            self._invalidate_cache()

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

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the store.
        
        Returns:
            Dict with index statistics.
        """
        sources: Dict[str, int] = {}
        severities: Dict[str, int] = {}
        
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
        self._invalidate_cache()
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


# ---------------------------------------------------------------------------
# LLM-powered analysis — supports OpenAI and Ollama providers
# ---------------------------------------------------------------------------

def _build_analysis_prompt(
    finding: Dict[str, Any],
    similar_findings: List[Dict[str, Any]],
) -> str:
    """Build the audit analysis prompt from finding data.

    Args:
        finding: Finding dictionary.
        similar_findings: Top-K similar past findings returned by RAG.

    Returns:
        Formatted prompt string ready to send to any LLM.
    """
    # Build context from top-3 similar past findings
    context_lines: List[str] = []
    for i, sf in enumerate(similar_findings[:3], 1):
        meta = sf.get("metadata", {})
        context_lines.append(
            f"Past Finding {i}: "
            f"[{meta.get('rule_id', 'unknown')}] "
            f"{meta.get('title', meta.get('text', '')[:120])} "
            f"(severity={meta.get('severity', '?')}) — "
            f"Remediation: {meta.get('remediation', 'N/A')}"
        )
    context_block = "\n".join(context_lines) or "No similar past findings."

    rule_id = finding.get("rule_id", "unknown")
    title = finding.get("title", finding.get("message", ""))
    description = finding.get("description", finding.get("message", ""))
    severity = finding.get("severity", "UNKNOWN")
    snippet = finding.get("code_snippet", "")
    snippet_block = (
        f"\n\nAffected code snippet:\n```solidity\n{snippet}\n```"
        if snippet else ""
    )

    return (
        f"You are an expert smart-contract security auditor.\n\n"
        f"A scanner has detected the following vulnerability:\n"
        f"- Rule ID: {rule_id}\n"
        f"- Title: {title}\n"
        f"- Severity: {severity}\n"
        f"- Description: {description}{snippet_block}\n\n"
        f"Similar past findings for context:\n{context_block}\n\n"
        f"Please provide a concise analysis covering:\n"
        f"1. What this vulnerability is (technical explanation)\n"
        f"2. Why it matters specifically in a DeFi/smart-contract context "
        f"(potential attack vectors, financial impact)\n"
        f"3. Specific remediation steps for this code\n\n"
        f"Keep the response under 400 words and use plain text."
    )


def _call_ollama(
    prompt: str,
    model: str,
    base_url: str = "http://localhost:11434",
) -> str:
    """Call a local Ollama instance for LLM analysis.

    Args:
        prompt: The prompt text to send.
        model: Ollama model name (e.g. "deepseek-coder", "codellama").
        base_url: Ollama API base URL.

    Returns:
        Response text, or empty string on failure.
    """
    try:
        import requests as _requests
        url = f"{base_url.rstrip('/')}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        response = _requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        result: str = str(response.json().get("response", ""))
        logger.debug(
            f"Ollama ({model}) returned {len(result)} chars"
        )
        return result.strip()
    except Exception as e:
        logger.warning(f"Ollama connection failed: {e}")
        return ""


def _call_openai(
    prompt: str,
    model: str,
    api_key: str,
) -> str:
    """Call the OpenAI API for LLM analysis.

    Args:
        prompt: The prompt text to send.
        model: OpenAI model name (e.g. "gpt-4o-mini").
        api_key: OpenAI API key.

    Returns:
        Response text, or empty string on failure.
    """
    try:
        import openai as _openai  # optional dependency
        client = _openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior smart-contract security auditor "
                        "specialising in DeFi protocols. Be precise and actionable."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=512,
            temperature=0.2,
        )
        result = response.choices[0].message.content or ""
        logger.debug(
            f"OpenAI ({model}) returned {len(result)} chars"
        )
        return result.strip()
    except ImportError:
        logger.debug("openai package not installed — LLM analysis skipped")
        return ""
    except Exception as e:
        logger.warning(f"OpenAI call failed: {e}")
        return ""


def generate_llm_analysis(
    finding: Dict[str, Any],
    similar_findings: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
    api_key: Optional[str] = None,
) -> str:
    """Generate an LLM-powered analysis for a security finding.

    Routes to the configured LLM provider.  Supported providers:
    - "openai"  — calls OpenAI Chat Completions (requires OPENAI_API_KEY)
    - "ollama"  — calls a local Ollama instance via HTTP (no key needed)
    - "none"    — disabled; returns empty string immediately

    Args:
        finding: Finding dictionary (rule_id, title, description, severity,
            code_snippet, etc.).
        similar_findings: Top-K similar past findings returned by RAG.
        config: Provider config dict with keys: llm_backend, llm_model,
            ollama_url, api_key.  Defaults to openai if omitted.
        api_key: Legacy positional API key (OpenAI only).  Ignored when
            config dict contains an ``api_key`` entry.

    Returns:
        Analysis text as a plain string, or empty string on any failure
        (missing key, import error, network error, provider == "none").
    """
    cfg = config or {}
    provider = cfg.get("llm_backend", "openai")
    model = cfg.get("llm_model", "gpt-4o-mini")

    if provider == "none":
        return ""

    prompt = _build_analysis_prompt(finding, similar_findings)

    if provider == "ollama":
        ollama_url = cfg.get("ollama_url", "http://localhost:11434")
        return _call_ollama(prompt, model, ollama_url)

    if provider == "openai":
        key = cfg.get("api_key") or api_key or os.getenv("OPENAI_API_KEY", "")
        if not key:
            logger.debug("OPENAI_API_KEY not set — LLM analysis skipped")
            return ""
        return _call_openai(prompt, model, key)

    logger.debug(f"Unknown llm_backend '{provider}' — LLM analysis skipped")
    return ""


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
        self.llm_enrichment = self.config.get("llm_enrichment", False)
        
        self.vector_store = VectorStore()
        self.knowledge_builder = KnowledgeBaseBuilder(self.vector_store)

        # Offline TTL: set when an API failure occurs, cleared when it expires
        self._offline_until: Optional[datetime] = None

        # Try to load existing index
        self._load_index()
        
        logger.info(
            f"AuditCopilot initialized (backend={self.embedding_backend}, "
            f"top_k={self.top_k})"
        )
    
    def _load_index(self) -> None:
        """Load existing RAG index if available."""
        try:
            resolved_path = self._resolve_legacy_index_path(self.index_path)
            self.vector_store.load(resolved_path)
            if resolved_path != self.index_path:
                logger.info(
                    "Using legacy RAG index fallback: %s -> %s",
                    self.index_path,
                    resolved_path,
                )
        except Exception as e:
            logger.warning(f"Could not load RAG index: {e}")

    @staticmethod
    def _resolve_legacy_index_path(index_path: str) -> str:
        """Resolve preferred/legacy index path compatibility for reads."""
        preferred = Path(index_path)
        if preferred.exists():
            return str(preferred)

        parts = list(preferred.parts)
        if ".scarpshield" in parts:
            parts[parts.index(".scarpshield")] = ".counterscarp"
            legacy = Path(*parts)
            if legacy.exists():
                return str(legacy)
        return index_path

    def _is_offline(self) -> bool:
        """Return True if the copilot is in the offline backoff window."""
        if self._offline_until is None:
            return False
        if datetime.now() > self._offline_until:
            self._offline_until = None  # TTL expired, retry
            return False
        return True

    def _set_offline(self, minutes: int = 5) -> None:
        """Enter offline mode for *minutes* (default 5)."""
        self._offline_until = datetime.now() + timedelta(minutes=minutes)

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
            vector_remediation = "\n\n".join(remediations[:3])
            enriched["rag_references"] = references[:5]

            # Optional LLM enrichment — enabled when llm_backend != "none"
            llm_backend = self.config.get("llm_backend", "none")
            _llm_active = self.llm_enrichment and llm_backend != "none"
            if _llm_active:
                llm_config = {
                    "llm_backend": llm_backend,
                    "llm_model": self.config.get("llm_model", "gpt-4o-mini"),
                    "ollama_url": self.config.get(
                        "ollama_url", "http://localhost:11434"
                    ),
                    "api_key": os.environ.get("OPENAI_API_KEY", ""),
                }
                llm_text = generate_llm_analysis(finding, similar, config=llm_config)
                if llm_text:
                    enriched["rag_remediation"] = llm_text
                    logger.debug(
                        f"LLM remediation stored for "
                        f"{finding.get('rule_id', 'unknown')}"
                    )
                else:
                    # Fallback to vector-only remediation
                    enriched["rag_remediation"] = vector_remediation
            else:
                enriched["rag_remediation"] = vector_remediation
            
            logger.debug(
                f"Enriched finding {finding.get('rule_id', 'unknown')} with "
                f"{len(similar)} similar findings"
            )
            
            return enriched

        except _NETWORK_ERRORS as e:
            logger.warning(
                f"AI Copilot unavailable (offline mode): {e}"
            )
            self._set_offline()
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

        When LLM enrichment is enabled, only the top 20 highest-severity
        findings receive LLM analysis to control API costs.  The rest fall
        back to vector-only enrichment.
        
        Args:
            findings: List of finding dictionaries.
            
        Returns:
            List of enriched findings (some may have rag_status='offline').
        """
        # --- Rate-limiting: cap LLM calls to 20 highest-severity findings ---
        LLM_CAP = 20

        # Determine which findings qualify for LLM enrichment
        llm_eligible_ids: set = set()
        _llm_backend = self.config.get("llm_backend", "none")
        if self.llm_enrichment and _llm_backend != "none":
            sorted_by_severity = sorted(
                range(len(findings)),
                key=lambda i: SEVERITY_RANK.get(
                    str(findings[i].get("severity", "INFO")).upper(), 4
                ),
            )
            llm_eligible_ids = set(sorted_by_severity[:LLM_CAP])

        enriched = []
        for idx, finding in enumerate(findings):
            if self._is_offline():
                # API already confirmed unreachable — skip remainder until TTL expires
                offline = dict(_OFFLINE_RESULT)
                offline.update(
                    {k: finding.get(k)
                     for k in finding if k not in offline}
                )
                enriched.append(offline)
                continue

            # Temporarily disable LLM for findings outside the cap
            _orig_llm = self.llm_enrichment
            if self.llm_enrichment and idx not in llm_eligible_ids:
                self.llm_enrichment = False

            result = self.enrich_finding(finding)

            # Restore flag
            self.llm_enrichment = _orig_llm

            if result.get("rag_status") == "offline":
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
            except _NETWORK_ERRORS as e:
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
            except _NETWORK_ERRORS as e:
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
            except _NETWORK_ERRORS as e:
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
            except _NETWORK_ERRORS as e:
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
        description="RAG Engine for Counterscarp - Build and query knowledge base"
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
        
        sources: Dict[str, Any] = {}
        source_list = [s.strip() for s in args.sources.split(",")]
        
        # Import REMEDIATION_DB from orchestrator if available
        if "remediation" in source_list:
            try:
                import orchestrator as _orc
                REMEDIATION_DB = getattr(_orc, "REMEDIATION_DB", None)
                if REMEDIATION_DB is None:
                    raise ImportError("REMEDIATION_DB not found in orchestrator")
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
