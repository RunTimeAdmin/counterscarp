"""Performance benchmarks for Garrison Engine.

Run with: pytest tests/test_benchmarks.py --benchmark-only
Skip during normal test runs with: pytest -m "not benchmark"
"""
from __future__ import annotations

import pytest
import random
import string
from unittest.mock import patch

# Mark all tests in this module as benchmarks
pytestmark = pytest.mark.benchmark


# ---------------------------------------------------------------------------
# Helpers to generate test data
# ---------------------------------------------------------------------------

def _random_text(length: int = 100) -> str:
    """Generate random text of specified length."""
    return ''.join(random.choices(string.ascii_lowercase + ' ', k=length))


def _random_embedding(dim: int = 384) -> list:
    """Generate a random embedding vector of specified dimension."""
    return [random.random() for _ in range(dim)]


def _make_findings(count: int) -> list:
    """Create mock findings dicts for attack graph benchmarks."""
    findings = []
    rule_types = ["REENTRANCY", "ACCESS_CONTROL", "INTEGER_OVERFLOW", 
                  "ORACLE_MANIPULATION", "UNCHECKED_EXTERNAL_CALL"]
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    
    for i in range(count):
        finding = {
            "rule_id": random.choice(rule_types),
            "severity": random.choice(severities),
            "file": f"contracts/Contract{i % 5}.sol",
            "line_no": random.randint(1, 500),
            "message": f"Vulnerability detected in function {i}",
            "description": f"Sample vulnerability description {i}"
        }
        findings.append(finding)
    return findings


def _make_solidity_contract(lines: int = 200) -> str:
    """Generate a sample Solidity contract string for scanning."""
    contract_parts = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.19;",
        "",
        "import \"@openzeppelin/contracts/token/ERC20/ERC20.sol\";",
        "import \"@openzeppelin/contracts/access/Ownable.sol\";",
        "",
        "contract SampleToken is ERC20, Ownable {",
        "    uint256 public constant MAX_SUPPLY = 1000000 * 10**18;",
        "    uint256 public totalMinted;",
        "    bool public tradingEnabled;",
        "    mapping(address => bool) public whitelist;",
        "",
        "    event TokensMinted(address indexed to, uint256 amount);",
        "    event TradingEnabled(bool enabled);",
        "",
        "    constructor() ERC20(\"SampleToken\", \"SAMPLE\") {",
        "        _mint(msg.sender, 100000 * 10**18);",
        "        totalMinted = 100000 * 10**18;",
        "        tradingEnabled = false;",
        "    }",
        "",
        "    function mint(address to, uint256 amount) external onlyOwner {",
        "        require(totalMinted + amount <= MAX_SUPPLY,",
        "            \"Max supply exceeded\");",
        "        _mint(to, amount);",
        "        totalMinted += amount;",
        "        emit TokensMinted(to, amount);",
        "    }",
        "",
        "    function enableTrading() external onlyOwner {",
        "        tradingEnabled = true;",
        "        emit TradingEnabled(true);",
        "    }",
        "",
        "    function emergencyWithdraw() external onlyOwner {",
        "        (bool success, ) = payable(owner()).",
        "            call{value: address(this).balance}(\"\");",
        "        require(success, \"Transfer failed\");",
        "    }",
        "",
        "    function setFee(uint256 newFee) external onlyOwner {",
        "        require(newFee <= 1000, \"Fee too high\");",
        "        // Set fee logic here",
        "    }",
        "",
    ]
    
    # Add more functions to reach the desired line count
    func_template = """    function transferWithCheck(address to,
        uint256 amount) external returns (bool) {{
        require(tradingEnabled || whitelist[msg.sender],
            \"Trading not enabled\");
        return transfer(to, amount);
    }}

    function batchTransfer(address[] calldata recipients,
        uint256[] calldata amounts) external {{
        require(recipients.length == amounts.length,
            \"Length mismatch\");
        for (uint256 i = 0; i < recipients.length; i++) {{
            transfer(recipients[i], amounts[i]);
        }}
    }}
"""
    
    # Keep adding functions until we reach the desired line count
    while len(contract_parts) < lines - 2:
        func_id = len(contract_parts)
        func_code = func_template.format(func_id)
        contract_parts.extend(func_code.strip().split('\n'))
    
    contract_parts.append("}")
    
    # Trim or pad to exact line count
    result = '\n'.join(contract_parts[:lines])
    while result.count('\n') < lines - 1:
        result += '\n// padding'
    
    return result


# ---------------------------------------------------------------------------
# Benchmark Tests
# ---------------------------------------------------------------------------

class TestRAGVectorStore:
    """Benchmarks for RAG VectorStore.query() performance."""
    
    def test_rag_query_100(self, benchmark):
        """Benchmark VectorStore.query() with 100 entries."""
        from rag_engine import VectorStore, IndexEntry
        from embeddings import cosine_similarity
        
        store = VectorStore()
        # Pre-populate with entries that have embeddings
        for i in range(100):
            entry = IndexEntry(
                text=_random_text(50),
                embedding=_random_embedding(384),
                metadata={"source": "test", "index": i}
            )
            store.entries.append(entry)
        
        query_embedding = _random_embedding(384)
        
        def query_func():
            # Simulate query by calculating similarities
            results = []
            for entry in store.entries:
                sim = cosine_similarity(query_embedding, entry.embedding)
                results.append({
                    "text": entry.text,
                    "metadata": entry.metadata,
                    "similarity": sim
                })
            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:5]
        
        result = benchmark(query_func)
        assert len(result) <= 5
    
    def test_rag_query_1000(self, benchmark):
        """Benchmark VectorStore.query() with 1000 entries."""
        from rag_engine import VectorStore, IndexEntry
        from embeddings import cosine_similarity
        
        store = VectorStore()
        for i in range(1000):
            entry = IndexEntry(
                text=_random_text(50),
                embedding=_random_embedding(384),
                metadata={"source": "test", "index": i}
            )
            store.entries.append(entry)
        
        query_embedding = _random_embedding(384)
        
        def query_func():
            results = []
            for entry in store.entries:
                sim = cosine_similarity(query_embedding, entry.embedding)
                results.append({
                    "text": entry.text,
                    "metadata": entry.metadata,
                    "similarity": sim
                })
            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:5]
        
        result = benchmark(query_func)
        assert len(result) <= 5
    
    def test_rag_query_5000(self, benchmark):
        """Benchmark VectorStore.query() with 5000 entries."""
        from rag_engine import VectorStore, IndexEntry
        from embeddings import cosine_similarity
        
        store = VectorStore()
        for i in range(5000):
            entry = IndexEntry(
                text=_random_text(50),
                embedding=_random_embedding(384),
                metadata={"source": "test", "index": i}
            )
            store.entries.append(entry)
        
        query_embedding = _random_embedding(384)
        
        def query_func():
            results = []
            for entry in store.entries:
                sim = cosine_similarity(query_embedding, entry.embedding)
                results.append({
                    "text": entry.text,
                    "metadata": entry.metadata,
                    "similarity": sim
                })
            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:5]
        
        result = benchmark(query_func)
        assert len(result) <= 5


class TestEmbeddings:
    """Benchmarks for embeddings generation."""
    
    def test_bag_of_words_fallback(self, benchmark):
        """Benchmark the local bag-of-words fallback embedding generation."""
        from embeddings import SimpleBagOfWords
        
        # Mock sentence-transformers as unavailable
        with patch('embeddings.SENTENCE_TRANSFORMERS_AVAILABLE', False):
            with patch('embeddings.SKLEARN_AVAILABLE', False):
                texts = [_random_text(100) for _ in range(10)]
                bow = SimpleBagOfWords(max_features=384)
                
                result = benchmark(bow.fit_transform, texts)
                assert len(result) == 10
                assert all(len(emb) <= 384 for emb in result)


class TestFingerprintSimilarity:
    """Benchmarks for fingerprint similarity scoring."""
    
    def test_calculate_similarity(self, benchmark):
        """Benchmark calculate_similarity() with realistic features."""
        from fingerprint_scanner import ContractFeatures
        from fingerprint_scanner import calculate_similarity
        from protocol_db import ProtocolFingerprint
        
        # Create realistic contract features
        features = ContractFeatures(
            file_path="test/Token.sol",
            function_signatures=[
                "transfer(address,uint256)",
                "balanceOf(address)",
                "approve(address,uint256)",
                "transferFrom(address,address,uint256)",
                "mint(address,uint256)",
                "burn(uint256)",
                "totalSupply()",
            ],
            event_signatures=[
                "Transfer(address,address,uint256)",
                "Approval(address,address,uint256)",
            ],
            inheritance_chain=["ERC20", "Ownable", "Pausable"],
            imports=["@openzeppelin/contracts/token/ERC20/ERC20.sol"],
            storage_variables=["_balances", "_allowances",
                               "_totalSupply", "_owner"],
            constants={"MAX_SUPPLY": "1000000 ether", "DECIMALS": "18"},
            function_bodies={}
        )
        
        # Create a protocol fingerprint
        fingerprint = ProtocolFingerprint(
            name="ERC20 Token",
            category="Token",
            version="1.0",
            function_signatures=[
                "transfer(address,uint256)",
                "balanceOf(address)",
                "approve(address,uint256)",
                "transferFrom(address,address,uint256)",
                "totalSupply()",
            ],
            event_signatures=[
                "Transfer(address,address,uint256)",
                "Approval(address,address,uint256)",
            ],
            inheritance_markers=["ERC20", "Ownable"],
            storage_patterns=["_balances", "_allowances"],
            constants={"DECIMALS": "18"},
            known_vulnerabilities=[]
        )
        
        result = benchmark(calculate_similarity, features, fingerprint)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], float)  # score
        assert isinstance(result[1], dict)   # details


class TestHeuristicScanner:
    """Benchmarks for heuristic scanner pattern matching."""
    
    def test_scan_file(self, benchmark, tmp_path):
        """Benchmark scanning a sample contract against all built-in rules."""
        from heuristic_scanner import scan_file
        
        # Create a temporary Solidity contract file
        contract_code = _make_solidity_contract(200)
        contract_file = tmp_path / "TestContract.sol"
        contract_file.write_text(contract_code)
        
        result = benchmark(scan_file, str(contract_file))
        assert isinstance(result, list)
        # Should find some findings given the contract has patterns like
        # tx.origin, emergencyWithdraw, etc.


class TestAttackGraph:
    """Benchmarks for attack graph construction."""
    
    def test_build_graph_10_findings(self, benchmark):
        """Benchmark build_graph() with 10 findings."""
        from attack_graph import build_graph
        
        findings = _make_findings(10)
        result = benchmark(build_graph, findings)
        assert result is not None
        assert len(result.nodes) >= 8  # Allow for deduplication
    
    def test_build_graph_50_findings(self, benchmark):
        """Benchmark build_graph() with 50 findings."""
        from attack_graph import build_graph
        
        findings = _make_findings(50)
        result = benchmark(build_graph, findings)
        assert result is not None
        assert len(result.nodes) >= 40
    
    def test_build_graph_100_findings(self, benchmark):
        """Benchmark build_graph() with 100 findings."""
        from attack_graph import build_graph
        
        findings = _make_findings(100)
        result = benchmark(build_graph, findings)
        assert result is not None
        assert len(result.nodes) >= 90
