"""
Tests for the attack_graph module.
"""

import pytest
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from attack_graph import (
    GraphNode,
    GraphEdge,
    AttackGraph,
    build_graph,
    trace_attack_paths,
    export_graph_json,
    get_attack_path_summary,
    _generate_node_id,
    _parse_solidity_file,
    _parse_rust_file,
)


# =============================================================================
# GraphNode Tests
# =============================================================================

class TestGraphNode:
    """Test GraphNode dataclass."""

    def test_valid_node_creation(self):
        """Test creating a valid GraphNode."""
        node = GraphNode(
            id="Contract_Vault_1234",
            type="Contract",
            name="Vault",
            metadata={"file": "Vault.sol", "line": 1}
        )
        assert node.id == "Contract_Vault_1234"
        assert node.type == "Contract"
        assert node.name == "Vault"
        assert node.metadata["file"] == "Vault.sol"

    def test_valid_types(self):
        """Test all valid node types."""
        valid_types = ["Contract", "Function", "Vulnerability",
                       "ExternalCall", "StateVariable"]
        for node_type in valid_types:
            node = GraphNode(
                id=f"test_{node_type}",
                type=node_type,
                name="Test"
            )
            assert node.type == node_type

    def test_invalid_node_type(self):
        """Test that invalid node type raises ValueError."""
        with pytest.raises(ValueError):
            GraphNode(
                id="test",
                type="InvalidType",
                name="Test"
            )

    def test_default_metadata(self):
        """Test GraphNode with default metadata."""
        node = GraphNode(
            id="test",
            type="Contract",
            name="Test"
        )
        assert node.metadata == {}


# =============================================================================
# GraphEdge Tests
# =============================================================================

class TestGraphEdge:
    """Test GraphEdge dataclass."""

    def test_valid_edge_creation(self):
        """Test creating a valid GraphEdge."""
        edge = GraphEdge(
            source_id="Function_withdraw",
            target_id="Vulnerability_reentrancy",
            type="triggers",
            metadata={"relationship": "vulnerability_in_function"}
        )
        assert edge.source_id == "Function_withdraw"
        assert edge.target_id == "Vulnerability_reentrancy"
        assert edge.type == "triggers"

    def test_valid_edge_types(self):
        """Test all valid edge types."""
        valid_types = ["calls", "reads", "writes", "delegates",
                       "inherits", "contains", "triggers"]
        for edge_type in valid_types:
            edge = GraphEdge(
                source_id="src",
                target_id="dst",
                type=edge_type
            )
            assert edge.type == edge_type

    def test_invalid_edge_type(self):
        """Test that invalid edge type raises ValueError."""
        with pytest.raises(ValueError):
            GraphEdge(
                source_id="src",
                target_id="dst",
                type="invalid"
            )


# =============================================================================
# AttackGraph Tests
# =============================================================================

class TestAttackGraph:
    """Test AttackGraph class."""

    def test_init_empty(self):
        """Test initializing empty AttackGraph."""
        graph = AttackGraph()
        assert graph.nodes == []
        assert graph.edges == []

    def test_add_node(self):
        """Test adding a node to the graph."""
        graph = AttackGraph()
        node = GraphNode(id="test", type="Contract", name="Test")
        
        graph.add_node(node)
        
        assert len(graph.nodes) == 1
        assert graph.nodes[0] == node

    def test_add_duplicate_node(self):
        """Test that duplicate nodes are not added."""
        graph = AttackGraph()
        node = GraphNode(id="test", type="Contract", name="Test")
        
        graph.add_node(node)
        graph.add_node(node)  # Duplicate
        
        assert len(graph.nodes) == 1

    def test_add_edge(self):
        """Test adding an edge to the graph."""
        graph = AttackGraph()
        edge = GraphEdge(
            source_id="src",
            target_id="dst",
            type="calls"
        )
        
        graph.add_edge(edge)
        
        assert len(graph.edges) == 1
        assert graph.edges[0] == edge

    def test_add_duplicate_edge(self):
        """Test that duplicate edges are not added."""
        graph = AttackGraph()
        edge = GraphEdge(
            source_id="src",
            target_id="dst",
            type="calls"
        )
        
        graph.add_edge(edge)
        graph.add_edge(edge)  # Duplicate
        
        assert len(graph.edges) == 1

    def test_get_node_existing(self):
        """Test getting an existing node."""
        graph = AttackGraph()
        node = GraphNode(id="test", type="Contract", name="Test")
        graph.add_node(node)
        
        result = graph.get_node("test")
        
        assert result == node

    def test_get_node_nonexistent(self):
        """Test getting a non-existent node."""
        graph = AttackGraph()
        
        result = graph.get_node("nonexistent")
        
        assert result is None

    def test_get_nodes_by_type(self):
        """Test getting nodes by type."""
        graph = AttackGraph()
        
        contract = GraphNode(id="c1", type="Contract", name="C1")
        func = GraphNode(id="f1", type="Function", name="F1")
        vuln = GraphNode(id="v1", type="Vulnerability", name="V1")
        
        graph.add_node(contract)
        graph.add_node(func)
        graph.add_node(vuln)
        
        contracts = graph.get_nodes_by_type("Contract")
        assert len(contracts) == 1
        assert contracts[0] == contract

    def test_get_outgoing_edges(self):
        """Test getting outgoing edges from a node."""
        graph = AttackGraph()
        
        edge1 = GraphEdge(source_id="A", target_id="B", type="calls")
        edge2 = GraphEdge(source_id="A", target_id="C", type="calls")
        edge3 = GraphEdge(source_id="B", target_id="C", type="calls")
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)
        
        outgoing = graph.get_outgoing_edges("A")
        assert len(outgoing) == 2

    def test_get_incoming_edges(self):
        """Test getting incoming edges to a node."""
        graph = AttackGraph()
        
        edge1 = GraphEdge(source_id="A", target_id="C", type="calls")
        edge2 = GraphEdge(source_id="B", target_id="C", type="calls")
        edge3 = GraphEdge(source_id="A", target_id="B", type="calls")
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)
        
        incoming = graph.get_incoming_edges("C")
        assert len(incoming) == 2

    def test_get_neighbors(self):
        """Test getting neighboring node IDs."""
        graph = AttackGraph()
        
        edge1 = GraphEdge(source_id="A", target_id="B", type="calls")
        edge2 = GraphEdge(source_id="C", target_id="A", type="calls")
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        
        neighbors = graph.get_neighbors("A")
        assert "B" in neighbors
        assert "C" in neighbors


# =============================================================================
# build_graph Tests
# =============================================================================

class TestBuildGraph:
    """Test build_graph function."""

    def test_build_graph_from_findings_only(self):
        """Test building graph from findings without source files."""
        findings = [
            {
                "rule_id": "REENTRANCY",
                "severity": "CRITICAL",
                "file": "Vault.sol",
                "line_no": 45,
                "message": "Reentrancy vulnerability"
            },
            {
                "rule_id": "TX_ORIGIN",
                "severity": "HIGH",
                "file": "Auth.sol",
                "line_no": 20,
                "message": "Uses tx.origin"
            }
        ]
        
        graph = build_graph(findings)
        
        assert len(graph.nodes) == 2
        
        # Check vulnerability nodes were created
        vuln_nodes = graph.get_nodes_by_type("Vulnerability")
        assert len(vuln_nodes) == 2

    def test_build_graph_node_metadata(self):
        """Test that vulnerability nodes have correct metadata."""
        findings = [
            {
                "rule_id": "REENTRANCY",
                "severity": "CRITICAL",
                "file": "Vault.sol",
                "line_no": 45,
                "message": "Reentrancy vulnerability"
            }
        ]
        
        graph = build_graph(findings)
        
        vuln = graph.get_nodes_by_type("Vulnerability")[0]
        assert vuln.metadata["severity"] == "CRITICAL"
        assert vuln.metadata["file"] == "Vault.sol"
        assert vuln.metadata["line"] == 45
        assert vuln.metadata["rule_id"] == "REENTRANCY"

    def test_build_graph_empty_findings(self):
        """Test building graph with empty findings."""
        graph = build_graph([])
        
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_build_graph_with_solidity_file(self, tmp_path):
        """Test building graph with Solidity source file."""
        # Create a test Solidity file
        sol_file = tmp_path / "Test.sol"
        sol_content = """
contract Test {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
}
"""
        sol_file.write_text(sol_content)
        
        findings = [
            {
                "rule_id": "TEST",
                "severity": "HIGH",
                "file": str(sol_file),
                "line_no": 6,
                "message": "Test finding"
            }
        ]
        
        graph = build_graph(findings, source_files=[str(sol_file)])
        
        # Should have vulnerability + contract + functions
        assert len(graph.nodes) >= 2

    def test_build_graph_missing_source_file(self):
        """Test building graph with missing source file."""
        findings = [
            {
                "rule_id": "TEST",
                "severity": "HIGH",
                "file": "nonexistent.sol",
                "line_no": 1,
                "message": "Test"
            }
        ]
        
        # Should not raise error, just skip missing file
        graph = build_graph(findings, source_files=["nonexistent.sol"])
        assert len(graph.nodes) == 1  # Just the vulnerability


# =============================================================================
# trace_attack_paths Tests
# =============================================================================

class TestTraceAttackPaths:
    """Test trace_attack_paths function."""

    def test_trace_simple_path(self):
        """Test tracing simple attack path."""
        graph = AttackGraph()
        
        # Create: Contract -> Function -> Vulnerability
        # Note: trace_attack_paths records paths ending at Vulnerability
        contract = GraphNode(id="C", type="Contract", name="Vault")
        func = GraphNode(id="F", type="Function", name="withdraw",
                         metadata={"visibility": "public"})
        vuln = GraphNode(id="V", type="Vulnerability", name="REENTRANCY")
        
        graph.add_node(contract)
        graph.add_node(func)
        graph.add_node(vuln)
        
        # Use "triggers" edge from Function to Vulnerability
        graph.add_edge(GraphEdge("C", "F", "contains"))
        graph.add_edge(GraphEdge("F", "V", "triggers"))
        
        paths = trace_attack_paths(graph)
        
        # Should find paths ending at vulnerability
        assert len(paths) > 0
        # Check that vulnerability is in one of the paths
        vuln_in_path = any("V" in path for path in paths)
        assert vuln_in_path

    def test_trace_with_vulnerability(self):
        """Test tracing path to vulnerability."""
        graph = AttackGraph()
        
        contract = GraphNode(id="C", type="Contract", name="Vault")
        func = GraphNode(id="F", type="Function", name="withdraw",
                         metadata={"visibility": "public"})
        vuln = GraphNode(id="V", type="Vulnerability", name="REENTRANCY")
        
        graph.add_node(contract)
        graph.add_node(func)
        graph.add_node(vuln)
        
        graph.add_edge(GraphEdge("C", "F", "contains"))
        graph.add_edge(GraphEdge("F", "V", "triggers"))
        
        paths = trace_attack_paths(graph)
        
        # Should find path to vulnerability
        assert len(paths) > 0
        # Check that vulnerability is in one of the paths
        vuln_in_path = any("V" in path for path in paths)
        assert vuln_in_path

    def test_trace_empty_graph(self):
        """Test tracing on empty graph."""
        graph = AttackGraph()
        
        paths = trace_attack_paths(graph)
        
        assert paths == []


# =============================================================================
# export_graph_json Tests
# =============================================================================

class TestExportGraphJson:
    """Test export_graph_json function."""

    def test_export_structure(self):
        """Test exported JSON structure."""
        graph = AttackGraph()
        
        node = GraphNode(
            id="test",
            type="Vulnerability",
            name="REENTRANCY",
            metadata={"severity": "CRITICAL"}
        )
        graph.add_node(node)
        
        edge = GraphEdge("src", "dst", "triggers")
        graph.add_edge(edge)
        
        result = export_graph_json(graph)
        
        assert "nodes" in result
        assert "links" in result
        assert "metadata" in result
        assert result["metadata"]["node_count"] == 1
        assert result["metadata"]["edge_count"] == 1

    def test_export_node_format(self):
        """Test node format in exported JSON."""
        graph = AttackGraph()
        
        node = GraphNode(
            id="Vuln_1",
            type="Vulnerability",
            name="REENTRANCY",
            metadata={"severity": "CRITICAL", "file": "test.sol"}
        )
        graph.add_node(node)
        
        result = export_graph_json(graph)
        
        exported_node = result["nodes"][0]
        assert exported_node["id"] == "Vuln_1"
        assert exported_node["type"] == "Vulnerability"
        assert exported_node["name"] == "REENTRANCY"
        assert exported_node["severity"] == "CRITICAL"
        assert "size" in exported_node  # Size based on severity

    def test_export_vulnerability_size(self):
        """Test that vulnerabilities have size based on severity."""
        graph = AttackGraph()
        
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for i, sev in enumerate(severities):
            node = GraphNode(
                id=f"V{i}",
                type="Vulnerability",
                name=f"Vuln{i}",
                metadata={"severity": sev}
            )
            graph.add_node(node)
        
        result = export_graph_json(graph)
        
        # Critical should have largest size
        critical_node = next(n for n in result["nodes"]
                             if n["severity"] == "CRITICAL")
        info_node = next(n for n in result["nodes"]
                         if n["severity"] == "INFO")
        assert critical_node["size"] > info_node["size"]

    def test_export_link_format(self):
        """Test link format in exported JSON."""
        graph = AttackGraph()
        
        edge = GraphEdge("src", "dst", "calls", {"meta": "data"})
        graph.add_edge(edge)
        
        result = export_graph_json(graph)
        
        exported_link = result["links"][0]
        assert exported_link["source"] == "src"
        assert exported_link["target"] == "dst"
        assert exported_link["type"] == "calls"


# =============================================================================
# get_attack_path_summary Tests
# =============================================================================

class TestGetAttackPathSummary:
    """Test get_attack_path_summary function."""

    def test_summary_structure(self):
        """Test summary dictionary structure."""
        graph = AttackGraph()
        
        vuln = GraphNode(
            id="V1",
            type="Vulnerability",
            name="REENTRANCY",
            metadata={"severity": "CRITICAL"}
        )
        graph.add_node(vuln)
        
        summary = get_attack_path_summary(graph)
        
        assert "total_paths" in summary
        assert "vulnerability_count" in summary
        assert "critical_vulnerabilities" in summary
        assert "high_vulnerabilities" in summary
        assert "contract_count" in summary
        assert "function_count" in summary

    def test_summary_counts(self):
        """Test summary counts are correct."""
        graph = AttackGraph()
        
        # Add various node types
        graph.add_node(GraphNode(id="C1", type="Contract", name="C1"))
        graph.add_node(GraphNode(id="F1", type="Function", name="F1"))
        graph.add_node(GraphNode(
            id="V1",
            type="Vulnerability",
            name="V1",
            metadata={"severity": "CRITICAL"}
        ))
        graph.add_node(GraphNode(
            id="V2",
            type="Vulnerability",
            name="V2",
            metadata={"severity": "HIGH"}
        ))
        
        summary = get_attack_path_summary(graph)
        
        assert summary["vulnerability_count"] == 2
        assert summary["critical_vulnerabilities"] == 1
        assert summary["high_vulnerabilities"] == 1
        assert summary["contract_count"] == 1
        assert summary["function_count"] == 1


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestGenerateNodeId:
    """Test _generate_node_id function."""

    def test_basic_id(self):
        """Test basic node ID generation."""
        node_id = _generate_node_id("Contract", "Vault")
        assert node_id == "Contract_Vault"

    def test_id_with_file(self):
        """Test ID generation with file path."""
        node_id = _generate_node_id("Contract", "Vault", "contracts/Vault.sol")
        assert "Contract_Vault" in node_id
        # File path is hashed to a 4-digit number, not included directly
        assert len(node_id) > len("Contract_Vault")
        # Should have a hash suffix (4 digits)
        parts = node_id.split("_")
        assert len(parts) >= 3
        assert parts[2].isdigit() or len(parts[2]) == 4

    def test_id_with_line(self):
        """Test ID generation with line number."""
        node_id = _generate_node_id("Function", "withdraw",
                                    "Vault.sol", 45)
        assert "Function_withdraw" in node_id
        assert "L45" in node_id


class TestParseSolidityFile:
    """Test _parse_solidity_file function."""

    def test_parse_contract(self, tmp_path):
        """Test parsing contract definition."""
        sol_file = tmp_path / "Test.sol"
        sol_content = """
contract TestContract {
    uint256 public value;
}
"""
        sol_file.write_text(sol_content)
        
        result = _parse_solidity_file(str(sol_file))
        
        assert len(result["contracts"]) == 1
        assert result["contracts"][0]["name"] == "TestContract"

    def test_parse_functions(self, tmp_path):
        """Test parsing function definitions."""
        sol_file = tmp_path / "Test.sol"
        sol_content = """
contract Test {
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function getValue() public view returns (uint256) {
        return value;
    }
}
"""
        sol_file.write_text(sol_content)
        
        result = _parse_solidity_file(str(sol_file))
        
        assert len(result["functions"]) >= 2

    def test_parse_external_calls(self, tmp_path):
        """Test parsing external calls."""
        sol_file = tmp_path / "Test.sol"
        sol_content = """
contract Test {
    function withdraw() external {
        (bool success, ) = msg.sender.call{value: 1 ether}("");
    }
}
"""
        sol_file.write_text(sol_content)
        
        result = _parse_solidity_file(str(sol_file))
        
        assert len(result["external_calls"]) >= 1

    def test_parse_missing_file(self):
        """Test parsing non-existent file."""
        result = _parse_solidity_file("/nonexistent/file.sol")
        assert result == {}


class TestParseRustFile:
    """Test _parse_rust_file function."""

    def test_parse_program(self, tmp_path):
        """Test parsing Anchor program."""
        rs_file = tmp_path / "lib.rs"
        rs_content = """
use anchor_lang::prelude::*;

#[program]
pub mod my_program {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}
"""
        rs_file.write_text(rs_content)
        
        result = _parse_rust_file(str(rs_file))
        
        assert len(result["programs"]) == 1

    def test_parse_functions(self, tmp_path):
        """Test parsing public functions."""
        rs_file = tmp_path / "lib.rs"
        rs_content = """
pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
    Ok(())
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    Ok(())
}
"""
        rs_file.write_text(rs_content)
        
        result = _parse_rust_file(str(rs_file))
        
        assert len(result["functions"]) == 2

    def test_parse_cpi_calls(self, tmp_path):
        """Test parsing CPI calls."""
        rs_file = tmp_path / "lib.rs"
        rs_content = """
token::transfer(cpi_ctx, amount)?;
invoke_signed(
    instruction,
    accounts,
    signer_seeds
)?;
"""
        rs_file.write_text(rs_content)
        
        result = _parse_rust_file(str(rs_file))
        
        # Should detect invoke_signed
        assert len(result["cpi_calls"]) >= 1

    def test_parse_missing_file(self):
        """Test parsing non-existent file."""
        result = _parse_rust_file("/nonexistent/file.rs")
        assert result == {}


# =============================================================================
# Cross-contract Edge Detection Tests
# =============================================================================

class TestCrossContractEdges:
    """Test cross-contract edge detection."""

    def test_external_call_edge(self):
        """Test that external calls create edges between contracts."""
        graph = AttackGraph()
        
        # Function in Contract A calls external contract B
        func_a = GraphNode(id="Func_A", type="Function", name="transfer")
        ext_call = GraphNode(id="Ext_B", type="ExternalCall",
                             name="B.transfer()")
        
        graph.add_node(func_a)
        graph.add_node(ext_call)
        graph.add_edge(GraphEdge("Func_A", "Ext_B", "calls"))
        
        # Verify edge exists
        edges = graph.get_outgoing_edges("Func_A")
        assert len(edges) == 1
        assert edges[0].type == "calls"

    def test_delegatecall_edge(self):
        """Test that delegatecall creates delegate edges."""
        graph = AttackGraph()
        
        func = GraphNode(id="Func", type="Function", name="upgrade")
        ext_call = GraphNode(id="Ext", type="ExternalCall",
                             name="impl.delegatecall()")
        
        graph.add_node(func)
        graph.add_node(ext_call)
        graph.add_edge(GraphEdge("Func", "Ext", "delegates"))
        
        edges = graph.get_outgoing_edges("Func")
        assert edges[0].type == "delegates"
