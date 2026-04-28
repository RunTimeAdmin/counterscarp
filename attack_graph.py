#!/usr/bin/env python3
"""
Attack Graph Construction Engine for Counterscarp Engine.

Provides graph-based analysis of smart contract vulnerabilities, enabling
visualization of attack paths across contracts and functions.

Example:
    >>> from attack_graph import build_graph, export_graph_json
    >>> findings = [{"rule_id": "REENTRANCY", "severity": "HIGH", ...}]
    >>> graph = build_graph(findings, source_files=["contracts/Token.sol"])
    >>> json_data = export_graph_json(graph)
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from pathlib import Path

from logger import get_logger
from exceptions import CounterscarpAnalysisError

logger = get_logger(__name__)


@dataclass
class GraphNode:
    """Represents a node in the attack graph.

    Attributes:
        id: Unique identifier for the node.
        type: Node type (Contract/Function/Vulnerability/
            ExternalCall/StateVariable).
        name: Human-readable name of the node.
        metadata: Additional context and properties.
    """
    id: str
    type: str  # Contract, Function, Vulnerability, ExternalCall, StateVariable
    name: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate node type."""
        valid_types = {
            "Contract", "Function", "Vulnerability",
            "ExternalCall", "StateVariable"
        }
        if self.type not in valid_types:
            raise ValueError(
                f"Invalid node type: {self.type}. "
                f"Must be one of {valid_types}"
            )


@dataclass
class GraphEdge:
    """Represents an edge in the attack graph.

    Attributes:
        source_id: ID of the source node.
        target_id: ID of the target node.
        type: Edge type (calls/reads/writes/delegates/inherits).
        metadata: Additional context and properties.
    """
    source_id: str
    target_id: str
    type: str  # calls, reads, writes, delegates, inherits
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate edge type."""
        valid_types = {
            "calls", "reads", "writes", "delegates",
            "inherits", "contains", "triggers"
        }
        if self.type not in valid_types:
            raise ValueError(
                f"Invalid edge type: {self.type}. "
                f"Must be one of {valid_types}"
            )


@dataclass
class AttackGraph:
    """Complete attack graph structure.

    Attributes:
        nodes: List of all nodes in the graph.
        edges: List of all edges in the graph.
    """
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    _node_ids: Set[str] = field(default_factory=set, repr=False)
    _edge_keys: Set[tuple] = field(default_factory=set, repr=False)
    _adj: Dict[str, Set[str]] = field(
        default_factory=dict, repr=False
    )

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph if it doesn't already exist.

        Args:
            node: The node to add.
        """
        if node.id not in self._node_ids:
            self.nodes.append(node)
            self._node_ids.add(node.id)
            logger.debug(f"Added node: {node.id} ({node.type})")

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph if it doesn't already exist.

        Args:
            edge: The edge to add.
        """
        key = (edge.source_id, edge.target_id, edge.type)
        if key not in self._edge_keys:
            self.edges.append(edge)
            self._edge_keys.add(key)
            self._adj.setdefault(
                edge.source_id, set()
            ).add(edge.target_id)
            self._adj.setdefault(
                edge.target_id, set()
            ).add(edge.source_id)
            logger.debug(
                f"Added edge: {edge.source_id} -> "
                f"{edge.target_id} ({edge.type})"
            )

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by its ID.

        Args:
            node_id: The ID of the node to retrieve.

        Returns:
            The node if found, None otherwise.
        """
        if node_id not in self._node_ids:
            return None
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_nodes_by_type(self, node_type: str) -> List[GraphNode]:
        """Get all nodes of a specific type.

        Args:
            node_type: The type of nodes to retrieve.

        Returns:
            List of nodes matching the type.
        """
        return [n for n in self.nodes if n.type == node_type]

    def get_outgoing_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges originating from a node.

        Args:
            node_id: The ID of the source node.

        Returns:
            List of outgoing edges.
        """
        return [e for e in self.edges if e.source_id == node_id]

    def get_incoming_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges targeting a node.

        Args:
            node_id: The ID of the target node.

        Returns:
            List of incoming edges.
        """
        return [e for e in self.edges if e.target_id == node_id]

    def get_neighbors(self, node_id: str) -> List[str]:
        """Get all neighboring node IDs.

        Args:
            node_id: The ID of the node.

        Returns:
            List of neighboring node IDs.
        """
        return list(self._adj.get(node_id, set()))


# Regex patterns for Solidity parsing
CONTRACT_PATTERN = re.compile(
    r"contract\s+(\w+)\s*(?:is\s+([^{]+))?\s*\{",
    re.MULTILINE
)

FUNCTION_PATTERN = re.compile(
    r"function\s+(\w+)\s*\([^)]*\)\s*(.*?)(?:\{|;)",
    re.MULTILINE | re.DOTALL
)

EXTERNAL_CALL_PATTERN = re.compile(
    r"(\w+)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*[\{\(]",
    re.MULTILINE
)

STATE_READ_PATTERN = re.compile(
    r"\b(\w+)\b(?=\s*[^=]*[^=!><]=(?!=))",
    re.MULTILINE
)

STATE_WRITE_PATTERN = re.compile(
    r"\b(\w+)\s*=[^=]",
    re.MULTILINE
)

INHERITANCE_PATTERN = re.compile(
    r"contract\s+\w+\s+is\s+([^\{]+)",
    re.MULTILINE
)

CPI_PATTERN = re.compile(
    r"(invoke|invoke_signed)\s*\(",
    re.MULTILINE
)

SOLANA_ACCOUNT_PATTERN = re.compile(
    r"Account\s*<\s*(\w+)\s*>",
    re.MULTILINE
)


def _generate_node_id(
    node_type: str, name: str, file: str = "", line: int = 0
) -> str:
    """Generate a unique node ID.

    Args:
        node_type: Type of the node.
        name: Name of the node.
        file: Optional file path.
        line: Optional line number.

    Returns:
        Unique node ID string.
    """
    base = f"{node_type}_{name}"
    if file:
        file_hash = hashlib.sha256(file.encode()).hexdigest()[:4]
        base += f"_{file_hash}"
    if line > 0:
        base += f"_L{line}"
    return base


def _parse_solidity_file(file_path: str) -> Dict[str, Any]:
    """Parse a Solidity file to extract contract structure.

    Args:
        file_path: Path to the Solidity file.

    Returns:
        Dictionary containing parsed contract information.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except (IOError, OSError) as e:
        logger.warning(f"Could not read file {file_path}: {e}")
        return {}

    result: Dict[str, Any] = {
        'contracts': [],
        'functions': [],
        'external_calls': [],
        'state_reads': [],
        'state_writes': [],
        'inheritance': []
    }

    # Extract contracts
    for match in CONTRACT_PATTERN.finditer(content):
        contract_name = match.group(1)
        inheritance = match.group(2)
        result['contracts'].append({
            'name': contract_name,
            'line': content[:match.start()].count('\n') + 1,
            'inheritance': [
                i.strip() for i in inheritance.split(',')
            ] if inheritance else []
        })

    # Extract functions
    for match in FUNCTION_PATTERN.finditer(content):
        func_name = match.group(1)
        modifiers = match.group(2)
        line_no = content[:match.start()].count('\n') + 1
        
        # Determine visibility
        visibility = 'internal'
        if 'public' in modifiers:
            visibility = 'public'
        elif 'external' in modifiers:
            visibility = 'external'
        elif 'private' in modifiers:
            visibility = 'private'

        result['functions'].append({
            'name': func_name,
            'line': line_no,
            'visibility': visibility,
            'modifiers': modifiers.strip() if modifiers else ''
        })

    # Extract external calls
    for match in EXTERNAL_CALL_PATTERN.finditer(content):
        target = match.group(1)
        call_type = match.group(2)
        line_no = content[:match.start()].count('\n') + 1
        
        result['external_calls'].append({
            'target': target,
            'call_type': call_type,
            'line': line_no
        })

    # Extract state variable reads and writes (simplified)
    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        # Skip comments
        clean_line = re.sub(r'//.*', '', line)
        
        # State writes (assignment)
        for match in STATE_WRITE_PATTERN.finditer(clean_line):
            var_name = match.group(1)
            if var_name not in [
                'return', 'if', 'for', 'while', 'require', 'assert'
            ]:
                result['state_writes'].append({
                    'variable': var_name,
                    'line': i
                })

    return result


def _parse_rust_file(file_path: str) -> Dict[str, Any]:
    """Parse a Rust file (Solana/Anchor) to extract program structure.

    Args:
        file_path: Path to the Rust file.

    Returns:
        Dictionary containing parsed program information.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except (IOError, OSError) as e:
        logger.warning(f"Could not read file {file_path}: {e}")
        return {}

    result: Dict[str, Any] = {
        'programs': [],
        'functions': [],
        'cpi_calls': [],
        'accounts': []
    }

    # Extract Anchor programs
    program_pattern = re.compile(r"#\[program\]", re.MULTILINE)

    for match in program_pattern.finditer(content):
        # Find the module containing this program
        line_no = content[:match.start()].count('\n') + 1
        result['programs'].append({
            'line': line_no,
            'type': 'anchor_program'
        })

    # Extract functions (pub fn)
    fn_pattern = re.compile(r"pub\s+fn\s+(\w+)\s*\(", re.MULTILINE)
    for match in fn_pattern.finditer(content):
        func_name = match.group(1)
        line_no = content[:match.start()].count('\n') + 1
        result['functions'].append({
            'name': func_name,
            'line': line_no,
            'visibility': 'public'
        })

    # Extract CPI calls
    for match in CPI_PATTERN.finditer(content):
        cpi_type = match.group(1)
        line_no = content[:match.start()].count('\n') + 1
        result['cpi_calls'].append({
            'type': cpi_type,
            'line': line_no
        })

    # Extract account types
    for match in SOLANA_ACCOUNT_PATTERN.finditer(content):
        account_type = match.group(1)
        line_no = content[:match.start()].count('\n') + 1
        result['accounts'].append({
            'type': account_type,
            'line': line_no
        })

    return result


def build_graph(
    findings: List[Dict[str, Any]],
    source_files: Optional[List[str]] = None
) -> AttackGraph:
    """Build an attack graph from findings and optional source files.

    Parses findings to create Vulnerability nodes and optionally analyzes
    source files to extract contract structure, functions, external calls,
    and state variable access patterns.

    Args:
        findings: List of finding dictionaries with rule_id, severity,
            file, line_no, etc.
        source_files: Optional list of source file paths to analyze.

    Returns:
        Constructed AttackGraph with nodes and edges.

    Raises:
        CounterscarpAnalysisError: If graph construction fails.

    Example:
        >>> findings = [
        ...     {
        ...         "rule_id": "REENTRANCY",
        ...         "severity": "HIGH",
        ...         "file": "contracts/Token.sol",
        ...         "line_no": 42,
        ...         "message": "Reentrancy vulnerability detected"
        ...     }
        ... ]
        >>> graph = build_graph(findings, ["contracts/Token.sol"])
    """
    try:
        graph = AttackGraph()
        contract_nodes: Dict[str, str] = {}  # contract_name -> node_id
        function_nodes: Dict[str, str] = {}  # function_key -> node_id

        # Process findings first to create vulnerability nodes
        for finding in findings:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            severity = finding.get('severity', 'MEDIUM')
            file_path = finding.get('file', '')
            line_no = finding.get('line_no', 0)
            message = finding.get('message', finding.get('description', ''))

            # Create vulnerability node
            vuln_id = _generate_node_id(
                'Vulnerability', 
                rule_id, 
                file_path, 
                line_no
            )
            
            vuln_node = GraphNode(
                id=vuln_id,
                type='Vulnerability',
                name=rule_id,
                metadata={
                    'severity': severity,
                    'file': file_path,
                    'line': line_no,
                    'description': message,
                    'rule_id': rule_id
                }
            )
            graph.add_node(vuln_node)

        # Process source files if provided
        if source_files:
            for file_path in source_files:
                if not os.path.exists(file_path):
                    logger.warning(f"Source file not found: {file_path}")
                    continue

                # Determine file type and parse accordingly
                if file_path.endswith('.sol'):
                    parsed = _parse_solidity_file(file_path)
                    _process_solidity_parsed(graph, parsed, file_path, contract_nodes, function_nodes)
                elif file_path.endswith('.rs'):
                    parsed = _parse_rust_file(file_path)
                    _process_rust_parsed(graph, parsed, file_path, contract_nodes, function_nodes)
                else:
                    logger.debug(f"Unsupported file type: {file_path}")

        logger.info(f"Built attack graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges")
        return graph

    except Exception as e:
        logger.error(f"Failed to build attack graph: {e}")
        raise CounterscarpAnalysisError(
            "Failed to build attack graph",
            details={"error": str(e), "finding_count": len(findings)}
        ) from e


def _process_solidity_parsed(
    graph: AttackGraph,
    parsed: Dict[str, Any],
    file_path: str,
    contract_nodes: Dict[str, str],
    function_nodes: Dict[str, str]
) -> None:
    """Process parsed Solidity data and add to graph.

    Args:
        graph: The attack graph to populate.
        parsed: Parsed Solidity data.
        file_path: Path to the source file.
        contract_nodes: Mapping of contract names to node IDs.
        function_nodes: Mapping of function keys to node IDs.
    """
    # Add contract nodes
    for contract in parsed.get('contracts', []):
        contract_name = contract['name']
        contract_id = _generate_node_id('Contract', contract_name, file_path)
        
        contract_node = GraphNode(
            id=contract_id,
            type='Contract',
            name=contract_name,
            metadata={
                'file': file_path,
                'line': contract['line'],
                'language': 'solidity'
            }
        )
        graph.add_node(contract_node)
        contract_nodes[contract_name] = contract_id

        # Add inheritance edges
        for parent in contract.get('inheritance', []):
            if parent:
                parent_id = _generate_node_id('Contract', parent, file_path)
                # Add parent contract node if not exists
                if not graph.get_node(parent_id):
                    graph.add_node(GraphNode(
                        id=parent_id,
                        type='Contract',
                        name=parent,
                        metadata={'inherited': True, 'language': 'solidity'}
                    ))
                
                graph.add_edge(GraphEdge(
                    source_id=contract_id,
                    target_id=parent_id,
                    type='inherits',
                    metadata={'file': file_path}
                ))

    # Add function nodes and link to contracts
    for func in parsed.get('functions', []):
        func_name = func['name']
        func_id = _generate_node_id('Function', func_name, file_path, func['line'])
        func_key = f"{file_path}:{func_name}"
        
        func_node = GraphNode(
            id=func_id,
            type='Function',
            name=func_name,
            metadata={
                'file': file_path,
                'line': func['line'],
                'visibility': func['visibility'],
                'modifiers': func['modifiers'],
                'language': 'solidity'
            }
        )
        graph.add_node(func_node)
        function_nodes[func_key] = func_id

        # Link function to its contract (if we can determine it)
        for contract in parsed.get('contracts', []):
            linked_contract_id = contract_nodes.get(contract['name'])
            if linked_contract_id:
                graph.add_edge(GraphEdge(
                    source_id=linked_contract_id,
                    target_id=func_id,
                    type='contains',
                    metadata={'relationship': 'has_function'}
                ))

    # Add external call edges
    for call in parsed.get('external_calls', []):
        target = call['target']
        call_type = call['call_type']
        line_no = call['line']

        # Create external call node
        call_id = _generate_node_id('ExternalCall', f"{target}_{call_type}", file_path, line_no)
        call_node = GraphNode(
            id=call_id,
            type='ExternalCall',
            name=f"{target}.{call_type}()",
            metadata={
                'target': target,
                'call_type': call_type,
                'file': file_path,
                'line': line_no,
                'language': 'solidity'
            }
        )
        graph.add_node(call_node)

        # Link to nearest function (simplified)
        for func in parsed.get('functions', []):
            if func['line'] <= line_no:
                func_key = f"{file_path}:{func['name']}"
                linked_func_id = function_nodes.get(func_key)
                if linked_func_id:
                    edge_type = 'delegates' if call_type == 'delegatecall' else 'calls'
                    graph.add_edge(GraphEdge(
                        source_id=linked_func_id,
                        target_id=call_id,
                        type=edge_type,
                        metadata={'call_type': call_type}
                    ))

    # Link vulnerabilities to functions based on line numbers
    for node in graph.nodes:
        if node.type == 'Vulnerability':
            vuln_file = node.metadata.get('file', '')
            vuln_line = node.metadata.get('line', 0)
            
            # Find containing function
            if vuln_file == file_path:
                for func in parsed.get('functions', []):
                    func_key = f"{file_path}:{func['name']}"
                    vuln_func_id = function_nodes.get(func_key)
                    if vuln_func_id and func['line'] <= vuln_line:
                        graph.add_edge(GraphEdge(
                            source_id=vuln_func_id,
                            target_id=node.id,
                            type='triggers',
                            metadata={'relationship': 'vulnerability_in_function'}
                        ))


def _process_rust_parsed(
    graph: AttackGraph,
    parsed: Dict[str, Any],
    file_path: str,
    contract_nodes: Dict[str, str],
    function_nodes: Dict[str, str]
) -> None:
    """Process parsed Rust (Solana) data and add to graph.

    Args:
        graph: The attack graph to populate.
        parsed: Parsed Rust data.
        file_path: Path to the source file.
        contract_nodes: Mapping of program names to node IDs.
        function_nodes: Mapping of function keys to node IDs.
    """
    # Add program nodes (similar to contracts)
    for program in parsed.get('programs', []):
        program_name = Path(file_path).stem
        program_id = _generate_node_id('Contract', program_name, file_path)
        
        program_node = GraphNode(
            id=program_id,
            type='Contract',
            name=program_name,
            metadata={
                'file': file_path,
                'line': program['line'],
                'language': 'rust',
                'platform': 'solana'
            }
        )
        graph.add_node(program_node)
        contract_nodes[program_name] = program_id

    # Add function nodes
    for func in parsed.get('functions', []):
        func_name = func['name']
        func_id = _generate_node_id('Function', func_name, file_path, func['line'])
        func_key = f"{file_path}:{func_name}"
        
        func_node = GraphNode(
            id=func_id,
            type='Function',
            name=func_name,
            metadata={
                'file': file_path,
                'line': func['line'],
                'visibility': func['visibility'],
                'language': 'rust',
                'platform': 'solana'
            }
        )
        graph.add_node(func_node)
        function_nodes[func_key] = func_id

        # Link to program
        program_name = Path(file_path).stem
        linked_program_id = contract_nodes.get(program_name)
        if linked_program_id:
            graph.add_edge(GraphEdge(
                source_id=linked_program_id,
                target_id=func_id,
                type='contains',
                metadata={'relationship': 'has_function'}
            ))

    # Add CPI call edges
    for cpi in parsed.get('cpi_calls', []):
        cpi_type = cpi['type']
        line_no = cpi['line']

        cpi_id = _generate_node_id('ExternalCall', cpi_type, file_path, line_no)
        cpi_node = GraphNode(
            id=cpi_id,
            type='ExternalCall',
            name=f"{cpi_type}()",
            metadata={
                'call_type': cpi_type,
                'file': file_path,
                'line': line_no,
                'language': 'rust',
                'platform': 'solana',
                'is_cpi': True
            }
        )
        graph.add_node(cpi_node)

        # Link to nearest function
        for func in parsed.get('functions', []):
            if func['line'] <= line_no:
                func_key = f"{file_path}:{func['name']}"
                cpi_func_id = function_nodes.get(func_key)
                if cpi_func_id:
                    graph.add_edge(GraphEdge(
                        source_id=cpi_func_id,
                        target_id=cpi_id,
                        type='calls',
                        metadata={'call_type': cpi_type, 'is_cpi': True}
                    ))


def trace_attack_paths(graph: AttackGraph) -> List[List[str]]:
    """Trace potential attack paths through the graph.

    Starting from each vulnerability node, trace paths through external
    calls to identify how an attacker could chain vulnerabilities across
    contract boundaries.

    Args:
        graph: The attack graph to analyze.

    Returns:
        List of attack paths, where each path is a list of node IDs
        showing the sequence from entry point to vulnerability.

    Example:
        >>> graph = build_graph(findings, source_files)
        >>> paths = trace_attack_paths(graph)
        >>> for path in paths:
        ...     print(" -> ".join(path))
    """
    paths: List[List[str]] = []
    visited: Set[str] = set()

    def dfs(current_id: str, path: List[str], depth: int = 0) -> None:
        """Depth-first search to trace paths."""
        if depth > 10:  # Limit recursion depth
            return
        
        if current_id in visited:
            return

        path.append(current_id)
        current_node = graph.get_node(current_id)
        
        if not current_node:
            return

        # If we reached a vulnerability, record the path
        if current_node.type == 'Vulnerability':
            paths.append(path.copy())

        # Continue traversing through outgoing edges
        for edge in graph.get_outgoing_edges(current_id):
            if edge.type in {'calls', 'delegates'}:
                dfs(edge.target_id, path, depth + 1)
            elif edge.type == 'triggers' and current_node.type == 'Function':
                dfs(edge.target_id, path, depth + 1)

        path.pop()

    # Start DFS from each contract node
    for node in graph.nodes:
        if node.type == 'Contract':
            visited.clear()
            dfs(node.id, [])

    # Also start from external entry points (public/external functions)
    for node in graph.nodes:
        if node.type == 'Function':
            visibility = node.metadata.get('visibility', '')
            if visibility in {'public', 'external'}:
                visited.clear()
                dfs(node.id, [])

    logger.info(f"Found {len(paths)} potential attack paths")
    return paths


def export_graph_json(graph: AttackGraph) -> Dict[str, Any]:
    """Export the attack graph as D3.js-compatible JSON.

    Converts the graph structure to a format suitable for D3.js
    force-directed graph visualization.

    Args:
        graph: The attack graph to export.

    Returns:
        Dictionary with 'nodes' and 'links' keys in D3.js format.

    Example:
        >>> graph = build_graph(findings, source_files)
        >>> json_data = export_graph_json(graph)
        >>> import json
        >>> with open('graph.json', 'w') as f:
        ...     json.dump(json_data, f, indent=2)
    """
    nodes = []
    for node in graph.nodes:
        node_data: Dict[str, Any] = {
            'id': node.id,
            'type': node.type,
            'name': node.name,
        }
        # Add metadata
        node_data.update(node.metadata)
        
        # Add size based on severity for vulnerabilities
        if node.type == 'Vulnerability':
            severity = node.metadata.get('severity', 'MEDIUM')
            size_map = {'CRITICAL': 20, 'HIGH': 15, 'MEDIUM': 10, 'LOW': 8, 'INFO': 5}
            node_data['size'] = size_map.get(severity, 10)
        else:
            node_data['size'] = 10
        
        nodes.append(node_data)

    links = []
    for edge in graph.edges:
        link_data = {
            'source': edge.source_id,
            'target': edge.target_id,
            'type': edge.type,
        }
        link_data.update(edge.metadata)
        links.append(link_data)

    return {
        'nodes': nodes,
        'links': links,
        'metadata': {
            'node_count': len(nodes),
            'edge_count': len(links),
            'node_types': list(set(n.type for n in graph.nodes)),
            'edge_types': list(set(e.type for e in graph.edges))
        }
    }


def get_attack_path_summary(graph: AttackGraph) -> Dict[str, Any]:
    """Generate a summary of attack paths in the graph.

    Args:
        graph: The attack graph to analyze.

    Returns:
        Dictionary containing summary statistics.
    """
    paths = trace_attack_paths(graph)
    
    vuln_nodes = [n for n in graph.nodes if n.type == 'Vulnerability']
    critical_count = sum(1 for n in vuln_nodes if n.metadata.get('severity') == 'CRITICAL')
    high_count = sum(1 for n in vuln_nodes if n.metadata.get('severity') == 'HIGH')

    return {
        'total_paths': len(paths),
        'vulnerability_count': len(vuln_nodes),
        'critical_vulnerabilities': critical_count,
        'high_vulnerabilities': high_count,
        'contract_count': len([n for n in graph.nodes if n.type == 'Contract']),
        'function_count': len([n for n in graph.nodes if n.type == 'Function']),
        'external_call_count': len([n for n in graph.nodes if n.type == 'ExternalCall']),
        'longest_path_length': max(len(p) for p in paths) if paths else 0,
        'average_path_length': sum(len(p) for p in paths) / len(paths) if paths else 0
    }


if __name__ == "__main__":
    # Demo/test code
    print("Testing Attack Graph Construction\n")
    
    # Sample findings
    demo_findings = [
        {
            'rule_id': 'REENTRANCY',
            'severity': 'CRITICAL',
            'file': 'contracts/Vault.sol',
            'line_no': 42,
            'message': 'Reentrancy vulnerability in withdraw function'
        },
        {
            'rule_id': 'UNCHECKED_EXTERNAL_CALL',
            'severity': 'HIGH',
            'file': 'contracts/Vault.sol',
            'line_no': 45,
            'message': 'Unchecked low-level call'
        }
    ]
    
    # Build graph without source files
    graph = build_graph(demo_findings)
    
    print(f"Nodes: {len(graph.nodes)}")
    print(f"Edges: {len(graph.edges)}")
    
    for node in graph.nodes:
        print(f"  - {node.type}: {node.name} ({node.id})")
    
    # Export to JSON
    json_data = export_graph_json(graph)
    print(f"\nExported JSON has {json_data['metadata']['node_count']} nodes")
    print(f"Node types: {json_data['metadata']['node_types']}")
    
    # Get summary
    summary = get_attack_path_summary(graph)
    print(f"\nAttack Path Summary:")
    print(f"  Vulnerabilities: {summary['vulnerability_count']}")
    print(f"  Critical: {summary['critical_vulnerabilities']}")
    print(f"  High: {summary['high_vulnerabilities']}")
