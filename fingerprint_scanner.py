"""Protocol fingerprint similarity scanner for Solidity contracts.

This module provides functionality to scan Solidity contracts and compare them
against known protocol fingerprints to identify similar implementations and
assess inherited vulnerabilities.
"""

from __future__ import annotations

import logging
import os
import re
import argparse
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import CounterscarpAnalysisError, CounterscarpValidationError
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)
    CounterscarpAnalysisError = None  # type: ignore[assignment,misc]
    CounterscarpValidationError = None  # type: ignore[assignment,misc]

# Import protocol database
try:
    from protocol_db import (
        ProtocolFingerprint,
        get_default_fingerprints,
        load_fingerprint_db,
        load_community_signatures,
    )
    PROTOCOL_DB_AVAILABLE = True
except ImportError:
    PROTOCOL_DB_AVAILABLE = False

# Import config loader
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    CounterscarpConfig = None  # type: ignore[assignment,misc]

# Import fork-specific logic checks
try:
    from fork_logic_checks import run_fork_checks
    FORK_CHECKS_AVAILABLE = True
except ImportError:
    FORK_CHECKS_AVAILABLE = False
    run_fork_checks = None  # type: ignore[assignment]

# Initialize logger
logger: logging.Logger = get_logger(__name__)


@dataclass
class ContractFeatures:
    """Extracted features from a Solidity contract.

    Attributes:
        file_path: Path to the source file.
        function_signatures: List of function signatures found.
        event_signatures: List of event signatures found.
        inheritance_chain: List of inherited contracts/interfaces.
        imports: List of imported files.
        storage_variables: List of storage variable names.
        constants: Dictionary of constant name -> value.
        function_bodies: Dictionary of function name -> body text.
    """
    file_path: str
    function_signatures: List[str] = field(default_factory=list)
    event_signatures: List[str] = field(default_factory=list)
    inheritance_chain: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    storage_variables: List[str] = field(default_factory=list)
    constants: Dict[str, str] = field(default_factory=dict)
    function_bodies: Dict[str, str] = field(default_factory=dict)


def extract_function_signature(line: str) -> Optional[str]:
    """Extract function signature from a function definition line.

    Args:
        line: Line containing function definition.

    Returns:
        Function signature string or None if not found.
    """
    # Match function definition pattern
    match = re.search(
        r"function\s+(\w+)\s*\(([^)]*)\)",
        line
    )
    if not match:
        return None

    func_name = match.group(1)
    params_str = match.group(2)

    # Extract parameter types
    param_types = []
    if params_str.strip():
        # Split by comma, but handle nested types
        depth = 0
        current_param = ""
        for char in params_str:
            if char == '(' or char == '[':
                depth += 1
            elif char == ')' or char == ']':
                depth -= 1
            elif char == ',' and depth == 0:
                # Process current param
                param_type = extract_param_type(current_param.strip())
                if param_type:
                    param_types.append(param_type)
                current_param = ""
                continue
            current_param += char

        # Process last param
        if current_param.strip():
            param_type = extract_param_type(current_param.strip())
            if param_type:
                param_types.append(param_type)

    return f"{func_name}({','.join(param_types)})"


def extract_param_type(param: str) -> str:
    """Extract the type from a parameter declaration.

    Args:
        param: Parameter declaration string.

    Returns:
        Parameter type string.
    """
    # Remove memory, storage, calldata keywords
    param = re.sub(r'\b(memory|storage|calldata)\b', '', param)
    # Remove parameter name (last word)
    parts = param.strip().split()
    if len(parts) >= 2:
        # Return everything except the last part (parameter name)
        return ' '.join(parts[:-1]).strip()
    elif len(parts) == 1:
        # Only type provided
        return parts[0]
    return param.strip()


def extract_event_signature(line: str) -> Optional[str]:
    """Extract event signature from an event definition line.

    Args:
        line: Line containing event definition.

    Returns:
        Event signature string or None if not found.
    """
    match = re.search(
        r"event\s+(\w+)\s*\(([^)]*)\)",
        line
    )
    if not match:
        return None

    event_name = match.group(1)
    params_str = match.group(2)

    # Extract parameter types with indexed keyword
    param_types = []
    if params_str.strip():
        for param in params_str.split(','):
            param = param.strip()
            # Remove indexed keyword but keep it as part of type
            indexed = " indexed" if " indexed " in param or param.startswith("indexed ") else ""
            param = re.sub(r'\bindexed\b', '', param).strip()
            # Remove parameter name
            parts = param.split()
            if len(parts) >= 2:
                param_type = parts[0] + indexed
            elif len(parts) == 1:
                param_type = parts[0]
            else:
                continue
            param_types.append(param_type)

    return f"{event_name}({','.join(param_types)})"


def extract_contract_features(source_path: str) -> ContractFeatures:
    """Parse Solidity source to extract contract features.

    Args:
        source_path: Path to the Solidity source file.

    Returns:
        ContractFeatures object with extracted features.

    Raises:
        CounterscarpValidationError: If file cannot be read.
    """
    features = ContractFeatures(file_path=source_path)

    try:
        with open(source_path, "r", encoding="utf-8") as f:
            content = f.read()
            lines = content.split('\n')
    except (IOError, OSError) as e:
        error_msg = f"Failed to read contract file: {source_path}"
        logger.error(error_msg)
        if CounterscarpValidationError is not None:
            raise CounterscarpValidationError(error_msg, details={"path": source_path})
        raise

    # Track contract scope
    in_contract = False
    brace_depth = 0
    current_function = None
    function_body_lines: list[str] = []

    for line in lines:
        stripped = line.strip()

        # Skip comments
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            continue

        # Track imports
        import_match = re.search(r'import\s+(?:\{[^}]+\}\s+from\s+)?["\']([^"\']+)["\']', stripped)
        if import_match:
            features.imports.append(import_match.group(1))

        # Track contract definition and inheritance
        contract_match = re.search(
            r'contract\s+(\w+)(?:\s+is\s+([^\{]+))?',
            stripped
        )
        if contract_match:
            in_contract = True
            inheritance = contract_match.group(2)
            if inheritance:
                # Split by comma and clean up
                parents = [p.strip() for p in inheritance.split(',')]
                features.inheritance_chain.extend(parents)

        # Track interface implementation
        interface_match = re.search(r'\bis\s+(I\w+)', stripped)
        if interface_match:
            interface_name = interface_match.group(1)
            if interface_name not in features.inheritance_chain:
                features.inheritance_chain.append(interface_name)

        # Track storage variables
        storage_match = re.search(
            r'^(?!\s*//)\s*(uint\d*|int\d*|bool|address|string|bytes\d*|mapping\s*\[[^\]]+\]\s*\w+)\s+(public|private|internal)?\s*(\w+)\s*;',
            line
        )
        if storage_match:
            var_name = storage_match.group(3)
            if var_name:
                features.storage_variables.append(var_name)

        # Track constants
        constant_match = re.search(
            r'(\w+)\s+constant\s+(\w+)\s*=\s*([^;]+);',
            stripped
        )
        if constant_match:
            const_name = constant_match.group(2)
            const_value = constant_match.group(3).strip()
            features.constants[const_name] = const_value

        # Track function definitions
        func_sig = extract_function_signature(line)
        if func_sig:
            features.function_signatures.append(func_sig)
            # Start tracking function body
            func_match = re.search(r'function\s+(\w+)', line)
            if func_match:
                current_function = func_match.group(1)
                function_body_lines = []

        # Track event definitions
        event_sig = extract_event_signature(line)
        if event_sig:
            features.event_signatures.append(event_sig)

        # Track brace depth for function body extraction
        if current_function:
            brace_depth += line.count('{') - line.count('}')
            function_body_lines.append(line)

            if brace_depth == 0 and '{' in ''.join(function_body_lines):
                # End of function
                features.function_bodies[current_function] = '\n'.join(function_body_lines)
                current_function = None
                function_body_lines = []

    logger.debug(
        f"Extracted features from {source_path}: "
        f"{len(features.function_signatures)} functions, "
        f"{len(features.event_signatures)} events, "
        f"{len(features.inheritance_chain)} inheritance markers"
    )

    return features


def calculate_jaccard_similarity(set1: List[str], set2: List[str]) -> float:
    """Calculate Jaccard similarity between two sets.

    Args:
        set1: First list of strings.
        set2: Second list of strings.

    Returns:
        Jaccard similarity score (0.0 to 1.0).
    """
    if not set1 or not set2:
        return 0.0

    set1_lower = {s.lower() for s in set1}
    set2_lower = {s.lower() for s in set2}

    intersection = len(set1_lower & set2_lower)
    union = len(set1_lower | set2_lower)

    if union == 0:
        return 0.0

    return intersection / union


def calculate_partial_match_similarity(
    features_list: List[str],
    fingerprint_list: List[str]
) -> float:
    """Calculate similarity with partial matching for function signatures.

    Args:
        features_list: List of function/event signatures from contract.
        fingerprint_list: List of function/event signatures from fingerprint.

    Returns:
        Similarity score (0.0 to 1.0).
    """
    if not fingerprint_list:
        return 0.0

    matched = 0
    for fp_sig in fingerprint_list:
        fp_sig_lower = fp_sig.lower()
        # Extract function name from signature
        fp_name = fp_sig_lower.split('(')[0] if '(' in fp_sig_lower else fp_sig_lower

        for feat_sig in features_list:
            feat_sig_lower = feat_sig.lower()
            feat_name = feat_sig_lower.split('(')[0] if '(' in feat_sig_lower else feat_sig_lower

            # Match by name
            if fp_name == feat_name:
                matched += 1
                break

    return matched / len(fingerprint_list)


def calculate_similarity(
    features: ContractFeatures,
    fingerprint: ProtocolFingerprint
) -> Tuple[float, Dict[str, Any]]:
    """Calculate similarity score between contract features and fingerprint.

    Uses weighted scoring across all feature dimensions:
    - Function signature overlap: 35% weight
    - Event signature overlap: 20% weight
    - Inheritance/import match: 25% weight
    - Storage pattern match: 10% weight
    - Constant match: 10% weight

    Args:
        features: Extracted contract features.
        fingerprint: Protocol fingerprint to compare against.

    Returns:
        Tuple of (confidence score 0.0-1.0, match details dict).
    """
    # Function signature similarity (35%)
    func_similarity = calculate_partial_match_similarity(
        features.function_signatures,
        fingerprint.function_signatures
    )
    matched_functions = []
    for fp_sig in fingerprint.function_signatures:
        fp_name = fp_sig.split('(')[0] if '(' in fp_sig else fp_sig
        for feat_sig in features.function_signatures:
            feat_name = feat_sig.split('(')[0] if '(' in feat_sig else feat_sig
            if fp_name.lower() == feat_name.lower():
                matched_functions.append(fp_sig)
                break

    # Event signature similarity (20%)
    event_similarity = calculate_partial_match_similarity(
        features.event_signatures,
        fingerprint.event_signatures
    )
    matched_events = []
    for fp_event in fingerprint.event_signatures:
        fp_name = fp_event.split('(')[0] if '(' in fp_event else fp_event
        for feat_event in features.event_signatures:
            feat_name = feat_event.split('(')[0] if '(' in feat_event else feat_event
            if fp_name.lower() == feat_name.lower():
                matched_events.append(fp_event)
                break

    # Inheritance/import match (25%)
    inheritance_matches = []
    for marker in fingerprint.inheritance_markers:
        marker_lower = marker.lower()
        # Check inheritance chain
        for inherited in features.inheritance_chain:
            if marker_lower in inherited.lower() or inherited.lower() in marker_lower:
                inheritance_matches.append(marker)
                break
        # Check imports
        for imp in features.imports:
            if marker_lower in imp.lower():
                inheritance_matches.append(marker)
                break

    inheritance_similarity = len(inheritance_matches) / len(fingerprint.inheritance_markers) if fingerprint.inheritance_markers else 0.0

    # Storage pattern match (10%)
    storage_matches = []
    for pattern in fingerprint.storage_patterns:
        pattern_regex = re.compile(pattern, re.IGNORECASE)
        for var in features.storage_variables:
            if pattern_regex.search(var):
                storage_matches.append(pattern)
                break

    storage_similarity = len(storage_matches) / len(fingerprint.storage_patterns) if fingerprint.storage_patterns else 0.0

    # Constant match (10%)
    constant_matches = []
    for const_name, const_value in fingerprint.constants.items():
        if const_name in features.constants:
            constant_matches.append(const_name)

    constant_similarity = len(constant_matches) / len(fingerprint.constants) if fingerprint.constants else 0.0

    # Calculate weighted score
    weights = {
        'function': 0.35,
        'event': 0.20,
        'inheritance': 0.25,
        'storage': 0.10,
        'constant': 0.10,
    }

    total_score = (
        func_similarity * weights['function'] +
        event_similarity * weights['event'] +
        inheritance_similarity * weights['inheritance'] +
        storage_similarity * weights['storage'] +
        constant_similarity * weights['constant']
    )

    match_details = {
        'matched_functions': matched_functions,
        'matched_events': matched_events,
        'matched_inheritance': inheritance_matches,
        'matched_storage': storage_matches,
        'matched_constants': constant_matches,
        'function_similarity': func_similarity,
        'event_similarity': event_similarity,
        'inheritance_similarity': inheritance_similarity,
        'storage_similarity': storage_similarity,
        'constant_similarity': constant_similarity,
    }

    return total_score, match_details


def assess_inherited_risk(matches: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate known vulnerabilities from matched protocols.

    Args:
        matches: List of match results from scan_for_protocol_similarity.

    Returns:
        Risk assessment dictionary with aggregated vulnerabilities and recommendations.
    """
    if not matches:
        return {
            'risk_score': 0.0,
            'risk_level': 'LOW',
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'all_vulnerabilities': [],
            'recommendations': [],
        }

    all_vulns = []
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    for match in matches:
        vulns = match.get('known_vulnerabilities', [])
        confidence = match.get('confidence', 0.0)

        for vuln in vulns:
            vuln_copy = vuln.copy()
            vuln_copy['source_protocol'] = match['protocol']
            vuln_copy['confidence'] = confidence
            all_vulns.append(vuln_copy)
            severity = vuln.get('severity', 'LOW')
            if severity in severity_counts:
                severity_counts[severity] += 1

    # Calculate risk score (0-100)
    # Weight by severity and confidence
    risk_score = (
        severity_counts['CRITICAL'] * 25 +
        severity_counts['HIGH'] * 10 +
        severity_counts['MEDIUM'] * 3 +
        severity_counts['LOW'] * 1
    ) * min(len(matches) * 0.2 + 0.6, 1.0)  # Factor in number of matches

    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score >= 50 or severity_counts['CRITICAL'] > 0:
        risk_level = 'CRITICAL'
    elif risk_score >= 30 or severity_counts['HIGH'] >= 2:
        risk_level = 'HIGH'
    elif risk_score >= 10 or severity_counts['HIGH'] > 0:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'

    # Generate recommendations
    recommendations = []

    if severity_counts['CRITICAL'] > 0:
        recommendations.append(
            f"URGENT: Address {severity_counts['CRITICAL']} critical inherited vulnerabilities immediately"
        )

    if any(v.get('id', '').startswith('UNI') for v in all_vulns):
        recommendations.append(
            "Review K invariant assumptions and price oracle implementations"
        )

    if any(v.get('id', '').startswith('AAVE') or v.get('id', '').startswith('COMP') for v in all_vulns):
        recommendations.append(
            "Audit flash loan protections and interest rate calculation accuracy"
        )

    if any(v.get('id', '').startswith('OZ') for v in all_vulns):
        recommendations.append(
            "Verify upgradeable proxy storage layout and initializer protections"
        )

    if any(v.get('id', '').startswith('CURVE') for v in all_vulns):
        recommendations.append(
            "Check for read-only reentrancy vulnerabilities in view functions"
        )

    if not recommendations:
        recommendations.append(
            "Standard security review recommended for identified protocol patterns"
        )

    return {
        'risk_score': round(risk_score, 2),
        'risk_level': risk_level,
        'total_vulnerabilities': len(all_vulns),
        'critical_count': severity_counts['CRITICAL'],
        'high_count': severity_counts['HIGH'],
        'medium_count': severity_counts['MEDIUM'],
        'low_count': severity_counts['LOW'],
        'all_vulnerabilities': all_vulns,
        'recommendations': recommendations,
    }


def scan_for_protocol_similarity(
    source_path: str,
    fingerprints: Optional[List[ProtocolFingerprint]] = None,
    min_similarity: float = 0.7
) -> List[Dict[str, Any]]:
    """Scan contract for protocol similarity.

    Args:
        source_path: Path to the Solidity contract file.
        fingerprints: Optional list of fingerprints to compare against.
            Uses defaults if None.
        min_similarity: Minimum similarity threshold (0.0-1.0).

    Returns:
        List of match results sorted by confidence.
    """
    if not PROTOCOL_DB_AVAILABLE:
        logger.error("Protocol database not available")
        return []

    # Load fingerprints
    if fingerprints is None:
        fingerprints = get_default_fingerprints()

    # Extract features from contract
    try:
        features = extract_contract_features(source_path)
    except Exception as e:
        logger.error(f"Failed to extract features from {source_path}: {e}")
        return []

    matches = []

    for fingerprint in fingerprints:
        confidence, details = calculate_similarity(features, fingerprint)

        if confidence >= min_similarity:
            # Determine risk assessment text
            vuln_count = len(fingerprint.known_vulnerabilities)
            if vuln_count > 0:
                high_crit = sum(
                    1 for v in fingerprint.known_vulnerabilities
                    if v.get('severity') in ['CRITICAL', 'HIGH']
                )
                if high_crit > 0:
                    risk_text = f"HIGH - This contract matches {fingerprint.name} with {vuln_count} known vulnerabilities ({high_crit} high/critical)"
                else:
                    risk_text = f"MEDIUM - This contract matches {fingerprint.name} with {vuln_count} known vulnerabilities"
            else:
                risk_text = f"LOW - This contract matches {fingerprint.name} with no known vulnerabilities"

            # Generate recommended checks
            recommended_checks = []
            for vuln in fingerprint.known_vulnerabilities:
                recommended_checks.append(
                    f"[{vuln['severity']}] {vuln['title']}: {vuln['description']}"
                )

            match_result = {
                'protocol': fingerprint.name,
                'category': fingerprint.category,
                'confidence': round(confidence, 3),
                'matched_functions': details['matched_functions'],
                'matched_events': details['matched_events'],
                'matched_inheritance': details['matched_inheritance'],
                'known_vulnerabilities': fingerprint.known_vulnerabilities,
                'risk_assessment': risk_text,
                'recommended_checks': recommended_checks[:5],  # Top 5
                'similarity_breakdown': {
                    'function': round(details['function_similarity'], 3),
                    'event': round(details['event_similarity'], 3),
                    'inheritance': round(details['inheritance_similarity'], 3),
                    'storage': round(details['storage_similarity'], 3),
                    'constant': round(details['constant_similarity'], 3),
                }
            }
            matches.append(match_result)

    # Sort by confidence descending
    matches.sort(key=lambda x: x['confidence'], reverse=True)

    return matches


def generate_fingerprint_report(
    results: List[Dict[str, Any]],
    output_path: Optional[str] = None
) -> str:
    """Generate Markdown report from fingerprint scan results.

    Args:
        results: List of match results from scan_for_protocol_similarity.
        output_path: Optional path to save the report.

    Returns:
        Markdown report string.
    """
    lines = []
    lines.append("# Protocol Fingerprint Analysis Report\n")
    lines.append(f"**Total Matches:** {len(results)}\n")

    if not results:
        lines.append("No protocol matches found above the similarity threshold.\n")
        report = '\n'.join(lines)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        return report

    # Risk assessment
    risk_assessment = assess_inherited_risk(results)
    lines.append("## Risk Assessment Summary\n")
    lines.append(f"- **Risk Level:** {risk_assessment['risk_level']}")
    lines.append(f"- **Risk Score:** {risk_assessment['risk_score']}/100")
    lines.append(f"- **Total Inherited Vulnerabilities:** {risk_assessment['total_vulnerabilities']}")
    lines.append(f"  - Critical: {risk_assessment['critical_count']}")
    lines.append(f"  - High: {risk_assessment['high_count']}")
    lines.append(f"  - Medium: {risk_assessment['medium_count']}")
    lines.append(f"  - Low: {risk_assessment['low_count']}")
    lines.append("")

    if risk_assessment['recommendations']:
        lines.append("### Recommendations\n")
        for rec in risk_assessment['recommendations']:
            lines.append(f"- {rec}")
        lines.append("")

    # Protocol matches
    lines.append("## Protocol Matches\n")

    for i, match in enumerate(results, 1):
        lines.append(f"### {i}. {match['protocol']} ({match['category']})\n")
        lines.append(f"- **Confidence:** {match['confidence'] * 100:.1f}%")
        lines.append(f"- **Risk Assessment:** {match['risk_assessment']}")
        lines.append("")

        # Similarity breakdown
        breakdown = match.get('similarity_breakdown', {})
        lines.append("**Similarity Breakdown:**")
        lines.append(f"- Function Signatures: {breakdown.get('function', 0) * 100:.1f}%")
        lines.append(f"- Event Signatures: {breakdown.get('event', 0) * 100:.1f}%")
        lines.append(f"- Inheritance Markers: {breakdown.get('inheritance', 0) * 100:.1f}%")
        lines.append(f"- Storage Patterns: {breakdown.get('storage', 0) * 100:.1f}%")
        lines.append(f"- Constants: {breakdown.get('constant', 0) * 100:.1f}%")
        lines.append("")

        if match['matched_functions']:
            lines.append(f"**Matched Functions ({len(match['matched_functions'])}):**")
            for func in match['matched_functions'][:5]:
                lines.append(f"- `{func}`")
            if len(match['matched_functions']) > 5:
                lines.append(f"- ... and {len(match['matched_functions']) - 5} more")
            lines.append("")

        if match['matched_events']:
            lines.append(f"**Matched Events ({len(match['matched_events'])}):**")
            for event in match['matched_events'][:3]:
                lines.append(f"- `{event}`")
            if len(match['matched_events']) > 3:
                lines.append(f"- ... and {len(match['matched_events']) - 3} more")
            lines.append("")

        if match['matched_inheritance']:
            lines.append(f"**Matched Inheritance:** {', '.join(match['matched_inheritance'])}")
            lines.append("")

        # Known vulnerabilities
        if match['known_vulnerabilities']:
            lines.append("**Known Vulnerabilities:**")
            for vuln in match['known_vulnerabilities']:
                lines.append(f"- **[{vuln['severity']}]** {vuln['title']}")
                lines.append(f"  - {vuln['description']}")
                lines.append(f"  - Reference: {vuln['reference_url']}")
            lines.append("")

        lines.append("---\n")

    report = '\n'.join(lines)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info(f"Report saved to {output_path}")

    return report


def scan_project(
    target_path: str,
    config: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """Scan all .sol files in target directory for protocol similarity.

    Args:
        target_path: Path to directory or .sol file to scan.
        config: Optional configuration dictionary with keys:
            - fingerprints: List of ProtocolFingerprint
            - min_similarity: float
            - database_path: str

    Returns:
        List of aggregated results per contract.
    """
    if not PROTOCOL_DB_AVAILABLE:
        logger.error("Protocol database not available")
        return []

    # Parse config
    cfg = config or {}
    min_similarity = cfg.get('min_similarity', 0.7)
    database_path = cfg.get('database_path')

    # Load fingerprints
    if 'fingerprints' in cfg:
        fingerprints = cfg['fingerprints']
    elif database_path and os.path.exists(database_path):
        fingerprints = load_fingerprint_db(database_path)
    else:
        fingerprints = get_default_fingerprints()

    # Extend with community-contributed signatures
    community_sigs = load_community_signatures()
    if community_sigs:
        fingerprints = list(fingerprints) + community_sigs
        logger.info(f"Loaded {len(community_sigs)} community protocol signature(s)")

    # Collect files to scan
    files_to_scan = []
    if os.path.isfile(target_path) and target_path.endswith('.sol'):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for filename in files:
                if filename.endswith('.sol'):
                    files_to_scan.append(os.path.join(root, filename))

    # Scan each file
    all_results = []
    for file_path in files_to_scan:
        logger.info(f"Scanning {file_path}...")
        matches = scan_for_protocol_similarity(
            file_path,
            fingerprints=fingerprints,
            min_similarity=min_similarity
        )

        if matches:
            # Run fork-specific logic checks for each matched protocol
            fork_findings = []
            if FORK_CHECKS_AVAILABLE and run_fork_checks is not None:
                try:
                    with open(file_path, "r", encoding="utf-8") as _f:
                        _source = _f.read()
                    for match in matches:
                        fork_findings.extend(
                            run_fork_checks(
                                _source,
                                match['protocol'],
                                file_path,
                            )
                        )
                    if fork_findings:
                        logger.info(
                            f"Fork checks: {len(fork_findings)} finding(s) "
                            f"in {file_path}"
                        )
                except Exception as _exc:
                    logger.warning(
                        f"Fork logic checks failed for {file_path}: {_exc}"
                    )

            all_results.append({
                'file': file_path,
                'matches': matches,
                'risk_assessment': assess_inherited_risk(matches),
                'fork_findings': fork_findings,
            })

    return all_results


def main() -> None:
    """Main entry point for the fingerprint scanner CLI."""
    parser = argparse.ArgumentParser(
        description="Protocol fingerprint similarity scanner for Solidity contracts"
    )
    parser.add_argument(
        "target",
        help="Path to a .sol file or directory containing Solidity files"
    )
    parser.add_argument(
        "--min-similarity",
        type=float,
        default=0.7,
        help="Minimum similarity threshold (0.0-1.0, default: 0.7)"
    )
    parser.add_argument(
        "--database",
        help="Path to custom fingerprint database JSON file"
    )
    parser.add_argument(
        "--output",
        help="Path to save the Markdown report"
    )
    parser.add_argument(
        "--config",
        help="Path to counterscarp.toml config file"
    )
    args = parser.parse_args()

    # Load config if available
    config = None
    if CONFIG_AVAILABLE and args.config:
        try:
            config = load_config(args.config)
            logger.info(f"Loaded config from {args.config}")
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")

    # Build scan config
    scan_config = {
        'min_similarity': args.min_similarity,
    }

    if args.database:
        scan_config['database_path'] = args.database
    elif config and hasattr(config, 'fingerprint'):
        scan_config['database_path'] = config.fingerprint.database_path

    # Run scan
    print(f"\n🔍 Scanning for protocol similarities (threshold: {args.min_similarity})...")
    results = scan_project(args.target, scan_config)

    # Generate report
    if results:
        print(f"\n✅ Found matches in {len(results)} file(s)")

        # Flatten matches for report
        all_matches = []
        for r in results:
            all_matches.extend(r['matches'])

        # Deduplicate by protocol
        seen_protocols = set()
        unique_matches = []
        for match in all_matches:
            if match['protocol'] not in seen_protocols:
                seen_protocols.add(match['protocol'])
                unique_matches.append(match)

        # Generate report
        report = generate_fingerprint_report(unique_matches, args.output)

        if not args.output:
            print("\n" + "=" * 60)
            print(report)
            print("=" * 60)
        else:
            print(f"\n📄 Report saved to: {args.output}")

        # Print summary
        risk = assess_inherited_risk(unique_matches)
        print(f"\n📊 Risk Summary:")
        print(f"   Level: {risk['risk_level']}")
        print(f"   Score: {risk['risk_score']}/100")
        print(f"   Vulnerabilities: {risk['total_vulnerabilities']} total")
        print(f"      - Critical: {risk['critical_count']}")
        print(f"      - High: {risk['high_count']}")
        print(f"      - Medium: {risk['medium_count']}")
        print(f"      - Low: {risk['low_count']}")
    else:
        print("\n✅ No protocol matches found above the similarity threshold.")


if __name__ == "__main__":
    main()
