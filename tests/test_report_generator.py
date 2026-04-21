"""
Tests for the report_generator module.
"""

import pytest
import sys
import os
import json
import tempfile
from datetime import datetime
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report_generator import (
    Finding,
    ReportSection,
    AuditReport,
    calculate_risk_score,
    get_pass_fail_status,
    enrich_finding,
    generate_html_report,
    generate_markdown_report,
    generate_sarif_report,
    save_sarif_report,
    create_audit_report,
    aggregate_findings_from_orchestrator,
    SEVERITY_WEIGHTS,
    SARIF_LEVEL_MAP,
)


@pytest.fixture
def mock_pro_license():
    """Fixture to mock pro license for HTML/SARIF report generation tests."""
    with patch('report_generator.LicenseManager') as mock_cls:
        mock_instance = mock_cls.return_value
        mock_instance.check_pro_feature.return_value = True
        yield


class TestCalculateRiskScore:
    """Test risk score calculation."""

    def test_empty_findings_returns_zero(self):
        """Test empty findings list returns 0 risk score."""
        score = calculate_risk_score([])
        assert score == 0.0

    def test_critical_finding_high_score(self):
        """Test critical findings produce high risk score."""
        findings = [
            Finding(
                rule_id="TEST",
                severity="CRITICAL",
                category="Test",
                title="Test",
                description="Test",
                file="test.sol",
                line_no=1
            )
        ]
        score = calculate_risk_score(findings)
        assert score == 100.0

    def test_mixed_severities_calculated_correctly(self):
        """Test mixed severity findings produce appropriate score."""
        findings = [
            Finding(rule_id="1", severity="HIGH", category="Test", title="T", description="D", file="t.sol", line_no=1),
            Finding(rule_id="2", severity="MEDIUM", category="Test", title="T", description="D", file="t.sol", line_no=2),
            Finding(rule_id="3", severity="LOW", category="Test", title="T", description="D", file="t.sol", line_no=3),
        ]
        score = calculate_risk_score(findings)
        # HIGH=5, MEDIUM=2, LOW=0.5, total=7.5, max_possible=30, score=25
        assert 0 < score < 100

    def test_info_findings_low_impact(self):
        """Test INFO findings have minimal impact on score."""
        findings = [
            Finding(rule_id="1", severity="INFO", category="Test", title="T", description="D", file="t.sol", line_no=1),
        ]
        score = calculate_risk_score(findings)
        assert score < 10  # INFO has very low weight


class TestGetPassFailStatus:
    """Test pass/fail status determination."""

    def test_critical_finding_fails(self):
        """Test any critical finding results in FAIL."""
        findings = [
            Finding(rule_id="1", severity="CRITICAL", category="Test", title="T", description="D", file="t.sol", line_no=1),
        ]
        status = get_pass_fail_status(findings)
        assert status == "FAIL"

    def test_many_high_findings_fails(self):
        """Test more than 3 high findings results in FAIL."""
        findings = [
            Finding(rule_id=f"{i}", severity="HIGH", category="Test", title="T", description="D", file="t.sol", line_no=i)
            for i in range(4)
        ]
        status = get_pass_fail_status(findings)
        assert status == "FAIL"

    def test_few_high_findings_warning(self):
        """Test 1-3 high findings results in WARNING."""
        findings = [
            Finding(rule_id="1", severity="HIGH", category="Test", title="T", description="D", file="t.sol", line_no=1),
        ]
        status = get_pass_fail_status(findings)
        assert status == "WARNING"

    def test_no_high_findings_pass(self):
        """Test no high/critical findings results in PASS."""
        findings = [
            Finding(rule_id="1", severity="MEDIUM", category="Test", title="T", description="D", file="t.sol", line_no=1),
            Finding(rule_id="2", severity="LOW", category="Test", title="T", description="D", file="t.sol", line_no=2),
        ]
        status = get_pass_fail_status(findings)
        assert status == "PASS"

    def test_empty_findings_pass(self):
        """Test empty findings results in PASS."""
        status = get_pass_fail_status([])
        assert status == "PASS"


class TestEnrichFinding:
    """Test finding enrichment with remediation."""

    def test_enrich_known_finding(self):
        """Test enrichment adds remediation for known finding types."""
        finding = Finding(
            rule_id="TX_ORIGIN_USAGE",
            severity="HIGH",
            category="Heuristic",
            title="Tx Origin Usage",
            description="Uses tx.origin",
            file="test.sol",
            line_no=1
        )
        
        enriched = enrich_finding(finding)
        
        assert enriched.remediation != ""
        assert len(enriched.references) > 0
        assert enriched.cwe is not None

    def test_enrich_unknown_finding_generic_remediation(self):
        """Test enrichment adds generic remediation for unknown types."""
        finding = Finding(
            rule_id="UNKNOWN_RULE",
            severity="MEDIUM",
            category="Test",
            title="Unknown",
            description="Unknown issue",
            file="test.sol",
            line_no=1
        )
        
        enriched = enrich_finding(finding)
        
        assert enriched.remediation != ""
        assert "Review" in enriched.remediation

    def test_enrich_preserves_existing_remediation(self):
        """Test enrichment preserves existing remediation."""
        finding = Finding(
            rule_id="TX_ORIGIN_USAGE",
            severity="HIGH",
            category="Heuristic",
            title="Tx Origin",
            description="Uses tx.origin",
            file="test.sol",
            line_no=1,
            remediation="Custom fix"
        )
        
        enriched = enrich_finding(finding)
        
        assert enriched.remediation == "Custom fix"


class TestGenerateHTMLReport:
    """Test HTML report generation."""

    def test_html_contains_expected_sections(self, tmp_path, mock_pro_license):
        """Test HTML report contains expected sections."""
        report = AuditReport(
            project_name="Test Project",
            target_path="./contracts",
            timestamp="2024-01-01 00:00:00",
            engine_version="3.4.0",
            executive_summary={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0},
            sections=[
                ReportSection(
                    title="Heuristic Analysis",
                    findings=[
                        Finding(
                            rule_id="TEST",
                            severity="CRITICAL",
                            category="Heuristic",
                            title="Test Finding",
                            description="Test description",
                            file="test.sol",
                            line_no=10,
                            code_snippet="code here",
                            remediation="Fix it"
                        )
                    ]
                )
            ],
            risk_score=75.0,
            pass_fail="FAIL"
        )
        
        output_path = str(tmp_path / "report.html")
        generate_html_report(report, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "Test Project" in content
        assert "Security Audit Report" in content
        assert "CRITICAL" in content
        assert "Test Finding" in content
        assert "code here" in content
        assert "Fix it" in content

    def test_html_risk_score_styling(self, tmp_path, mock_pro_license):
        """Test HTML includes risk score with appropriate styling."""
        report = AuditReport(
            project_name="Test",
            target_path="./",
            timestamp="2024-01-01",
            engine_version="3.4.0",
            executive_summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            sections=[],
            risk_score=25.0,
            pass_fail="PASS"
        )
        
        output_path = str(tmp_path / "report.html")
        generate_html_report(report, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "Risk Score:" in content
        assert "25" in content


class TestGenerateMarkdownReport:
    """Test Markdown report generation."""

    def test_markdown_contains_expected_sections(self, tmp_path):
        """Test Markdown report contains expected sections."""
        report = AuditReport(
            project_name="Test Project",
            target_path="./contracts",
            timestamp="2024-01-01 00:00:00",
            engine_version="3.4.0",
            executive_summary={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0},
            sections=[
                ReportSection(
                    title="Heuristic Analysis",
                    findings=[
                        Finding(
                            rule_id="TEST",
                            severity="HIGH",
                            category="Heuristic",
                            title="Test Finding",
                            description="Test description",
                            file="test.sol",
                            line_no=10,
                            code_snippet="function test() {}",
                            remediation="Fix it"
                        )
                    ]
                )
            ],
            risk_score=50.0,
            pass_fail="WARNING"
        )
        
        output_path = str(tmp_path / "report.md")
        generate_markdown_report(report, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "Test Project" in content
        assert "Security Audit Report" in content
        assert "HIGH" in content
        assert "Test Finding" in content
        assert "function test()" in content
        assert "Fix it" in content

    def test_markdown_severity_table(self, tmp_path):
        """Test Markdown includes severity count table."""
        report = AuditReport(
            project_name="Test",
            target_path="./",
            timestamp="2024-01-01",
            engine_version="3.4.0",
            executive_summary={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4},
            sections=[],
            risk_score=50.0,
            pass_fail="FAIL"
        )
        
        output_path = str(tmp_path / "report.md")
        generate_markdown_report(report, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "|" in content  # Table format
        assert "CRITICAL" in content
        assert "HIGH" in content


class TestGenerateSARIFReport:
    """Test SARIF report generation."""

    def test_sarif_valid_structure(self, mock_pro_license):
        """Test SARIF output has valid 2.1.0 structure."""
        findings = [
            Finding(
                rule_id="TEST_RULE",
                severity="HIGH",
                category="Heuristic",
                title="Test Finding",
                description="Test description",
                file="test.sol",
                line_no=10,
                code_snippet="code",
                remediation="Fix it",
                cwe="CWE-123"
            )
        ]
        
        sarif = generate_sarif_report(findings)
        
        assert sarif["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_info(self, mock_pro_license):
        """Test SARIF includes tool information."""
        findings = []
        sarif = generate_sarif_report(findings)
        
        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "Garrison Engine"
        assert "version" in tool
        assert "informationUri" in tool

    def test_sarif_results_structure(self, mock_pro_license):
        """Test SARIF results have correct structure."""
        findings = [
            Finding(
                rule_id="TEST_RULE",
                severity="MEDIUM",
                category="Test",
                title="Test",
                description="Test desc",
                file="test.sol",
                line_no=42,
                code_snippet="test code"
            )
        ]
        
        sarif = generate_sarif_report(findings)
        
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "TEST_RULE"
        assert results[0]["level"] == "warning"
        assert results[0]["message"]["text"] == "Test desc"
        
        location = results[0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "test.sol"
        assert location["region"]["startLine"] == 42

    def test_sarif_rules_from_findings(self, mock_pro_license):
        """Test SARIF includes unique rules from findings."""
        findings = [
            Finding(rule_id="RULE_1", severity="HIGH", category="Test", title="T1", description="D1", file="t.sol", line_no=1),
            Finding(rule_id="RULE_1", severity="HIGH", category="Test", title="T1", description="D2", file="t.sol", line_no=2),
            Finding(rule_id="RULE_2", severity="MEDIUM", category="Test", title="T2", description="D3", file="t.sol", line_no=3),
        ]
        
        sarif = generate_sarif_report(findings)
        
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"RULE_1", "RULE_2"}

    def test_sarif_severity_mapping(self, mock_pro_license):
        """Test SARIF severity mapping is correct."""
        test_cases = [
            ("CRITICAL", "error"),
            ("HIGH", "error"),
            ("MEDIUM", "warning"),
            ("LOW", "note"),
            ("INFO", "note"),
        ]
        
        for severity, expected_level in test_cases:
            findings = [
                Finding(rule_id="TEST", severity=severity, category="Test", title="T", description="D", file="t.sol", line_no=1)
            ]
            sarif = generate_sarif_report(findings)
            assert sarif["runs"][0]["results"][0]["level"] == expected_level

    def test_sarif_with_metadata(self, mock_pro_license):
        """Test SARIF generation with metadata."""
        findings = []
        metadata = {
            "project_name": "MyProject",
            "target_path": "./contracts",
            "timestamp": "2024-01-01T00:00:00"
        }
        
        sarif = generate_sarif_report(findings, metadata)
        
        assert sarif["runs"][0]["automationDetails"]["id"] == "MyProject"


class TestSaveSARIFReport:
    """Test saving SARIF report to file."""

    def test_save_sarif_creates_file(self, tmp_path, mock_pro_license):
        """Test SARIF file is created correctly."""
        findings = [
            Finding(rule_id="TEST", severity="HIGH", category="Test", title="T", description="D", file="t.sol", line_no=1)
        ]
        output_path = str(tmp_path / "report.sarif")
        
        result_path = save_sarif_report(findings, output_path)
        
        assert result_path == output_path
        assert os.path.exists(output_path)
        
        with open(output_path, 'r') as f:
            content = json.load(f)
        assert content["version"] == "2.1.0"


class TestCreateAuditReport:
    """Test create_audit_report function."""

    def test_create_report_with_findings(self):
        """Test report creation with findings."""
        findings = [
            Finding(rule_id="1", severity="CRITICAL", category="Heuristic", title="T1", description="D1", file="t.sol", line_no=1),
            Finding(rule_id="2", severity="HIGH", category="Slither", title="T2", description="D2", file="t.sol", line_no=2),
        ]
        
        report = create_audit_report("Test Project", "./contracts", findings)
        
        assert report.project_name == "Test Project"
        assert report.target_path == "./contracts"
        assert report.executive_summary["CRITICAL"] == 1
        assert report.executive_summary["HIGH"] == 1
        assert len(report.sections) == 2  # One per category

    def test_create_report_empty_findings(self):
        """Test report creation with empty findings."""
        report = create_audit_report("Test", "./", [])
        
        assert report.risk_score == 0.0
        assert report.pass_fail == "PASS"
        assert len(report.sections) == 0

    def test_sections_sorted_by_severity(self):
        """Test report sections have findings sorted by severity."""
        findings = [
            Finding(rule_id="1", severity="LOW", category="Test", title="T1", description="D1", file="t.sol", line_no=1),
            Finding(rule_id="2", severity="CRITICAL", category="Test", title="T2", description="D2", file="t.sol", line_no=2),
            Finding(rule_id="3", severity="HIGH", category="Test", title="T3", description="D3", file="t.sol", line_no=3),
        ]
        
        report = create_audit_report("Test", "./", findings)
        
        if report.sections:
            severities = [f.severity for f in report.sections[0].findings]
            assert severities == ["CRITICAL", "HIGH", "LOW"]


class TestAggregateFindings:
    """Test aggregate_findings_from_orchestrator."""

    def test_aggregate_empty_results(self):
        """Test aggregation with empty results."""
        findings = aggregate_findings_from_orchestrator(
            static_results=[],
            heuristic_results=[],
            liar_results=[],
            access_matrix_results=[],
            aderyn_results=None,
            upgrade_diff_results=None,
            solana_results=None
        )
        
        assert findings == []

    def test_aggregate_static_results(self):
        """Test aggregation of static analysis results."""
        static_results = [
            {"check": "reentrancy", "impact": "High", "title": "Reentrancy", "description": "Test", "location": "test.sol:10"}
        ]
        
        findings = aggregate_findings_from_orchestrator(
            static_results=static_results,
            heuristic_results=[],
            liar_results=[],
            access_matrix_results=[],
            aderyn_results=None,
            upgrade_diff_results=None,
            solana_results=None
        )
        
        assert len(findings) == 1
        assert findings[0].rule_id == "reentrancy"
        assert findings[0].severity == "HIGH"
        assert findings[0].category == "Slither"

    def test_aggregate_heuristic_results(self):
        """Test aggregation of heuristic results."""
        heuristic_results = [
            {"rule_id": "TX_ORIGIN", "severity": "HIGH", "message": "Uses tx.origin", "file": "test.sol", "line_no": 5, "line_text": "code"}
        ]
        
        findings = aggregate_findings_from_orchestrator(
            static_results=[],
            heuristic_results=heuristic_results,
            liar_results=[],
            access_matrix_results=[],
            aderyn_results=None,
            upgrade_diff_results=None,
            solana_results=None
        )
        
        assert len(findings) == 1
        assert findings[0].rule_id == "TX_ORIGIN"
        assert findings[0].category == "Heuristic"

    def test_aggregate_liar_results(self):
        """Test aggregation of liar detector results."""
        liar_results = [
            {"function": "withdraw", "trigger_word": "onlyOwner", "file": "test.sol", "line": 20}
        ]
        
        findings = aggregate_findings_from_orchestrator(
            static_results=[],
            heuristic_results=[],
            liar_results=liar_results,
            access_matrix_results=[],
            aderyn_results=None,
            upgrade_diff_results=None,
            solana_results=None
        )
        
        assert len(findings) == 1
        assert findings[0].rule_id == "INTENT_IMPLEMENTATION_MISMATCH"
        assert findings[0].severity == "CRITICAL"


class TestSeverityMappings:
    """Test severity mapping constants."""

    def test_severity_weights_defined(self):
        """Test severity weights are defined for all levels."""
        assert "CRITICAL" in SEVERITY_WEIGHTS
        assert "HIGH" in SEVERITY_WEIGHTS
        assert "MEDIUM" in SEVERITY_WEIGHTS
        assert "LOW" in SEVERITY_WEIGHTS
        assert "INFO" in SEVERITY_WEIGHTS

    def test_sarif_level_map_defined(self):
        """Test SARIF level map is defined for all severities."""
        assert "CRITICAL" in SARIF_LEVEL_MAP
        assert "HIGH" in SARIF_LEVEL_MAP
        assert "MEDIUM" in SARIF_LEVEL_MAP
        assert "LOW" in SARIF_LEVEL_MAP
        assert "INFO" in SARIF_LEVEL_MAP

    def test_critical_high_map_to_error(self):
        """Test CRITICAL and HIGH map to error level."""
        assert SARIF_LEVEL_MAP["CRITICAL"] == "error"
        assert SARIF_LEVEL_MAP["HIGH"] == "error"

    def test_medium_maps_to_warning(self):
        """Test MEDIUM maps to warning level."""
        assert SARIF_LEVEL_MAP["MEDIUM"] == "warning"

    def test_low_info_map_to_note(self):
        """Test LOW and INFO map to note level."""
        assert SARIF_LEVEL_MAP["LOW"] == "note"
        assert SARIF_LEVEL_MAP["INFO"] == "note"


class TestDataclasses:
    """Test dataclass creation."""

    def test_finding_creation(self):
        """Test Finding dataclass."""
        finding = Finding(
            rule_id="TEST",
            severity="HIGH",
            category="Test",
            title="Test Title",
            description="Test Desc",
            file="test.sol",
            line_no=10,
            code_snippet="code",
            remediation="fix",
            references=["https://example.com"],
            cwe="CWE-123",
            owasp="A01"
        )
        assert finding.rule_id == "TEST"
        assert finding.line_no == 10

    def test_report_section_creation(self):
        """Test ReportSection dataclass."""
        section = ReportSection(
            title="Test Section",
            findings=[],
            summary="Test summary"
        )
        assert section.title == "Test Section"

    def test_audit_report_creation(self):
        """Test AuditReport dataclass."""
        report = AuditReport(
            project_name="Test",
            target_path="./",
            timestamp="2024-01-01",
            engine_version="3.4.0",
            executive_summary={},
            sections=[],
            risk_score=50.0,
            pass_fail="WARNING"
        )
        assert report.project_name == "Test"
        assert report.pass_fail == "WARNING"
