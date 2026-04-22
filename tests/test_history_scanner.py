"""
Tests for the history_scanner module.
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from history_scanner import (
    CommitInfo,
    CommitFinding,
    VulnerabilityTimelineEntry,
    parse_git_history,
    scan_commit,
    build_timeline,
    generate_trends,
    generate_history_report,
    scan_history,
)


# =============================================================================
# CommitInfo Tests
# =============================================================================

class TestCommitInfo:
    """Test CommitInfo dataclass."""

    def test_creation(self):
        """Test creating a CommitInfo."""
        commit = CommitInfo(
            hash="abc123",
            author="John Doe",
            email="john@example.com",
            date="2024-01-15T10:30:00+00:00",
            message="Initial commit",
            changed_files=["contracts/Vault.sol"]
        )
        
        assert commit.hash == "abc123"
        assert commit.author == "John Doe"
        assert commit.email == "john@example.com"
        assert len(commit.changed_files) == 1

    def test_default_changed_files(self):
        """Test CommitInfo with default changed_files."""
        commit = CommitInfo(
            hash="abc123",
            author="John",
            email="john@example.com",
            date="2024-01-15",
            message="Test"
        )
        
        assert commit.changed_files == []


# =============================================================================
# CommitFinding Tests
# =============================================================================

class TestCommitFinding:
    """Test CommitFinding dataclass."""

    def test_creation(self):
        """Test creating a CommitFinding."""
        finding = CommitFinding(
            commit_hash="abc123",
            date="2024-01-15",
            author="John",
            file="contracts/Vault.sol",
            findings=[{"rule_id": "REENTRANCY"}]
        )
        
        assert finding.commit_hash == "abc123"
        assert len(finding.findings) == 1


# =============================================================================
# VulnerabilityTimelineEntry Tests
# =============================================================================

class TestVulnerabilityTimelineEntry:
    """Test VulnerabilityTimelineEntry dataclass."""

    def test_creation(self):
        """Test creating a VulnerabilityTimelineEntry."""
        entry = VulnerabilityTimelineEntry(
            vuln_id="VULN-0001",
            rule_id="REENTRANCY",
            severity="CRITICAL",
            file="Vault.sol",
            line_no=45,
            introduced_commit="abc123",
            introduced_date="2024-01-15",
            introduced_author="John",
            status="active"
        )
        
        assert entry.vuln_id == "VULN-0001"
        assert entry.status == "active"
        assert entry.fixed_commit is None

    def test_fixed_vulnerability(self):
        """Test entry for fixed vulnerability."""
        entry = VulnerabilityTimelineEntry(
            vuln_id="VULN-0001",
            rule_id="REENTRANCY",
            severity="CRITICAL",
            file="Vault.sol",
            line_no=45,
            introduced_commit="abc123",
            introduced_date="2024-01-15",
            introduced_author="John",
            fixed_commit="def456",
            fixed_date="2024-01-20",
            lifespan_days=5,
            status="fixed"
        )
        
        assert entry.status == "fixed"
        assert entry.lifespan_days == 5


# =============================================================================
# parse_git_history Tests
# =============================================================================

class TestParseGitHistory:
    """Test parse_git_history function."""

    def test_parse_valid_git_log(self, tmp_path):
        """Test parsing valid git log output."""
        # Create a mock git repo
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        repo_path = str(tmp_path)
        
        # Mock subprocess.run
        git_output = """abc123def456|John Doe|john@example.com|2024-01-15T10:30:00+00:00|Initial commit

contracts/Vault.sol
contracts/Token.sol
<<COMMIT_SEP>>
def789abc012|Jane Smith|jane@example.com|2024-01-16T14:45:00+00:00|Add feature

contracts/Vault.sol
<<COMMIT_SEP>>"""
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = git_output
        mock_result.stderr = ""
        
        with patch('subprocess.run', return_value=mock_result):
            commits = parse_git_history(repo_path, max_commits=10)
        
        assert len(commits) == 2
        assert commits[0].hash == "abc123def456"
        assert commits[0].author == "John Doe"
        assert len(commits[0].changed_files) == 2

    def test_not_a_git_repo(self, tmp_path):
        """Test error when path is not a git repo."""
        from exceptions import CounterscarpValidationError
        
        with pytest.raises(CounterscarpValidationError):
            parse_git_history(str(tmp_path))

    def test_git_command_failure(self, tmp_path):
        """Test handling of git command failure."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "fatal: not a git repository"
        
        from exceptions import CounterscarpAnalysisError
        
        with patch('subprocess.run', return_value=mock_result):
            with pytest.raises(CounterscarpAnalysisError):
                parse_git_history(str(tmp_path))

    def test_git_not_found(self, tmp_path):
        """Test handling when git is not installed."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        from exceptions import CounterscarpAnalysisError
        
        with patch('subprocess.run', side_effect=FileNotFoundError()):
            with pytest.raises(CounterscarpAnalysisError):
                parse_git_history(str(tmp_path))

    def test_filters_non_sol_rs_files(self, tmp_path):
        """Test that only .sol and .rs files are included."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        git_output = """abc123|John|john@example.com|2024-01-15|Test commit

contracts/Vault.sol
README.md
package.json
src/lib.rs
<<COMMIT_SEP>>"""
        
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = git_output
        
        with patch('subprocess.run', return_value=mock_result):
            commits = parse_git_history(str(tmp_path))
        
        assert len(commits) == 1
        assert "contracts/Vault.sol" in commits[0].changed_files
        assert "src/lib.rs" in commits[0].changed_files
        assert "README.md" not in commits[0].changed_files


# =============================================================================
# scan_commit Tests
# =============================================================================

class TestScanCommit:
    """Test scan_commit function."""

    def test_scan_with_mock_heuristic(self, tmp_path):
        """Test scanning a commit with mocked heuristic scanner."""
        # Create temp file structure
        repo_path = str(tmp_path)
        
        mock_finding = MagicMock()
        mock_finding.rule_id = "REENTRANCY"
        mock_finding.severity = "HIGH"
        mock_finding.message = "Reentrancy detected"
        mock_finding.file = str(tmp_path / "Vault.sol")
        mock_finding.line_no = 45
        mock_finding.line_text = "msg.sender.call"
        mock_finding.suppressed = False
        
        with patch('history_scanner.scan_file', return_value=[mock_finding]):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="contract Vault {}"
                )
                
                result = scan_commit(
                    repo_path,
                    "abc123",
                    ["contracts/Vault.sol"]
                )
        
        assert result.commit_hash == "abc123"
        assert len(result.findings) == 1
        assert result.findings[0]["rule_id"] == "REENTRANCY"

    def test_scan_skips_non_sol_files(self, tmp_path):
        """Test that non-.sol files are skipped."""
        repo_path = str(tmp_path)
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="content"
            )
            
            result = scan_commit(
                repo_path,
                "abc123",
                ["README.md", "script.js"]  # Non-.sol files
            )
        
        assert len(result.findings) == 0


# =============================================================================
# build_timeline Tests
# =============================================================================

class TestBuildTimeline:
    """Test build_timeline function."""

    def test_build_timeline_from_results(self):
        """Test building timeline from scan results."""
        scan_results = [
            {
                "commit_hash": "abc123",
                "date": "2024-01-15T10:00:00",
                "author": "John",
                "file": "contracts/Vault.sol",
                "findings": [
                    {
                        "rule_id": "REENTRANCY",
                        "severity": "HIGH",
                        "file": "contracts/Vault.sol",
                        "line_no": 45,
                        "suppressed": False
                    }
                ]
            }
        ]
        
        timeline = build_timeline(scan_results)
        
        assert len(timeline) == 1
        assert timeline[0].rule_id == "REENTRANCY"
        assert timeline[0].status == "active"
        assert timeline[0].introduced_commit == "abc123"

    def test_detect_fixed_vulnerabilities(self):
        """Test detecting when vulnerabilities are fixed."""
        scan_results = [
            {
                "commit_hash": "abc123",
                "date": "2024-01-15T10:00:00",
                "author": "John",
                "findings": [
                    {
                        "rule_id": "REENTRANCY",
                        "severity": "HIGH",
                        "file": "Vault.sol",
                        "line_no": 45,
                        "suppressed": False
                    }
                ]
            },
            {
                "commit_hash": "def456",
                "date": "2024-01-20T10:00:00",
                "author": "Jane",
                "findings": []  # Vulnerability fixed
            }
        ]
        
        timeline = build_timeline(scan_results)
        
        assert len(timeline) == 1
        assert timeline[0].status == "fixed"
        assert timeline[0].fixed_commit == "def456"
        assert timeline[0].lifespan_days == 5

    def test_empty_results(self):
        """Test building timeline from empty results."""
        timeline = build_timeline([])
        
        assert timeline == []

    def test_suppressed_findings_ignored(self):
        """Test that suppressed findings are not included."""
        scan_results = [
            {
                "commit_hash": "abc123",
                "date": "2024-01-15",
                "author": "John",
                "findings": [
                    {
                        "rule_id": "REENTRANCY",
                        "severity": "HIGH",
                        "file": "Vault.sol",
                        "line_no": 45,
                        "suppressed": True  # Suppressed
                    }
                ]
            }
        ]
        
        timeline = build_timeline(scan_results)
        
        assert len(timeline) == 0


# =============================================================================
# generate_trends Tests
# =============================================================================

class TestGenerateTrends:
    """Test generate_trends function."""

    def test_empty_timeline(self):
        """Test generating trends from empty timeline."""
        trends = generate_trends([])
        
        assert trends["total_vulnerabilities"] == 0
        assert trends["active_vulnerabilities"] == 0
        assert trends["fixed_vulnerabilities"] == 0

    def test_calculate_fix_rate(self):
        """Test calculating fix rate."""
        timeline = [
            VulnerabilityTimelineEntry(
                vuln_id="V1",
                rule_id="R1",
                severity="HIGH",
                file="f.sol",
                line_no=1,
                introduced_commit="a",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="fixed",
                fixed_commit="b",
                fixed_date="2024-01-20",
                lifespan_days=5
            ),
            VulnerabilityTimelineEntry(
                vuln_id="V2",
                rule_id="R2",
                severity="MEDIUM",
                file="f.sol",
                line_no=2,
                introduced_commit="a",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="active"
            )
        ]
        
        trends = generate_trends(timeline)
        
        assert trends["total_vulnerabilities"] == 2
        assert trends["active_vulnerabilities"] == 1
        assert trends["fixed_vulnerabilities"] == 1
        assert trends["fix_rate_percent"] == 50.0

    def test_calculate_average_fix_time(self):
        """Test calculating average fix time."""
        timeline = [
            VulnerabilityTimelineEntry(
                vuln_id="V1",
                rule_id="R1",
                severity="HIGH",
                file="f.sol",
                line_no=1,
                introduced_commit="a",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="fixed",
                fixed_commit="b",
                fixed_date="2024-01-20",
                lifespan_days=5
            ),
            VulnerabilityTimelineEntry(
                vuln_id="V2",
                rule_id="R2",
                severity="MEDIUM",
                file="f.sol",
                line_no=2,
                introduced_commit="a",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="fixed",
                fixed_commit="b",
                fixed_date="2024-01-25",
                lifespan_days=10
            )
        ]
        
        trends = generate_trends(timeline)
        
        assert trends["average_fix_time_days"] == 7.5

    def test_severity_distribution(self):
        """Test severity distribution calculation."""
        timeline = [
            VulnerabilityTimelineEntry(
                vuln_id="V1", rule_id="R1", severity="CRITICAL",
                file="f.sol", line_no=1,
                introduced_commit="a", introduced_date="2024-01-15",
                introduced_author="John", status="active"
            ),
            VulnerabilityTimelineEntry(
                vuln_id="V2", rule_id="R2", severity="HIGH",
                file="f.sol", line_no=2,
                introduced_commit="a", introduced_date="2024-01-15",
                introduced_author="John", status="active"
            ),
            VulnerabilityTimelineEntry(
                vuln_id="V3", rule_id="R3", severity="HIGH",
                file="f.sol", line_no=3,
                introduced_commit="a", introduced_date="2024-01-15",
                introduced_author="John", status="active"
            ),
        ]
        
        trends = generate_trends(timeline)
        
        assert trends["severity_distribution"]["CRITICAL"] == 1
        assert trends["severity_distribution"]["HIGH"] == 2
        assert trends["severity_distribution"]["MEDIUM"] == 0


# =============================================================================
# generate_history_report Tests
# =============================================================================

class TestGenerateHistoryReport:
    """Test generate_history_report function."""

    def test_generates_json_report(self, tmp_path):
        """Test generating JSON report."""
        timeline = [
            VulnerabilityTimelineEntry(
                vuln_id="V1",
                rule_id="REENTRANCY",
                severity="HIGH",
                file="Vault.sol",
                line_no=45,
                introduced_commit="abc123",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="active"
            )
        ]
        
        trends = generate_trends(timeline)
        
        json_path, md_path = generate_history_report(
            timeline, trends, str(tmp_path)
        )
        
        assert os.path.exists(json_path)
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        assert "timeline" in data
        assert "trends" in data
        assert len(data["timeline"]) == 1

    def test_generates_markdown_report(self, tmp_path):
        """Test generating Markdown report."""
        timeline = [
            VulnerabilityTimelineEntry(
                vuln_id="V1",
                rule_id="REENTRANCY",
                severity="HIGH",
                file="Vault.sol",
                line_no=45,
                introduced_commit="abc123",
                introduced_date="2024-01-15",
                introduced_author="John",
                status="active"
            )
        ]
        
        trends = generate_trends(timeline)
        
        json_path, md_path = generate_history_report(
            timeline, trends, str(tmp_path)
        )
        
        assert os.path.exists(md_path)
        
        with open(md_path, 'r') as f:
            content = f.read()
        
        assert "Vulnerability Timeline Report" in content
        assert "REENTRANCY" in content
        assert "Vault.sol" in content


# =============================================================================
# scan_history Tests
# =============================================================================

class TestScanHistory:
    """Test scan_history function."""

    def test_no_commits_found(self, tmp_path):
        """Test scan when no commits are found."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        with patch('history_scanner.parse_git_history', return_value=[]):
            result = scan_history(str(tmp_path))
        
        assert result["status"] == "no_commits"
        assert result["total_commits"] == 0

    def test_scan_with_commits(self, tmp_path):
        """Test scan with commits."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        
        commits = [
            CommitInfo(
                hash="abc123",
                author="John",
                email="john@example.com",
                date="2024-01-15",
                message="Test commit",
                changed_files=["contracts/Vault.sol"]
            )
        ]
        
        with patch('history_scanner.parse_git_history', return_value=commits):
            with patch('history_scanner.scan_commit') as mock_scan:
                mock_scan.return_value = CommitFinding(
                    commit_hash="abc123",
                    date="2024-01-15",
                    author="John",
                    file="contracts/Vault.sol",
                    findings=[]
                )
                
                result = scan_history(str(tmp_path))
        
        assert result["status"] == "success"
        assert result["total_commits"] == 1
