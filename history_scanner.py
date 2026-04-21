#!/usr/bin/env python3
"""
Time-Travel Historical Vulnerability Scanner for Counterscarp Engine.

Scans Git history to track when vulnerabilities were introduced and fixed,
providing a timeline view of security issues across the codebase evolution.

Example:
    >>> from history_scanner import scan_history
    >>> results = scan_history("./my-contracts", max_commits=100)
    >>> print(f"Found {results['total_vulnerabilities']} vulnerabilities")
"""

from __future__ import annotations

import os
import json
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict

# Import logger and exceptions
try:
    from logger import get_logger, append_stderr_log
    from exceptions import (
        CounterscarpError, CounterscarpAnalysisError, CounterscarpValidationError
    )
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None
    append_stderr_log = None
    CounterscarpError = Exception
    CounterscarpAnalysisError = Exception
    CounterscarpValidationError = Exception

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Import heuristic scanner
try:
    from heuristic_scanner import scan_file, HeuristicFinding
    from config_loader import CounterscarpConfig, load_config
    HEURISTIC_AVAILABLE = True
except ImportError:
    HEURISTIC_AVAILABLE = False
    scan_file = None
    HeuristicFinding = None
    CounterscarpConfig = None
    load_config = None


@dataclass
class CommitInfo:
    """Represents a Git commit with metadata.
    
    Attributes:
        hash: Full commit hash.
        author: Author name.
        email: Author email.
        date: Commit date (ISO format).
        message: Commit message.
        changed_files: List of files changed in this commit.
    """
    hash: str
    author: str
    email: str
    date: str
    message: str
    changed_files: List[str] = field(default_factory=list)


@dataclass
class CommitFinding:
    """Represents findings from scanning a specific commit.
    
    Attributes:
        commit_hash: The commit hash.
        date: Commit date.
        author: Commit author.
        file: File path that was scanned.
        findings: List of heuristic findings.
    """
    commit_hash: str
    date: str
    author: str
    file: str
    findings: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class VulnerabilityTimelineEntry:
    """Represents a vulnerability's lifecycle across commits.
    
    Attributes:
        vuln_id: Unique identifier for this vulnerability instance.
        rule_id: The heuristic rule that triggered.
        severity: Severity level.
        file: File path where vulnerability exists.
        line_no: Line number (approximate).
        introduced_commit: First commit where vulnerability appeared.
        introduced_date: Date when introduced.
        introduced_author: Author who introduced the vulnerability.
        fixed_commit: Commit where vulnerability was fixed (None if still
            active).
        fixed_date: Date when fixed (None if still active).
        lifespan_days: Number of days vulnerability existed.
        status: "active" or "fixed".
    """
    vuln_id: str
    rule_id: str
    severity: str
    file: str
    line_no: int
    introduced_commit: str
    introduced_date: str
    introduced_author: str
    fixed_commit: Optional[str] = None
    fixed_date: Optional[str] = None
    lifespan_days: int = 0
    status: str = "active"


def parse_git_history(
    repo_path: str,
    max_commits: int = 50,
    since: Optional[str] = None,
    branch: str = "main",
    stderr_log: Optional[str] = None
) -> List[CommitInfo]:
    """Parse Git history to extract commits with changed files.
    
    Uses subprocess to call git log and parse the output into structured
    commit information, filtering to only commits that changed .sol or .rs
    files.
    
    Args:
        repo_path: Path to the Git repository.
        max_commits: Maximum number of commits to parse (default: 50).
        since: Optional date filter (ISO format, e.g., "2024-01-01").
        branch: Branch to scan (default: "main").
    
    Returns:
        List of CommitInfo objects with metadata and changed files.
    
    Raises:
        CounterscarpValidationError: If repo_path is not a valid git repository.
        CounterscarpAnalysisError: If git command fails.
    """
    repo_path = os.path.abspath(repo_path)
    
    # Validate repository
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.isdir(git_dir):
        raise CounterscarpValidationError(
            "Not a valid Git repository",
            details={"path": repo_path}
        )
    
    # Build git log command
    # Format: hash|author|email|date|message
    format_str = "%H|%an|%ae|%ai|%s"
    cmd = [
        "git", "-C", repo_path, "log",
        f"--pretty=format:{format_str}<<COMMIT_SEP>>",
        "--name-only",
        f"--max-count={max_commits}",
        branch
    ]
    
    if since:
        cmd.extend([f"--since={since}"])
    
    logger.info(
        f"Parsing git history for {repo_path} "
        f"(branch: {branch}, max: {max_commits})"
    )
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300
        )
        
        if result.stderr and append_stderr_log:
            append_stderr_log(result.stderr, "git-log", stderr_log)

        if result.returncode != 0:
            raise CounterscarpAnalysisError(
                "Git log command failed",
                details={"error": result.stderr, "path": repo_path}
            )
        
    except subprocess.TimeoutExpired:
        logger.warning(
            f"Git log command timed out for {repo_path} "
            f"(limit: 300s). Returning empty commit list."
        )
        return []
    except FileNotFoundError:
        raise CounterscarpAnalysisError(
            "Git command not found",
            details={"install_hint": "Install Git and ensure it's in PATH"}
        )
    except subprocess.SubprocessError as e:
        raise CounterscarpAnalysisError(
            "Failed to execute git command",
            details={"error": str(e)}
        )
    
    # Parse output
    commits = []
    raw_commits = result.stdout.split("<<COMMIT_SEP>>")
    
    for raw_commit in raw_commits:
        raw_commit = raw_commit.strip()
        if not raw_commit:
            continue
        
        lines = raw_commit.split("\n")
        if not lines:
            continue
        
        # Parse header line
        header = lines[0].strip()
        parts = header.split("|", 4)  # Split into max 5 parts
        
        if len(parts) < 5:
            logger.debug(f"Skipping malformed commit header: {header[:50]}...")
            continue
        
        commit_hash, author, email, commit_date, message = parts
        
        # Collect changed files (skip empty lines)
        changed_files = []
        for line in lines[1:]:
            line = line.strip()
            if line and (line.endswith(".sol") or line.endswith(".rs")):
                changed_files.append(line)
        
        # Only include commits that changed relevant files
        if changed_files:
            commits.append(CommitInfo(
                hash=commit_hash,
                author=author,
                email=email,
                date=commit_date,
                message=message,
                changed_files=changed_files
            ))
    
    logger.info(f"Found {len(commits)} commits with .sol/.rs changes")
    return commits


def scan_commit(
    repo_path: str,
    commit_hash: str,
    files: List[str],
    config: Optional[CounterscarpConfig] = None,
    stderr_log: Optional[str] = None
) -> CommitFinding:
    """Scan files at a specific commit for vulnerabilities.
    
    Extracts file content at the given commit using git show, writes to a
    temporary file, and runs the heuristic scanner against it.
    
    Args:
        repo_path: Path to the Git repository.
        commit_hash: The commit hash to scan.
        files: List of file paths to scan.
        config: Optional configuration for heuristic scanning.
    
    Returns:
        CommitFinding with all findings from this commit.
    
    Raises:
        CounterscarpAnalysisError: If git show or scanning fails.
    """
    if not HEURISTIC_AVAILABLE or scan_file is None:
        raise CounterscarpAnalysisError(
            "Heuristic scanner not available",
            details={"hint": "Ensure heuristic_scanner.py is accessible"}
        )
    
    repo_path = os.path.abspath(repo_path)
    all_findings = []
    
    # Create temporary directory for extracted files
    temp_dir = tempfile.mkdtemp(prefix="counterscarp_history_")
    
    try:
        for file_path in files:
            # Skip non-.sol files for now (heuristic scanner focuses on
            # Solidity)
            if not file_path.endswith(".sol"):
                continue
            
            # Get file content at this commit
            git_cmd = [
                "git", "-C", repo_path, "show",
                f"{commit_hash}:{file_path}"
            ]
            
            try:
                result = subprocess.run(
                    git_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30
                )
                if result.stderr and append_stderr_log:
                    append_stderr_log(result.stderr, "git-show", stderr_log)
                
                if result.returncode != 0:
                    # File might not exist at this commit (added later)
                    logger.debug(
                        f"Could not get {file_path} at {commit_hash[:8]}"
                    )
                    continue
                
                # Write to temp file
                temp_file = os.path.join(
                    temp_dir,
                    f"{commit_hash[:8]}_"
                    f"{os.path.basename(file_path)}"
                )
                with open(temp_file, "w", encoding="utf-8") as f:
                    f.write(result.stdout)
                
                # Scan the temp file
                findings = scan_file(temp_file, config)
                
                # Convert findings to dict and adjust file path
                for finding in findings:
                    finding_dict = {
                        "rule_id": finding.rule_id,
                        "severity": finding.severity,
                        "message": finding.message,
                        "file": file_path,  # Use original path, not temp path
                        "line_no": finding.line_no,
                        "line_text": finding.line_text,
                        "suppressed": finding.suppressed
                    }
                    all_findings.append(finding_dict)
                
            except subprocess.TimeoutExpired:
                logger.warning(
                    f"Git show timed out for {file_path} "
                    f"at {commit_hash[:8]} (limit: 30s). Skipping file."
                )
                continue
            except subprocess.SubprocessError as e:
                logger.warning(
                    f"Failed to scan {file_path} "
                    f"at {commit_hash[:8]}: {e}"
                )
                continue
    
    finally:
        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return CommitFinding(
        commit_hash=commit_hash,
        date="",  # Will be filled by caller
        author="",  # Will be filled by caller
        file=",".join(files),
        findings=all_findings
    )


def build_timeline(
    scan_results: List[Dict[str, Any]]
) -> List[VulnerabilityTimelineEntry]:
    """Build a vulnerability timeline from scan results.
    
    Tracks each unique vulnerability (by rule_id + file + approximate location)
    across commits to determine when it was introduced and fixed.
    
    Args:
        scan_results: List of scan results from scan_commit operations.
    
    Returns:
        List of VulnerabilityTimelineEntry objects.
    """
    # Track vulnerabilities by unique key
    vuln_tracker: Dict[str, Dict[str, Any]] = {}
    
    # Process commits in order (oldest first)
    sorted_results = sorted(scan_results, key=lambda x: x.get("date", ""))
    
    for result in sorted_results:
        commit_hash = result.get("commit_hash", "")
        commit_date = result.get("date", "")
        commit_author = result.get("author", "")
        findings = result.get("findings", [])
        
        # Track which vulnerabilities exist in this commit
        current_vuln_keys = set()

        for finding in findings:
            if finding.get("suppressed"):
                continue
            
            # Create unique key for this vulnerability
            # Use rule_id + file + line_no (with some tolerance for line
            # shifts)
            file_path = finding.get("file", "")
            rule_id = finding.get("rule_id", "")
            line_no = finding.get("line_no", 0)
            
            # Round line number to nearest 5 for tolerance against minor shifts
            line_bucket = (line_no // 5) * 5
            vuln_key = f"{rule_id}:{file_path}:{line_bucket}"
            
            current_vuln_keys.add(vuln_key)
            
            if vuln_key not in vuln_tracker:
                # New vulnerability introduced
                vuln_tracker[vuln_key] = {
                    "rule_id": rule_id,
                    "severity": finding.get("severity", "INFO"),
                    "file": file_path,
                    "line_no": line_no,
                    "introduced_commit": commit_hash,
                    "introduced_date": commit_date,
                    "introduced_author": commit_author,
                    "fixed_commit": None,
                    "fixed_date": None,
                    "lifespan_days": 0,
                    "status": "active"
                }
        
        # Check for fixed vulnerabilities (were present before, not in this
        # commit)
        for vuln_key, vuln_info in vuln_tracker.items():
            if (vuln_info["status"] == "active" and
                    vuln_key not in current_vuln_keys):
                # Vulnerability was fixed in this commit
                vuln_info["fixed_commit"] = (
                    commit_hash
                )
                vuln_info["fixed_date"] = commit_date
                vuln_info["status"] = "fixed"
                
                # Calculate lifespan
                try:
                    intro_date = datetime.fromisoformat(
                        vuln_info["introduced_date"].replace("Z", "+00:00")
                    )
                    fix_date = datetime.fromisoformat(
                        commit_date.replace("Z", "+00:00")
                    )
                    lifespan = (fix_date - intro_date).days
                    vuln_info["lifespan_days"] = max(0, lifespan)
                except (ValueError, AttributeError):
                    vuln_info["lifespan_days"] = 0
    
    # Convert to timeline entries
    timeline = []
    for i, (vuln_key, vuln_info) in enumerate(vuln_tracker.items(), 1):
        entry = VulnerabilityTimelineEntry(
            vuln_id=f"VULN-{i:04d}",
            rule_id=vuln_info["rule_id"],
            severity=vuln_info["severity"],
            file=vuln_info["file"],
            line_no=vuln_info["line_no"],
            introduced_commit=vuln_info["introduced_commit"],
            introduced_date=vuln_info["introduced_date"],
            introduced_author=vuln_info["introduced_author"],
            fixed_commit=vuln_info["fixed_commit"],
            fixed_date=vuln_info["fixed_date"],
            lifespan_days=vuln_info["lifespan_days"],
            status=vuln_info["status"]
        )
        timeline.append(entry)

    # Sort by introduction date
    timeline.sort(key=lambda x: x.introduced_date)
    
    # Re-number after sorting
    for i, entry in enumerate(timeline, 1):
        entry.vuln_id = f"VULN-{i:04d}"
    
    return timeline


def generate_trends(
    timeline: List[VulnerabilityTimelineEntry]
) -> Dict[str, Any]:
    """Generate trend analysis from vulnerability timeline.
    
    Calculates statistics including new vulnerabilities per month,
    average fix time, most vulnerable files, and fix rates.
    
    Args:
        timeline: List of VulnerabilityTimelineEntry objects.
    
    Returns:
        Dictionary with trend statistics.
    """
    trends = {
        "total_vulnerabilities": len(timeline),
        "active_vulnerabilities": 0,
        "fixed_vulnerabilities": 0,
        "fix_rate_percent": 0.0,
        "new_vulnerabilities_per_month": {},
        "average_fix_time_days": 0.0,
        "most_vulnerable_files": [],
        "most_frequently_modified_files": [],
        "severity_distribution": {},
        "scan_summary": {}
    }

    if not timeline:
        return trends
    
    # Count active vs fixed
    active_vulns = [v for v in timeline if v.status == "active"]
    fixed_vulns = [v for v in timeline if v.status == "fixed"]
    
    trends["active_vulnerabilities"] = len(active_vulns)
    trends["fixed_vulnerabilities"] = len(fixed_vulns)
    
    # Fix rate
    if timeline:
        trends["fix_rate_percent"] = round(
            (len(fixed_vulns) / len(timeline)) * 100, 2
        )
    
    # New vulnerabilities per month
    monthly_counts: Dict[str, int] = {}
    for entry in timeline:
        try:
            date_obj = datetime.fromisoformat(entry.introduced_date.replace("Z", "+00:00"))
            month_key = date_obj.strftime("%Y-%m")
            monthly_counts[month_key] = monthly_counts.get(month_key, 0) + 1
        except (ValueError, AttributeError):
            continue
    
    trends["new_vulnerabilities_per_month"] = dict(sorted(monthly_counts.items()))
    
    # Average fix time
    fix_times = [v.lifespan_days for v in fixed_vulns if v.lifespan_days > 0]
    if fix_times:
        trends["average_fix_time_days"] = round(sum(fix_times) / len(fix_times), 2)
    
    # Most vulnerable files (by vulnerability count)
    file_counts: Dict[str, int] = {}
    file_authors: Dict[str, List[str]] = {}
    
    for entry in timeline:
        file_counts[entry.file] = file_counts.get(entry.file, 0) + 1
        if entry.file not in file_authors:
            file_authors[entry.file] = []
        file_authors[entry.file].append(entry.introduced_author)
    
    # Top 10 most vulnerable files
    sorted_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)
    trends["most_vulnerable_files"] = [
        {"file": f, "vulnerability_count": c} for f, c in sorted_files[:10]
    ]
    
    # Most frequently modified files (neutral language for contributors)
    file_modifications: Dict[str, Dict[str, Any]] = {}
    for entry in timeline:
        file = entry.file
        if file not in file_modifications:
            file_modifications[file] = {"file": file, "modification_count": 0, "authors": set()}
        file_modifications[file]["modification_count"] += 1
        file_modifications[file]["authors"].add(entry.introduced_author)
    
    sorted_modifications = sorted(
        file_modifications.values(),
        key=lambda x: x["modification_count"],
        reverse=True
    )
    trends["most_frequently_modified_files"] = [
        {"file": x["file"], "modification_count": x["modification_count"], "unique_authors": len(x["authors"])}
        for x in sorted_modifications[:10]
    ]
    
    # Severity distribution
    severity_counts: Dict[str, int] = {}
    for entry in timeline:
        sev = entry.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Order by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    trends["severity_distribution"] = {
        sev: severity_counts.get(sev, 0) for sev in severity_order
    }
    
    # Summary stats
    trends["scan_summary"] = {
        "total_commits_analyzed": len(set(v.introduced_commit for v in timeline)),
        "unique_files_affected": len(file_counts),
        "unique_authors": len(set(v.introduced_author for v in timeline)),
        "date_range": {
            "earliest": min((v.introduced_date for v in timeline), default=""),
            "latest": max((v.introduced_date for v in timeline), default="")
        }
    }
    
    return trends


def generate_history_report(
    timeline: List[VulnerabilityTimelineEntry],
    trends: Dict[str, Any],
    output_dir: str = "."
) -> Tuple[str, str]:
    """Generate history scan reports.
    
    Writes vulnerability_timeline.json and vulnerability_trends.md to the
    specified output directory.
    
    Args:
        timeline: List of VulnerabilityTimelineEntry objects.
        trends: Trend analysis dictionary.
        output_dir: Directory to write reports (default: current directory).
    
    Returns:
        Tuple of (json_path, markdown_path).
    
    Raises:
        CounterscarpAnalysisError: If report generation fails.
    """
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate JSON report
    json_path = os.path.join(output_dir, "vulnerability_timeline.json")
    try:
        timeline_data = [asdict(entry) for entry in timeline]
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "timeline": timeline_data,
            "trends": trends
        }
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        
        logger.info(f"Timeline JSON written to: {json_path}")
    
    except (IOError, OSError) as e:
        raise CounterscarpAnalysisError(
            "Failed to write timeline JSON",
            details={"path": json_path, "error": str(e)}
        )
    
    # Generate Markdown report
    md_path = os.path.join(output_dir, "vulnerability_trends.md")
    try:
        with open(md_path, "w", encoding="utf-8") as f:
            f.write("# Vulnerability Timeline Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Executive Summary
            f.write("## Executive Summary\n\n")
            f.write(f"- **Total Vulnerabilities:** {trends['total_vulnerabilities']}\n")
            f.write(f"- **Active (Unfixed):** {trends['active_vulnerabilities']}\n")
            f.write(f"- **Fixed:** {trends['fixed_vulnerabilities']}\n")
            f.write(f"- **Fix Rate:** {trends['fix_rate_percent']}%\n")
            f.write(f"- **Average Fix Time:** {trends['average_fix_time_days']} days\n\n")
            
            # Severity Distribution
            f.write("## Severity Distribution\n\n")
            f.write("| Severity | Count |\n")
            f.write("|----------|-------|\n")
            for sev, count in trends['severity_distribution'].items():
                f.write(f"| {sev} | {count} |\n")
            f.write("\n")
            
            # Most Vulnerable Files
            if trends['most_vulnerable_files']:
                f.write("## Most Vulnerable Files\n\n")
                f.write("| File | Vulnerability Count |\n")
                f.write("|------|---------------------|\n")
                for item in trends['most_vulnerable_files'][:10]:
                    f.write(f"| `{item['file']}` | {item['vulnerability_count']} |\n")
                f.write("\n")
            
            # Most Frequently Modified Files
            if trends['most_frequently_modified_files']:
                f.write("## Most Frequently Modified Files\n\n")
                f.write("| File | Modifications | Unique Authors |\n")
                f.write("|------|---------------|----------------|\n")
                for item in trends['most_frequently_modified_files'][:10]:
                    f.write(f"| `{item['file']}` | {item['modification_count']} | {item['unique_authors']} |\n")
                f.write("\n")
            
            # New Vulnerabilities Per Month
            if trends['new_vulnerabilities_per_month']:
                f.write("## New Vulnerabilities Per Month\n\n")
                f.write("| Month | Count |\n")
                f.write("|-------|-------|\n")
                for month, count in trends['new_vulnerabilities_per_month'].items():
                    f.write(f"| {month} | {count} |\n")
                f.write("\n")
            
            # Active Vulnerabilities
            active = [v for v in timeline if v.status == "active"]
            if active:
                f.write("## Currently Active Vulnerabilities\n\n")
                f.write("| ID | Rule | Severity | File | Line | Introduced | Author |\n")
                f.write("|----|------|----------|------|------|------------|--------|\n")
                for entry in active:
                    intro_date = entry.introduced_date[:10] if entry.introduced_date else ""
                    f.write(f"| {entry.vuln_id} | {entry.rule_id} | {entry.severity} | "
                            f"`{entry.file}` | {entry.line_no} | {intro_date} | {entry.introduced_author} |\n")
                f.write("\n")
            
            # Recently Fixed
            fixed = [v for v in timeline if v.status == "fixed"]
            if fixed:
                f.write("## Recently Fixed Vulnerabilities\n\n")
                f.write("| ID | Rule | Severity | File | Lifespan (Days) | Fixed Commit |\n")
                f.write("|----|------|----------|------|-----------------|--------------|\n")
                # Sort by fix date (most recent first)
                sorted_fixed = sorted(fixed, key=lambda x: x.fixed_date or "", reverse=True)
                for entry in sorted_fixed[:20]:  # Show top 20 most recent
                    fixed_commit = entry.fixed_commit[:8] if entry.fixed_commit else ""
                    f.write(f"| {entry.vuln_id} | {entry.rule_id} | {entry.severity} | "
                            f"`{entry.file}` | {entry.lifespan_days} | {fixed_commit} |\n")
                f.write("\n")
            
            # Full Timeline
            f.write("## Full Vulnerability Timeline\n\n")
            f.write("| ID | Rule | Severity | File | Line | Status | Introduced | Fixed | Lifespan |\n")
            f.write("|----|------|----------|------|------|--------|------------|-------|----------|\n")
            for entry in timeline:
                intro_date = entry.introduced_date[:10] if entry.introduced_date else ""
                fixed_date = entry.fixed_date[:10] if entry.fixed_date else "N/A"
                lifespan = f"{entry.lifespan_days}d" if entry.lifespan_days > 0 else "-"
                f.write(f"| {entry.vuln_id} | {entry.rule_id} | {entry.severity} | "
                        f"`{entry.file}` | {entry.line_no} | {entry.status.upper()} | "
                        f"{intro_date} | {fixed_date} | {lifespan} |\n")
        
        logger.info(f"Trends Markdown written to: {md_path}")
    
    except (IOError, OSError) as e:
        raise CounterscarpAnalysisError(
            "Failed to write trends Markdown",
            details={"path": md_path, "error": str(e)}
        )
    
    return json_path, md_path


def scan_history(
    repo_path: str,
    max_commits: int = 50,
    since: Optional[str] = None,
    branch: str = "main",
    output_dir: str = ".",
    config: Optional[CounterscarpConfig] = None,
    stderr_log: Optional[str] = None
) -> Dict[str, Any]:
    """Main entry point for historical vulnerability scanning.
    
    Orchestrates the full pipeline: parse history -> scan commits -> 
    build timeline -> generate trends -> write reports.
    
    Args:
        repo_path: Path to the Git repository.
        max_commits: Maximum number of commits to scan (default: 50).
        since: Optional date filter (ISO format).
        branch: Branch to scan (default: "main").
        output_dir: Directory to write reports.
        config: Optional CounterscarpConfig for heuristic scanning.
    
    Returns:
        Summary dictionary with counts and report paths.
    """
    logger.info("=" * 60)
    logger.info("Starting Historical Vulnerability Scan")
    logger.info("=" * 60)
    
    start_time = datetime.now()
    
    # Step 1: Parse Git history
    logger.info(f"[1/4] Parsing Git history from {repo_path}")
    commits = parse_git_history(repo_path, max_commits, since, branch, stderr_log)
    
    if not commits:
        logger.warning("No commits with .sol/.rs files found")
        return {
            "status": "no_commits",
            "total_commits": 0,
            "vulnerabilities_found": 0,
            "reports": None
        }
    
    # Step 2: Scan each commit
    logger.info(f"[2/4] Scanning {len(commits)} commits for vulnerabilities")
    scan_results = []
    
    for i, commit in enumerate(commits, 1):
        logger.info(f"Scanning commit {i}/{len(commits)}: {commit.hash[:8]} - {commit.message[:50]}")
        
        try:
            finding = scan_commit(repo_path, commit.hash, commit.changed_files, config, stderr_log)
            finding.date = commit.date
            finding.author = commit.author
            
            scan_results.append({
                "commit_hash": finding.commit_hash,
                "date": finding.date,
                "author": finding.author,
                "file": finding.file,
                "findings": finding.findings
            })
            
            if finding.findings:
                logger.info(f"  Found {len(finding.findings)} issues in this commit")
        
        except Exception as e:
            logger.warning(f"  Failed to scan commit {commit.hash[:8]}: {e}")
            continue
    
    # Step 3: Build timeline
    logger.info("[3/4] Building vulnerability timeline")
    timeline = build_timeline(scan_results)
    
    # Step 4: Generate trends
    logger.info("[4/4] Generating trend analysis")
    trends = generate_trends(timeline)
    
    # Step 5: Generate reports
    logger.info("Generating reports...")
    json_path, md_path = generate_history_report(timeline, trends, output_dir)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Summary
    summary = {
        "status": "success",
        "duration_seconds": round(duration, 2),
        "total_commits": len(commits),
        "commits_scanned": len(scan_results),
        "total_vulnerabilities": len(timeline),
        "active_vulnerabilities": trends["active_vulnerabilities"],
        "fixed_vulnerabilities": trends["fixed_vulnerabilities"],
        "fix_rate_percent": trends["fix_rate_percent"],
        "average_fix_time_days": trends["average_fix_time_days"],
        "reports": {
            "json": json_path,
            "markdown": md_path
        }
    }
    
    logger.info("=" * 60)
    logger.info("Historical Vulnerability Scan Complete")
    logger.info(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
    logger.info(f"Active: {summary['active_vulnerabilities']}, Fixed: {summary['fixed_vulnerabilities']}")
    logger.info(f"Fix rate: {summary['fix_rate_percent']}%")
    logger.info(f"Reports written to: {output_dir}")
    logger.info("=" * 60)
    
    return summary


def main() -> None:
    """CLI entry point for history scanner."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Time-Travel Historical Vulnerability Scanner"
    )
    parser.add_argument(
        "repo_path",
        help="Path to Git repository"
    )
    parser.add_argument(
        "--commits",
        type=int,
        default=50,
        help="Maximum commits to scan (default: 50)"
    )
    parser.add_argument(
        "--since",
        help="Only scan commits since this date (ISO format, e.g., 2024-01-01)"
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to scan (default: main)"
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Output directory for reports (default: current directory)"
    )
    parser.add_argument(
        "--config",
        help="Path to counterscarp.toml config file"
    )
    
    args = parser.parse_args()
    
    # Load config if provided
    config = None
    if args.config and load_config:
        try:
            config = load_config(args.config)
            print(f"[*] Loaded config: {config.engine.name} v{config.engine.version}")
        except Exception as e:
            print(f"[!] Error loading config: {e}")
    
    # Run scan
    try:
        results = scan_history(
            repo_path=args.repo_path,
            max_commits=args.commits,
            since=args.since,
            branch=args.branch,
            output_dir=args.output,
            config=config
        )
        
        print("\n" + "=" * 60)
        print("Historical Vulnerability Scan Complete")
        print("=" * 60)
        print(f"Duration: {results['duration_seconds']}s")
        print(f"Commits scanned: {results['commits_scanned']}")
        print(f"Vulnerabilities found: {results['total_vulnerabilities']}")
        print(f"  - Active: {results['active_vulnerabilities']}")
        print(f"  - Fixed: {results['fixed_vulnerabilities']}")
        print(f"Fix rate: {results['fix_rate_percent']}%")
        print(f"Avg fix time: {results['average_fix_time_days']} days")
        print("\nReports:")
        print(f"  JSON: {results['reports']['json']}")
        print(f"  Markdown: {results['reports']['markdown']}")
        
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        raise


if __name__ == "__main__":
    main()
