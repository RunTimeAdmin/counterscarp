#!/usr/bin/env python3
"""Tests for the pipeline_generator module.

This module contains unit tests for the CI/CD pipeline generator functionality,
including template generation for GitHub Actions, GitLab CI, Azure DevOps, and Jenkins.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline_generator import (
    generate_pipeline,
    _get_triggers,
    _get_analyzer_steps,
    _get_notification_steps,
    GITHUB_ACTIONS_TEMPLATE,
    GITLAB_CI_TEMPLATE,
    AZURE_DEVOPS_TEMPLATE,
    JENKINSFILE_TEMPLATE,
)

# Try to import config_loader
try:
    from config_loader import (
        CounterscarpConfig,
        CIConfig,
        CIGeneratorConfig,
        EngineConfig,
        StaticAnalysisConfig,
        FuzzingConfig,
        HeuristicConfig,
    )
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    CONFIG_LOADER_AVAILABLE = False


class TestPipelineGenerator(unittest.TestCase):
    """Test cases for the pipeline generator module."""

    def test_generate_pipeline_github(self):
        """Test generating a GitHub Actions pipeline."""
        content = generate_pipeline(
            config_path="counterscarp.toml",
            platform="github",
            target_path="./contracts"
        )
        
        # Verify basic structure
        self.assertIn("name: Counterscarp Security Audit", content)
        self.assertIn("on:", content)
        self.assertIn("jobs:", content)
        self.assertIn("runs-on: ubuntu-latest", content)
        self.assertIn("actions/checkout@v4", content)
        
    def test_generate_pipeline_gitlab(self):
        """Test generating a GitLab CI pipeline."""
        content = generate_pipeline(
            config_path="counterscarp.toml",
            platform="gitlab",
            target_path="./contracts"
        )
        
        # Verify basic structure
        self.assertIn("stages:", content)
        self.assertIn("- security", content)
        self.assertIn("counterscarp-security-scan:", content)
        self.assertIn("image: python:3.10-slim", content)
        
    def test_generate_pipeline_azure(self):
        """Test generating an Azure DevOps pipeline."""
        content = generate_pipeline(
            config_path="counterscarp.toml",
            platform="azure",
            target_path="./contracts"
        )
        
        # Verify basic structure
        self.assertIn("trigger:", content)
        self.assertIn("pool:", content)
        self.assertIn("steps:", content)
        self.assertIn("UsePythonVersion@0", content)
        
    def test_generate_pipeline_jenkins(self):
        """Test generating a Jenkinsfile."""
        content = generate_pipeline(
            config_path="counterscarp.toml",
            platform="jenkins",
            target_path="./contracts"
        )
        
        # Verify basic structure
        self.assertIn("pipeline {", content)
        self.assertIn("agent any", content)
        self.assertIn("stages {", content)
        self.assertIn("post {", content)
        
    def test_generate_pipeline_invalid_platform(self):
        """Test that invalid platform raises an error."""
        with self.assertRaises(Exception) as context:
            generate_pipeline(
                config_path="counterscarp.toml",
                platform="invalid_platform"
            )
        
        self.assertIn("Unsupported platform", str(context.exception))
        
    def test_generate_pipeline_writes_file(self):
        """Test that pipeline is written to file when output_path is provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "test-workflow.yml")
            
            content = generate_pipeline(
                config_path="counterscarp.toml",
                platform="github",
                output_path=output_path
            )
            
            # Verify file was created
            self.assertTrue(os.path.exists(output_path))
            
            # Verify content matches
            with open(output_path, 'r') as f:
                file_content = f.read()
            self.assertEqual(content, file_content)
            
    def test_get_triggers_github(self):
        """Test trigger generation for GitHub."""
        triggers = _get_triggers(None, "github")
        
        # Should include default triggers
        self.assertIn("push:", triggers)
        self.assertIn("pull_request:", triggers)
        
    def test_get_triggers_gitlab(self):
        """Test trigger generation for GitLab."""
        triggers = _get_triggers(None, "gitlab")
        
        # Should include CI variables
        self.assertIn("$CI_COMMIT_BRANCH", triggers)
        
    @unittest.skipUnless(CONFIG_LOADER_AVAILABLE, "Config loader not available")
    def test_get_triggers_with_config(self):
        """Test trigger generation with config object."""
        config = CounterscarpConfig()
        config.ci = CIConfig()
        config.ci.generator = CIGeneratorConfig(
            triggers=["schedule", "workflow_dispatch"]
        )
        
        triggers = _get_triggers(config, "github")
        
        self.assertIn("schedule:", triggers)
        self.assertIn("workflow_dispatch:", triggers)
        
    @unittest.skipUnless(CONFIG_LOADER_AVAILABLE, "Config loader not available")
    def test_get_analyzer_steps_with_config(self):
        """Test analyzer steps with config."""
        config = CounterscarpConfig()
        config.static_analysis = StaticAnalysisConfig(
            slither_enabled=True,
            aderyn_enabled=True
        )
        config.fuzzing = FuzzingConfig(medusa_enabled=False)
        config.heuristics = HeuristicConfig(enabled=True)
        
        steps = _get_analyzer_steps(config, "github", "./contracts", "counterscarp.toml")
        
        # Should include enabled analyzers
        self.assertIn("slither", steps.lower())
        
    @unittest.skipUnless(CONFIG_LOADER_AVAILABLE, "Config loader not available")
    def test_get_notification_steps_with_slack(self):
        """Test notification steps with Slack enabled."""
        config = CounterscarpConfig()
        config.ci = CIConfig()
        config.ci.generator = CIGeneratorConfig(
            notifications=["slack"]
        )
        
        steps = _get_notification_steps(config, "github")
        
        self.assertIn("slack", steps.lower())
        
    def test_github_template_contains_key_elements(self):
        """Verify GitHub template has all required elements."""
        # Check template constants
        self.assertIn("{triggers}", GITHUB_ACTIONS_TEMPLATE)
        self.assertIn("{fail_on_severity}", GITHUB_ACTIONS_TEMPLATE)
        self.assertIn("{report_format}", GITHUB_ACTIONS_TEMPLATE)
        self.assertIn("{target_path}", GITHUB_ACTIONS_TEMPLATE)
        self.assertIn("{analyzer_steps}", GITHUB_ACTIONS_TEMPLATE)
        
    def test_gitlab_template_contains_key_elements(self):
        """Verify GitLab template has all required elements."""
        self.assertIn("{trigger_rules}", GITLAB_CI_TEMPLATE)
        self.assertIn("{fail_on_severity}", GITLAB_CI_TEMPLATE)
        self.assertIn("{target_path}", GITLAB_CI_TEMPLATE)
        
    def test_azure_template_contains_key_elements(self):
        """Verify Azure template has all required elements."""
        self.assertIn("{triggers}", AZURE_DEVOPS_TEMPLATE)
        self.assertIn("{fail_on_severity}", AZURE_DEVOPS_TEMPLATE)
        self.assertIn("{target_path}", AZURE_DEVOPS_TEMPLATE)
        
    def test_jenkins_template_contains_key_elements(self):
        """Verify Jenkins template has all required elements."""
        self.assertIn("{analyzer_stages}", JENKINSFILE_TEMPLATE)
        self.assertIn("{fail_on_severity}", JENKINSFILE_TEMPLATE)
        self.assertIn("{target_path}", JENKINSFILE_TEMPLATE)
        
    def test_platform_case_insensitive(self):
        """Test that platform names are case insensitive."""
        for platform in ["GITHUB", "GitLab", "Azure", "JENKINS"]:
            content = generate_pipeline(
                config_path="counterscarp.toml",
                platform=platform,
                target_path="./contracts"
            )
            self.assertIsNotNone(content)
            self.assertGreater(len(content), 0)


class TestPipelineGeneratorIntegration(unittest.TestCase):
    """Integration tests for the pipeline generator."""
    
    @unittest.skipUnless(CONFIG_LOADER_AVAILABLE, "Config loader not available")
    def test_full_config_integration(self):
        """Test pipeline generation with full configuration."""
        config = CounterscarpConfig()
        config.engine = EngineConfig(
            fail_on_severity="MEDIUM",
            name="Test Engine",
            version="1.0"
        )
        config.static_analysis = StaticAnalysisConfig(
            slither_enabled=True,
            aderyn_enabled=True
        )
        config.fuzzing = FuzzingConfig(
            foundry_enabled=True,
            medusa_enabled=True
        )
        config.heuristics = HeuristicConfig(enabled=True)
        config.ci = CIConfig()
        config.ci.generator = CIGeneratorConfig(
            platform="github",
            triggers=["push", "pull_request", "schedule"],
            notifications=["slack"]
        )
        
        content = generate_pipeline(
            config_path="counterscarp.toml",
            platform="github",
            target_path="./contracts"
        )
        
        # Verify content is generated
        self.assertIn("Counterscarp Security Audit", content)
        
    def test_output_directory_creation(self):
        """Test that output directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = os.path.join(tmpdir, "nested", "path")
            output_path = os.path.join(nested_dir, "workflow.yml")
            
            content = generate_pipeline(
                config_path="counterscarp.toml",
                platform="github",
                output_path=output_path
            )
            
            self.assertTrue(os.path.exists(nested_dir))
            self.assertTrue(os.path.exists(output_path))


if __name__ == "__main__":
    unittest.main()
