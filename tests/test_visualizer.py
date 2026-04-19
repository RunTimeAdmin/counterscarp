"""
Tests for the visualizer module.
"""

import pytest
import sys
import os

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from visualizer import (
    generate_attack_graph_html,
    generate_attack_graph_with_paths,
    _generate_d3_js,
    _generate_html_template,
    NODE_COLORS,
    SEVERITY_COLORS,
    EDGE_STYLES,
)


# =============================================================================
# generate_attack_graph_html Tests
# =============================================================================

class TestGenerateAttackGraphHtml:
    """Test generate_attack_graph_html function."""

    def test_generates_valid_html(self, tmp_path, sample_attack_graph_data):
        """Test that function generates valid HTML file."""
        output_path = str(tmp_path / "test_graph.html")
        
        result = generate_attack_graph_html(
            sample_attack_graph_data,
            output_path,
            "Test Project Analysis"
        )
        
        assert result == output_path
        assert os.path.exists(output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert content.startswith('<!DOCTYPE html>')
        assert '<html' in content
        assert '</html>' in content

    def test_html_contains_d3_script(self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains D3.js script reference."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert 'd3.v7.min.js' in content
        assert 'd3.' in content or 'd3[' in content

    def test_html_contains_graph_data(
            self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains embedded graph data."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain graph data
        assert 'graphData' in content or 'graph_data' in content
        assert 'nodes' in content
        assert 'links' in content

    def test_html_contains_title(self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains the specified title."""
        output_path = str(tmp_path / "test_graph.html")
        title = "My Custom Analysis"
        
        generate_attack_graph_html(
            sample_attack_graph_data, output_path, title)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert title in content
        assert '<title>' in content

    def test_html_contains_statistics(
            self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains statistics panel."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain stats section
        assert 'Statistics' in content or 'stats' in content.lower()

    def test_html_contains_severity_filter(
        self, tmp_path, sample_attack_graph_data
    ):
        """Test that HTML contains severity filtering elements."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain severity filters
        assert 'CRITICAL' in content
        assert 'HIGH' in content
        assert 'MEDIUM' in content
        assert 'LOW' in content

    def test_html_contains_search_functionality(
        self, tmp_path, sample_attack_graph_data
    ):
        """Test that HTML contains search functionality."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain search elements
        assert 'search' in content.lower()
        assert 'searchInput' in content or 'searchNodes' in content

    def test_html_contains_zoom_controls(
            self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains zoom controls."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain zoom controls
        assert 'zoomIn' in content or 'zoom' in content.lower()

    def test_html_contains_node_legend(
            self, tmp_path, sample_attack_graph_data):
        """Test that HTML contains node type legend."""
        output_path = str(tmp_path / "test_graph.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain node type references
        assert 'Contract' in content
        assert 'Function' in content
        assert 'Vulnerability' in content

    def test_empty_graph_data(self, tmp_path):
        """Test generating HTML with empty graph data."""
        output_path = str(tmp_path / "empty_graph.html")
        empty_graph = {"nodes": [], "links": []}
        
        generate_attack_graph_html(empty_graph, output_path)
        
        assert os.path.exists(output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert content.startswith('<!DOCTYPE html>')


# =============================================================================
# generate_attack_graph_with_paths Tests
# =============================================================================

class TestGenerateAttackGraphWithPaths:
    """Test generate_attack_graph_with_paths function."""

    def test_generates_html_with_paths(
            self, tmp_path, sample_attack_graph_data):
        """Test that function generates HTML with attack paths."""
        output_path = str(tmp_path / "paths_graph.html")
        attack_paths = [
            ["Contract_Vault_1234", "Function_withdraw_1234_L45",
             "Vulnerability_REENTRANCY_1234_L50"]
        ]
        
        result = generate_attack_graph_with_paths(
            sample_attack_graph_data,
            attack_paths,
            output_path,
            "Attack Path Analysis"
        )
        
        assert result == output_path
        assert os.path.exists(output_path)

    def test_includes_path_metadata(self, tmp_path, sample_attack_graph_data):
        """Test that attack paths are included in graph data."""
        output_path = str(tmp_path / "paths_graph.html")
        attack_paths = [["node1", "node2", "node3"]]
        
        generate_attack_graph_with_paths(
            sample_attack_graph_data,
            attack_paths,
            output_path
        )
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Should contain path information
        assert 'attack_paths' in content or 'path_count' in content


# =============================================================================
# _generate_d3_js Tests
# =============================================================================

class TestGenerateD3Js:
    """Test _generate_d3_js function."""

    def test_generates_javascript_code(self, sample_attack_graph_data):
        """Test that function generates JavaScript code."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert isinstance(js_code, str)
        assert len(js_code) > 0

    def test_contains_force_simulation(self, sample_attack_graph_data):
        """Test that JS contains force simulation setup."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'forceSimulation' in js_code
        assert 'forceLink' in js_code
        assert 'forceManyBody' in js_code

    def test_contains_node_rendering(self, sample_attack_graph_data):
        """Test that JS contains node rendering code."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'append' in js_code
        assert 'circle' in js_code

    def test_contains_link_rendering(self, sample_attack_graph_data):
        """Test that JS contains link rendering code."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'line' in js_code.lower() or 'link' in js_code.lower()

    def test_contains_zoom_behavior(self, sample_attack_graph_data):
        """Test that JS contains zoom behavior."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'zoom' in js_code.lower()

    def test_contains_drag_behavior(self, sample_attack_graph_data):
        """Test that JS contains drag behavior."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'drag' in js_code.lower()

    def test_contains_tooltip(self, sample_attack_graph_data):
        """Test that JS contains tooltip functionality."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'tooltip' in js_code.lower()

    def test_contains_graph_data_reference(self, sample_attack_graph_data):
        """Test that JS references the graph data."""
        js_code = _generate_d3_js(sample_attack_graph_data)
        
        assert 'graphData' in js_code


# =============================================================================
# _generate_html_template Tests
# =============================================================================

class TestGenerateHtmlTemplate:
    """Test _generate_html_template function."""

    def test_generates_complete_html(self, sample_attack_graph_data):
        """Test that function generates complete HTML document."""
        js_code = "// Test JS"
        html = _generate_html_template(
            "Test", js_code, sample_attack_graph_data)

        assert '<!DOCTYPE html>' in html
        assert '<html' in html
        assert '<head>' in html
        assert '<body>' in html
        assert '</html>' in html

    def test_includes_title(self, sample_attack_graph_data):
        """Test that HTML includes the title."""
        js_code = "// Test JS"
        title = "My Analysis"
        html = _generate_html_template(
            title, js_code, sample_attack_graph_data)
        
        assert title in html
        assert '<title>' in html

    def test_includes_d3js_cdn(self, sample_attack_graph_data):
        """Test that HTML includes D3.js CDN link."""
        js_code = "// Test JS"
        html = _generate_html_template(
            "Test", js_code, sample_attack_graph_data)

        assert 'd3js.org' in html or 'd3.v7' in html

    def test_includes_styles(self, sample_attack_graph_data):
        """Test that HTML includes CSS styles."""
        js_code = "// Test JS"
        html = _generate_html_template(
            "Test", js_code, sample_attack_graph_data)
        
        assert '<style>' in html
        assert '{' in html  # CSS rules

    def test_includes_javascript(self, sample_attack_graph_data):
        """Test that HTML includes the JavaScript code."""
        js_code = "// Custom test code"
        html = _generate_html_template("Test", js_code, sample_attack_graph_data)
        
        assert js_code in html
        assert '<script>' in html


# =============================================================================
# Color Constants Tests
# =============================================================================

class TestColorConstants:
    """Test color constant definitions."""

    def test_node_colors_defined(self):
        """Test that node colors are defined for all types."""
        expected_types = ["Contract", "Function", "Vulnerability",
                          "ExternalCall", "StateVariable"]
        
        for node_type in expected_types:
            assert node_type in NODE_COLORS
            assert NODE_COLORS[node_type].startswith('#')

    def test_severity_colors_defined(self):
        """Test that severity colors are defined for all levels."""
        expected_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        
        for severity in expected_severities:
            assert severity in SEVERITY_COLORS
            assert SEVERITY_COLORS[severity].startswith('#')

    def test_edge_styles_defined(self):
        """Test that edge styles are defined for all types."""
        expected_types = ["calls", "reads", "writes", "delegates",
                          "inherits", "contains", "triggers"]
        
        for edge_type in expected_types:
            assert edge_type in EDGE_STYLES
            assert 'stroke' in EDGE_STYLES[edge_type]
            assert 'strokeWidth' in EDGE_STYLES[edge_type]


# =============================================================================
# Integration Tests
# =============================================================================

class TestVisualizerIntegration:
    """Integration tests for visualizer module."""

    def test_end_to_end_workflow(self, tmp_path, sample_attack_graph_data):
        """Test complete workflow from graph data to HTML file."""
        output_path = str(tmp_path / "integration_test.html")
        
        # Generate HTML
        result = generate_attack_graph_html(
            sample_attack_graph_data,
            output_path,
            "Integration Test"
        )
        
        # Verify file was created
        assert os.path.exists(result)
        
        # Read and verify content
        with open(result, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Verify all expected components are present
        assert '<!DOCTYPE html>' in content
        assert 'Integration Test' in content
        assert 'd3.v7.min.js' in content
        assert 'graphData' in content
        assert 'Statistics' in content
        assert 'Search' in content or 'search' in content.lower()
        assert 'CRITICAL' in content
        assert 'Contract' in content
        assert 'Function' in content
        assert 'Vulnerability' in content

    def test_file_written_to_specified_path(
            self, tmp_path, sample_attack_graph_data):
        """Test that file is written to the specified path."""
        output_path = str(tmp_path / "subdir" / "nested_graph.html")
        
        # Create parent directory
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        assert os.path.exists(output_path)

    def test_html_valid_structure(self, tmp_path, sample_attack_graph_data):
        """Test that generated HTML has valid structure."""
        output_path = str(tmp_path / "valid_test.html")
        
        generate_attack_graph_html(sample_attack_graph_data, output_path)
        
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for balanced tags (HTML has <html lang="en">)
        assert content.count('<html') == 1
        assert content.count('</html>') == 1
        assert content.count('<head>') == content.count('</head>')
        assert content.count('<body>') == content.count('</body>')
        # Script tags may appear in JS code strings, just check presence
        assert '<script>' in content
        assert '</script>' in content
        assert content.count('<style>') == content.count('</style>')
