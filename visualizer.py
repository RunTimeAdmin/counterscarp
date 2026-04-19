#!/usr/bin/env python3
"""
Interactive D3.js Attack Graph Visualizer for Sentinel Engine.

Generates self-contained HTML files with interactive force-directed
graph visualizations of attack paths and vulnerabilities.

Example:
    >>> from visualizer import generate_attack_graph_html
    >>> from attack_graph import build_graph, export_graph_json
    >>> graph = build_graph(findings, source_files)
    >>> graph_json = export_graph_json(graph)
    >>> html_path = generate_attack_graph_html(
    ...     graph_json, "attack_graph.html", "My Project Analysis"
    ... )
"""

from __future__ import annotations

import json
import os
from typing import Dict, Any, Optional, List

from logger import get_logger
from exceptions import SentinelReportError

logger = get_logger(__name__)


# Color scheme for node types
NODE_COLORS = {
    "Contract": "#4A90E2",        # Blue
    "Function": "#50C878",        # Green
    "Vulnerability": "#E74C3C",   # Red
    "ExternalCall": "#F39C12",    # Orange
    "StateVariable": "#95A5A6"    # Gray
}

# Severity colors for vulnerabilities
SEVERITY_COLORS = {
    "CRITICAL": "#8B0000",  # Dark Red
    "HIGH": "#E74C3C",      # Red
    "MEDIUM": "#F39C12",    # Orange
    "LOW": "#3498DB",       # Blue
    "INFO": "#95A5A6"       # Gray
}

# Edge styling
EDGE_STYLES = {
    "calls": {"stroke": "#ffffff", "strokeWidth": 1.5, "dash": "none"},
    "reads": {"stroke": "#aaaaaa", "strokeWidth": 1, "dash": "5,5"},
    "writes": {"stroke": "#ff6b6b", "strokeWidth": 1.5, "dash": "2,2"},
    "delegates": {"stroke": "#ff9f43", "strokeWidth": 3, "dash": "none"},
    "inherits": {"stroke": "#4ecdc4", "strokeWidth": 2, "dash": "10,5"},
    "contains": {"stroke": "#666666", "strokeWidth": 1, "dash": "none"},
    "triggers": {"stroke": "#e74c3c", "strokeWidth": 2, "dash": "none"}
}


def _generate_d3_js(graph_data: Dict[str, Any]) -> str:
    """Generate the D3.js JavaScript code for the visualization.

    Args:
        graph_data: The graph data with nodes and links.

    Returns:
        JavaScript code string.
    """
    # Convert graph data to JSON string for embedding
    graph_json = json.dumps(graph_data)
    
    return f"""
        // Graph data
        const graphData = {graph_json};
        
        // Node colors
        const nodeColors = {json.dumps(NODE_COLORS)};
        const severityColors = {json.dumps(SEVERITY_COLORS)};
        const edgeStyles = {json.dumps(EDGE_STYLES)};
        
        // Get container dimensions
        const container = document.getElementById('graph-container');
        const width = container.clientWidth;
        const height = container.clientHeight;
        
        // Create SVG
        const svg = d3.select('#graph-container')
            .append('svg')
            .attr('width', width)
            .attr('height', height)
            .attr('viewBox', [0, 0, width, height]);
        
        // Add zoom behavior
        const g = svg.append('g');
        
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {{
                g.attr('transform', event.transform);
            }});
        
        svg.call(zoom);
        
        // Create force simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force('link', d3.forceLink(graphData.links)
                .id(d => d.id)
                .distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(d => (d.size || 10) + 10));
        
        // Create arrow markers
        const defs = svg.append('defs');
        
        Object.keys(edgeStyles).forEach(type => {{
            defs.append('marker')
                .attr('id', `arrow-${{type}}`)
                .attr('viewBox', '0 -5 10 10')
                .attr('refX', 25)
                .attr('refY', 0)
                .attr('markerWidth', 6)
                .attr('markerHeight', 6)
                .attr('orient', 'auto')
                .append('path')
                .attr('d', 'M0,-5L10,0L0,5')
                .attr('fill', edgeStyles[type].stroke);
        }});
        
        // Create links
        const link = g.append('g')
            .attr('class', 'links')
            .selectAll('line')
            .data(graphData.links)
            .enter()
            .append('line')
            .attr('stroke', d => edgeStyles[d.type]?.stroke || '#999')
            .attr('stroke-width', d => edgeStyles[d.type]?.strokeWidth || 1)
            .attr('stroke-dasharray', d => edgeStyles[d.type]?.dash || 'none')
            .attr('marker-end', d => `url(#arrow-${{d.type}})`);
        
        // Create nodes
        const node = g.append('g')
            .attr('class', 'nodes')
            .selectAll('g')
            .data(graphData.nodes)
            .enter()
            .append('g')
            .attr('class', 'node')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Add circles to nodes
        node.append('circle')
            .attr('r', d => d.size || 10)
            .attr('fill', d => {{
                if (d.type === 'Vulnerability') {{
                    return severityColors[d.severity] || nodeColors[d.type];
                }}
                return nodeColors[d.type] || '#999';
            }})
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
        
        // Add labels to nodes
        node.append('text')
            .attr('dy', d => (d.size || 10) + 15)
            .attr('text-anchor', 'middle')
            .text(d => d.name)
            .attr('class', 'node-label');
        
        // Tooltip
        const tooltip = d3.select('body').append('div')
            .attr('class', 'tooltip')
            .style('opacity', 0);
        
        // Node hover events
        node.on('mouseover', function(event, d) {{
            tooltip.transition()
                .duration(200)
                .style('opacity', .9);
            tooltip.html(`<strong>${{d.name}}</strong><br/>Type: ${{d.type}}`)
                .style('left', (event.pageX + 10) + 'px')
                .style('top', (event.pageY - 28) + 'px');
        }})
        .on('mouseout', function(d) {{
            tooltip.transition()
                .duration(500)
                .style('opacity', 0);
        }});
        
        // Node click event
        node.on('click', function(event, d) {{
            showNodeDetails(d);
        }});
        
        // Update positions on tick
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // Store references for filtering
        window.graphNodes = node;
        window.graphLinks = link;
        window.graphData = graphData;
    """


def _generate_html_template(
    title: str,
    d3_js: str,
    graph_data: Dict[str, Any],
    logo_html: str = ""
) -> str:
    """Generate the complete HTML template.

    Args:
        title: The page title.
        d3_js: The D3.js JavaScript code.
        graph_data: The graph data for statistics.

    Returns:
        Complete HTML string.
    """
    # Count node types for statistics
    node_counts = {}
    for node in graph_data.get('nodes', []):
        node_type = node.get('type', 'Unknown')
        node_counts[node_type] = node_counts.get(node_type, 0) + 1
    
    # Count severities
    severity_counts = {}
    for node in graph_data.get('nodes', []):
        if node.get('type') == 'Vulnerability':
            sev = node.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #ffffff;
            min-height: 100vh;
            overflow: hidden;
        }}
        
        .header {{
            background: rgba(0, 0, 0, 0.3);
            padding: 15px 30px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .header h1 {{
            font-size: 1.5em;
            font-weight: 300;
            letter-spacing: 1px;
        }}
        
        .main-container {{
            display: flex;
            height: calc(100vh - 70px);
        }}
        
        .sidebar {{
            width: 320px;
            background: rgba(0, 0, 0, 0.2);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            padding: 20px;
            overflow-y: auto;
        }}
        
        .graph-area {{
            flex: 1;
            position: relative;
        }}
        
        #graph-container {{
            width: 100%;
            height: 100%;
        }}
        
        .panel {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        
        .panel h3 {{
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            color: #4ecdc4;
        }}
        
        .filter-group {{
            margin-bottom: 15px;
        }}
        
        .filter-group label {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            cursor: pointer;
            font-size: 0.9em;
        }}
        
        .filter-group input[type="checkbox"] {{
            margin-right: 10px;
            cursor: pointer;
        }}
        
        .color-indicator {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
            display: inline-block;
        }}
        
        .search-box {{
            width: 100%;
            padding: 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.3);
            color: #fff;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #4ecdc4;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }}
        
        .stat-item {{
            background: rgba(255, 255, 255, 0.05);
            padding: 10px;
            border-radius: 4px;
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #4ecdc4;
        }}
        
        .stat-label {{
            font-size: 0.75em;
            color: #888;
            text-transform: uppercase;
        }}
        
        .node-label {{
            font-size: 11px;
            fill: #ffffff;
            pointer-events: none;
            text-shadow: 0 1px 3px rgba(0,0,0,0.8);
        }}
        
        .tooltip {{
            position: absolute;
            text-align: center;
            padding: 8px 12px;
            font-size: 12px;
            background: rgba(0, 0, 0, 0.9);
            color: #fff;
            border-radius: 4px;
            pointer-events: none;
            z-index: 1000;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        
        .details-panel {{
            display: none;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
        }}
        
        .details-panel.active {{
            display: block;
        }}
        
        .details-panel h4 {{
            color: #4ecdc4;
            margin-bottom: 10px;
            font-size: 1em;
        }}
        
        .details-row {{
            margin-bottom: 8px;
            font-size: 0.85em;
        }}
        
        .details-label {{
            color: #888;
            display: inline-block;
            width: 80px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #8B0000; }}
        .severity-high {{ background: #E74C3C; }}
        .severity-medium {{ background: #F39C12; }}
        .severity-low {{ background: #3498DB; }}
        .severity-info {{ background: #95A5A6; }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 6px;
            font-size: 0.85em;
        }}
        
        .legend-line {{
            width: 30px;
            height: 2px;
            margin-right: 8px;
        }}
        
        button {{
            background: #4ecdc4;
            color: #1a1a2e;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85em;
            font-weight: bold;
            margin-top: 10px;
            width: 100%;
        }}
        
        button:hover {{
            background: #45b7b8;
        }}
        
        .controls {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            display: flex;
            gap: 10px;
        }}
        
        .control-btn {{
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.2);
            color: #fff;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2em;
        }}
        
        .control-btn:hover {{
            background: rgba(78, 205, 196, 0.3);
        }}
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center;">
            {logo_html}
            <h1>🔍 {title}</h1>
        </div>
        <div style="color: #888; font-size: 0.9em;">
            Sentinel Engine Attack Path Visualizer
        </div>
    </div>
    
    <div class="main-container">
        <div class="sidebar">
            <div class="panel">
                <h3>Statistics</h3>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value">{node_counts.get('Vulnerability', 0)}</div>
                        <div class="stat-label">Vulns</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{node_counts.get('Contract', 0)}</div>
                        <div class="stat-label">Contracts</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{node_counts.get('Function', 0)}</div>
                        <div class="stat-label">Functions</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">{len(graph_data.get('links', []))}</div>
                        <div class="stat-label">Edges</div>
                    </div>
                </div>
            </div>
            
            <div class="panel">
                <h3>Search</h3>
                <input type="text" class="search-box" id="searchInput" 
                       placeholder="Search nodes..." onkeyup="searchNodes()">
            </div>
            
            <div class="panel">
                <h3>Node Filters</h3>
                <div class="filter-group">
                    <label>
                        <input type="checkbox" checked onchange="toggleNodeType('Contract')">
                        <span class="color-indicator" style="background: {NODE_COLORS['Contract']}"></span>
                        Contracts
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleNodeType('Function')">
                        <span class="color-indicator" style="background: {NODE_COLORS['Function']}"></span>
                        Functions
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleNodeType('Vulnerability')">
                        <span class="color-indicator" style="background: {NODE_COLORS['Vulnerability']}"></span>
                        Vulnerabilities
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleNodeType('ExternalCall')">
                        <span class="color-indicator" style="background: {NODE_COLORS['ExternalCall']}"></span>
                        External Calls
                    </label>
                </div>
            </div>
            
            <div class="panel">
                <h3>Severity Filter</h3>
                <div class="filter-group">
                    <label>
                        <input type="checkbox" checked onchange="toggleSeverity('CRITICAL')">
                        <span class="color-indicator" style="background: {SEVERITY_COLORS['CRITICAL']}"></span>
                        Critical
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleSeverity('HIGH')">
                        <span class="color-indicator" style="background: {SEVERITY_COLORS['HIGH']}"></span>
                        High
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleSeverity('MEDIUM')">
                        <span class="color-indicator" style="background: {SEVERITY_COLORS['MEDIUM']}"></span>
                        Medium
                    </label>
                    <label>
                        <input type="checkbox" checked onchange="toggleSeverity('LOW')">
                        <span class="color-indicator" style="background: {SEVERITY_COLORS['LOW']}"></span>
                        Low
                    </label>
                </div>
            </div>
            
            <div class="panel">
                <h3>Edge Legend</h3>
                <div class="legend-item">
                    <div class="legend-line" style="background: #fff;"></div>
                    <span>Calls</span>
                </div>
                <div class="legend-item">
                    <div class="legend-line" style="background: #aaa; border-top: 2px dashed #aaa; height: 0;"></div>
                    <span>Reads</span>
                </div>
                <div class="legend-item">
                    <div class="legend-line" style="background: #ff6b6b; border-top: 2px dotted #ff6b6b; height: 0;"></div>
                    <span>Writes</span>
                </div>
                <div class="legend-item">
                    <div class="legend-line" style="background: #ff9f43; height: 3px;"></div>
                    <span>Delegates</span>
                </div>
                <div class="legend-item">
                    <div class="legend-line" style="background: #4ecdc4; border-top: 2px double #4ecdc4; height: 0;"></div>
                    <span>Inherits</span>
                </div>
            </div>
            
            <div class="details-panel" id="detailsPanel">
                <h4>Node Details</h4>
                <div id="detailsContent"></div>
            </div>
        </div>
        
        <div class="graph-area">
            <div id="graph-container"></div>
            <div class="controls">
                <button class="control-btn" onclick="zoomIn()" title="Zoom In">+</button>
                <button class="control-btn" onclick="zoomOut()" title="Zoom Out">−</button>
                <button class="control-btn" onclick="resetZoom()" title="Reset">⟲</button>
            </div>
        </div>
    </div>
    
    <script>
        {d3_js}
        
        // Filter state
        const activeNodeTypes = new Set(['Contract', 'Function', 'Vulnerability', 'ExternalCall', 'StateVariable']);
        const activeSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
        
        // Toggle node type visibility
        function toggleNodeType(nodeType) {{
            if (activeNodeTypes.has(nodeType)) {{
                activeNodeTypes.delete(nodeType);
            }} else {{
                activeNodeTypes.add(nodeType);
            }}
            updateVisibility();
        }}
        
        // Toggle severity visibility
        function toggleSeverity(severity) {{
            if (activeSeverities.has(severity)) {{
                activeSeverities.delete(severity);
            }} else {{
                activeSeverities.add(severity);
            }}
            updateVisibility();
        }}
        
        // Update node visibility based on filters
        function updateVisibility() {{
            window.graphNodes.style('opacity', d => {{
                if (!activeNodeTypes.has(d.type)) return 0.1;
                if (d.type === 'Vulnerability' && !activeSeverities.has(d.severity)) return 0.1;
                return 1;
            }});
            
            window.graphLinks.style('opacity', d => {{
                const sourceVisible = activeNodeTypes.has(d.source.type);
                const targetVisible = activeNodeTypes.has(d.target.type);
                return (sourceVisible && targetVisible) ? 1 : 0.1;
            }});
        }}
        
        // Search functionality
        function searchNodes() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            
            window.graphNodes.style('opacity', d => {{
                if (!query) return 1;
                const match = d.name.toLowerCase().includes(query) ||
                             d.type.toLowerCase().includes(query);
                return match ? 1 : 0.1;
            }});
            
            window.graphLinks.style('opacity', 0.1);
        }}
        
        // Show node details
        function showNodeDetails(node) {{
            const panel = document.getElementById('detailsPanel');
            const content = document.getElementById('detailsContent');
            
            let html = `
                <div class="details-row">
                    <span class="details-label">Name:</span>
                    <span>${{node.name}}</span>
                </div>
                <div class="details-row">
                    <span class="details-label">Type:</span>
                    <span>${{node.type}}</span>
                </div>
            `;
            
            if (node.type === 'Vulnerability') {{
                html += `
                    <div class="details-row">
                        <span class="details-label">Severity:</span>
                        <span class="severity-badge severity-${{node.severity.toLowerCase()}}">${{node.severity}}</span>
                    </div>
                    <div class="details-row">
                        <span class="details-label">Rule:</span>
                        <span>${{node.rule_id || 'N/A'}}</span>
                    </div>
                    <div class="details-row">
                        <span class="details-label">File:</span>
                        <span>${{node.file || 'N/A'}}</span>
                    </div>
                    <div class="details-row">
                        <span class="details-label">Line:</span>
                        <span>${{node.line || 'N/A'}}</span>
                    </div>
                    <div class="details-row" style="margin-top: 10px;">
                        <span class="details-label">Description:</span>
                        <p style="margin-top: 5px; color: #aaa;">${{node.description || 'No description available'}}</p>
                    </div>
                `;
            }} else if (node.file) {{
                html += `
                    <div class="details-row">
                        <span class="details-label">File:</span>
                        <span>${{node.file}}</span>
                    </div>
                    <div class="details-row">
                        <span class="details-label">Line:</span>
                        <span>${{node.line || 'N/A'}}</span>
                    </div>
                `;
            }}
            
            if (node.visibility) {{
                html += `
                    <div class="details-row">
                        <span class="details-label">Visibility:</span>
                        <span>${{node.visibility}}</span>
                    </div>
                `;
            }}
            
            content.innerHTML = html;
            panel.classList.add('active');
        }}
        
        // Zoom controls
        function zoomIn() {{
            d3.select('#graph-container svg').transition().call(
                d3.zoom().transform,
                d3.zoomTransform(d3.select('#graph-container svg').node()).scale(1.3)
            );
        }}
        
        function zoomOut() {{
            d3.select('#graph-container svg').transition().call(
                d3.zoom().transform,
                d3.zoomTransform(d3.select('#graph-container svg').node()).scale(0.7)
            );
        }}
        
        function resetZoom() {{
            d3.select('#graph-container svg').transition().call(
                d3.zoom().transform,
                d3.zoomIdentity
            );
        }}
    </script>
</body>
</html>"""


def generate_attack_graph_html(
    graph_json: Dict[str, Any],
    output_path: str,
    title: str = "Attack Path Analysis",
    logo_path: Optional[str] = None
) -> str:
    """Generate an interactive HTML file with D3.js attack graph visualization.

    Creates a self-contained HTML file with embedded D3.js visualization
    featuring force-directed layout, interactive filtering, zoom/pan,
    and detailed node inspection.

    Args:
        graph_json: Graph data dictionary with 'nodes' and 'links' keys.
        output_path: Path where the HTML file will be saved.
        title: Title for the visualization page.
        logo_path: Optional path to a logo image file to embed in the visualization.

    Returns:
        Path to the generated HTML file.

    Raises:
        SentinelReportError: If HTML generation fails.

    Example:
        >>> from attack_graph import build_graph, export_graph_json
        >>> graph = build_graph(findings, source_files)
        >>> graph_json = export_graph_json(graph)
        >>> html_path = generate_attack_graph_html(
        ...     graph_json, "report.html", "Project X Analysis"
        ... )
        >>> print(f"Report saved to: {html_path}")
    """
    try:
        logger.info(f"Generating attack graph HTML: {output_path}")
        
        # Process logo if provided
        logo_html = ""
        if logo_path and os.path.exists(logo_path):
            import base64
            from pathlib import Path
            with open(logo_path, 'rb') as f:
                logo_data = f.read()
            logo_b64 = base64.b64encode(logo_data).decode('utf-8')
            ext = Path(logo_path).suffix.lower().lstrip('.')
            mime = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'svg': 'image/svg+xml'}.get(ext, 'image/png')
            logo_html = f'<img src="data:{mime};base64,{logo_b64}" alt="Sentinel Engine" style="height: 40px; margin-right: 12px; vertical-align: middle;">'
        
        # Generate D3.js code
        d3_js = _generate_d3_js(graph_json)
        
        # Generate complete HTML
        html = _generate_html_template(title, d3_js, graph_json, logo_html)
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Attack graph HTML saved to: {output_path}")
        return output_path
        
    except (IOError, OSError) as e:
        logger.error(f"Failed to write HTML file: {e}")
        raise SentinelReportError(
            "Failed to generate attack graph HTML",
            details={"output_path": output_path, "error": str(e)}
        ) from e
    except Exception as e:
        logger.error(f"Unexpected error generating HTML: {e}")
        raise SentinelReportError(
            "Failed to generate attack graph visualization",
            details={"error": str(e)}
        ) from e


def generate_attack_graph_with_paths(
    graph_json: Dict[str, Any],
    attack_paths: List[List[str]],
    output_path: str,
    title: str = "Attack Path Analysis"
) -> str:
    """Generate HTML with highlighted attack paths.

    Similar to generate_attack_graph_html but highlights specific
    attack paths in the visualization.

    Args:
        graph_json: Graph data dictionary.
        attack_paths: List of attack paths (each path is a list of node IDs).
        output_path: Path where the HTML file will be saved.
        title: Title for the visualization page.

    Returns:
        Path to the generated HTML file.
    """
    # Add path information to graph data
    graph_json['attack_paths'] = attack_paths
    graph_json['path_count'] = len(attack_paths)
    
    # Generate base HTML (path highlighting would be added to D3.js code)
    # For now, we just add path info to the metadata
    return generate_attack_graph_html(graph_json, output_path, title)


if __name__ == "__main__":
    # Demo/test code
    print("Testing Attack Graph Visualizer\n")
    
    # Sample graph data
    demo_graph = {
        "nodes": [
            {"id": "contract_1", "type": "Contract", "name": "Vault", "size": 15},
            {"id": "func_1", "type": "Function", "name": "withdraw", "size": 12, "visibility": "public"},
            {"id": "vuln_1", "type": "Vulnerability", "name": "REENTRANCY", "size": 20, "severity": "CRITICAL", "file": "Vault.sol", "line": 42, "description": "Reentrancy vulnerability"},
            {"id": "call_1", "type": "ExternalCall", "name": "recipient.call{value: amount}()", "size": 10}
        ],
        "links": [
            {"source": "contract_1", "target": "func_1", "type": "contains"},
            {"source": "func_1", "target": "call_1", "type": "calls"},
            {"source": "func_1", "target": "vuln_1", "type": "triggers"}
        ]
    }
    
    output_file = "demo_attack_graph.html"
    try:
        result = generate_attack_graph_html(demo_graph, output_file, "Demo Analysis")
        print(f"Generated: {result}")
        print(f"Open {output_file} in a browser to view the visualization")
    except Exception as e:
        print(f"Error: {e}")
