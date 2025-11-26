<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Bastion Security Report - ${scanResult.projectName}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 0;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }
        
        .summary-card.critical { border-left-color: #dc3545; }
        .summary-card.high { border-left-color: #fd7e14; }
        .summary-card.medium { border-left-color: #ffc107; }
        .summary-card.low { border-left-color: #28a745; }
        
        .summary-card h3 {
            font-size: 2.2em;
            margin-bottom: 5px;
            color: #2c3e50;
        }
        
        .summary-card .label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 1px;
        }
        
        .section {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }
        
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .vulnerability-table th {
            background-color: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
            color: #495057;
        }
        
        .vulnerability-table td {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
            vertical-align: top;
        }
        
        .vulnerability-table tr:hover {
            background-color: #f8f9fa;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .severity-critical {
            background-color: #dc3545;
            color: white;
        }
        
        .severity-high {
            background-color: #fd7e14;
            color: white;
        }
        
        .severity-medium {
            background-color: #ffc107;
            color: #212529;
        }
        
        .severity-low {
            background-color: #28a745;
            color: white;
        }
        
        .severity-unknown {
            background-color: #6c757d;
            color: white;
        }
        
        .cvss-score {
            font-weight: 700;
            padding: 6px 10px;
            border-radius: 6px;
            background-color: #e9ecef;
            color: #495057;
        }
        
        .meta-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .meta-item {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }
        
        .meta-item .label {
            font-size: 0.85em;
            color: #666;
            margin-bottom: 5px;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .meta-item .value {
            font-size: 1.1em;
            color: #2c3e50;
            font-weight: 500;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #dee2e6;
            margin-top: 40px;
        }
        
        .footer .powered-by {
            font-size: 0.9em;
            margin-bottom: 10px;
        }
        
        .footer .timestamp {
            font-size: 0.8em;
            color: #999;
        }
        
        /* Statistics Section */
        .statistics-section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .statistics-section h2 {
            color: #2c3e50;
            margin-bottom: 25px;
            font-size: 1.8em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #667eea;
            transition: transform 0.2s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 8px;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 60px 20px;
            color: #28a745;
        }
        
        .no-vulnerabilities .icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        
        .description-cell {
            max-width: 300px;
            word-wrap: break-word;
            font-size: 0.9em;
            line-height: 1.4;
        }
        
        .component-cell {
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.85em;
            background-color: #f8f9fa;
            padding: 8px;
            border-radius: 4px;
        }
        
        /* Enhanced Vulnerability Card Styles */
        .vulnerability-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .vulnerability-card {
            background: white;
            border: 1px solid #e3e6f0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: box-shadow 0.3s ease;
        }
        
        .vulnerability-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .vulnerability-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 20px;
            background: linear-gradient(135deg, #f8f9fc 0%, #eaecf4 100%);
            border-bottom: 1px solid #e3e6f0;
        }
        
        .cve-id-section h3 {
            margin: 0 0 8px 0;
            font-size: 1.4em;
            color: #333;
        }
        
        .cve-link {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        
        .cve-link:hover {
            text-decoration: underline;
            color: #5a6fd8;
        }
        
        .reference-links {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }
        
        .ref-link {
            display: inline-block;
            padding: 4px 8px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.8em;
            transition: background-color 0.3s ease;
        }
        
        .ref-link.official {
            background: #28a745;
        }
        
        .ref-link.nvd {
            background: #fd7e14;
        }
        
        .ref-link:hover {
            opacity: 0.9;
            transform: translateY(-1px);
        }
        
        .severity-section {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 8px;
        }
        
        .cvss-score.large {
            font-size: 1.8em;
            font-weight: 700;
            color: #333;
        }
        
        .vulnerability-body {
            padding: 20px;
        }
        
        .description-section,
        .component-section,
        .metadata-section {
            margin-bottom: 20px;
        }
        
        .description-section h4,
        .component-section h4 {
            margin: 0 0 8px 0;
            font-size: 1em;
            color: #666;
            font-weight: 600;
        }
        
        .vulnerability-description {
            margin: 0;
            line-height: 1.6;
            color: #444;
            background: #f8f9fa;
            padding: 12px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }
        
        .component-path {
            font-family: 'Monaco', 'Menlo', monospace;
            background: #2d3748;
            color: #e2e8f0;
            padding: 10px;
            border-radius: 6px;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        .metadata-section {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            padding-top: 16px;
            border-top: 1px solid #e3e6f0;
        }
        
        .metadata-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .metadata-item .label {
            font-weight: 600;
            color: #666;
            font-size: 0.9em;
            min-width: 80px;
        }
        
        .metadata-item .value {
            color: #333;
            font-size: 0.9em;
        }
        
        /* Improved table responsiveness */
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .vulnerability-table th {
            background: #667eea;
            color: white;
            font-weight: 600;
            text-align: left;
            padding: 15px 12px;
            border-bottom: 2px solid #5a6fd8;
        }
        
        .vulnerability-table td {
            padding: 12px;
            border-bottom: 1px solid #e3e6f0;
            vertical-align: top;
        }
        
        .vulnerability-table tr:hover {
            background-color: #f8f9fc;
        }
        
        /* CVE Documentation Table Styles */
        .table-container {
            overflow-x: auto;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        /* Dependency Tree Styles */
        .dependency-tree {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.9em;
            line-height: 1.6;
            overflow-x: auto;
            border-left: 4px solid #667eea;
        }
        
        .tree-node {
            margin: 2px 0;
            position: relative;
            padding-left: 0;
        }
        
        .tree-node.root {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
            padding-left: 0;
        }
        
        .tree-node.direct {
            padding-left: 20px;
            position: relative;
        }
        
        .tree-node.transitive {
            padding-left: 40px;
            position: relative;
        }
        
        .tree-node.deep {
            padding-left: 60px;
            position: relative;
        }
        
        .tree-node::before {
            content: '';
            position: absolute;
            left: -8px;
            top: 50%;
            width: 8px;
            height: 1px;
            background-color: #999;
            transform: translateY(-50%);
        }
        
        .tree-node.direct::before {
            content: '├── ';
            position: absolute;
            left: 8px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-weight: normal;
        }
        
        .tree-node.transitive::before {
            content: '│   ├── ';
            position: absolute;
            left: 28px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-weight: normal;
        }
        
        .tree-node.deep::before {
            content: '│   │   ├── ';
            position: absolute;
            left: 48px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-weight: normal;
        }
        
        .tree-node.last-direct::before {
            content: '└── ';
        }
        
        .tree-node.last-transitive::before {
            content: '│   └── ';
        }
        
        .tree-node.last-deep::before {
            content: '│   │   └── ';
        }
        
        .dependency-info {
            display: inline;
        }
        
        .dependency-coords {
            color: #2c3e50;
            font-weight: 600;
        }
        
        .dependency-scope {
            color: #666;
            font-style: italic;
            margin-left: 8px;
            font-size: 0.85em;
        }
        
        .vulnerability-indicator {
            display: inline-flex;
            align-items: center;
            margin-left: 12px;
            gap: 6px;
        }
        
        .vuln-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: 600;
            color: white;
        }
        
        .vuln-badge.critical { background-color: #dc3545; }
        .vuln-badge.high { background-color: #fd7e14; }
        .vuln-badge.medium { background-color: #ffc107; color: #212529; }
        .vuln-badge.low { background-color: #28a745; }
        
        .vuln-count {
            background: #dc3545;
            color: white;
            padding: 1px 5px;
            border-radius: 10px;
            font-size: 0.7em;
            font-weight: 600;
            min-width: 18px;
            text-align: center;
            display: inline-block;
        }
        
        .clean-dependency {
            color: #28a745;
        }
        
        .vulnerable-dependency {
            color: #dc3545;
        }
        
        .dependency-path {
            color: #666;
            font-size: 0.8em;
            margin-top: 4px;
            padding-left: 20px;
            font-style: italic;
        }
        
        .tree-legend {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            font-size: 0.9em;
        }
        
        .tree-legend h4 {
            margin: 0 0 10px 0;
            color: #2c3e50;
            font-size: 1em;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            margin: 6px 0;
            gap: 10px;
        }
        
        .legend-symbol {
            font-family: 'Monaco', 'Menlo', monospace;
            color: #666;
            min-width: 60px;
        }
        
        .tree-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .tree-stat-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }
        
        .tree-stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .tree-stat-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .cve-documentation-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            font-size: 0.9em;
        }
        
        .cve-documentation-table th {
            background: #2c3e50;
            color: white;
            font-weight: 600;
            text-align: left;
            padding: 15px 12px;
            border-bottom: 2px solid #34495e;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        
        .cve-documentation-table td {
            padding: 12px;
            border-bottom: 1px solid #e3e6f0;
            vertical-align: middle;
        }
        
        .cve-row:hover {
            background-color: #f8f9fc;
        }
        
        .cve-row:nth-child(even) {
            background-color: #fbfcfd;
        }
        
        .cve-row:nth-child(even):hover {
            background-color: #f4f6f8;
        }
        
        .cve-id-cell {
            display: flex;
            align-items: center;
        }
        
        .cve-badge {
            background: #34495e;
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
        }
        
        .documentation-links, .additional-references {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        
        .doc-link {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 6px 10px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85em;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid transparent;
        }
        
        .doc-link.official-cve {
            background: #27ae60;
            color: white;
            border-color: #2ecc71;
        }
        
        .doc-link.official-cve:hover {
            background: #2ecc71;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(46, 204, 113, 0.3);
        }
        
        .doc-link.nvd-link {
            background: #e67e22;
            color: white;
            border-color: #f39c12;
        }
        
        .doc-link.nvd-link:hover {
            background: #f39c12;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(243, 156, 18, 0.3);
        }
        
        .doc-link.additional-ref {
            background: #3498db;
            color: white;
            border-color: #5dade2;
        }
        
        .doc-link.additional-ref:hover {
            background: #5dade2;
            transform: translateY(-1px);
            box-shadow: 0 2px 6px rgba(93, 173, 226, 0.3);
        }
        
        .link-icon {
            font-size: 1em;
        }
        
        .link-text {
            font-size: 0.9em;
        }
        
        .no-link {
            color: #7f8c8d;
            font-style: italic;
            font-size: 0.85em;
            padding: 6px 0;
        }
        
        .component-cell.compact {
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8em;
            color: #2c3e50;
            max-width: 200px;
            word-break: break-all;
            line-height: 1.3;
        }
        
        .cve-summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }

        .stat-card {
            text-align: center;
            background: white;
            padding: 20px;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .stat-value {
            font-size: 2.2em;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 8px;
        }

        .stat-label {
            font-size: 0.9em;
            color: #7f8c8d;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        /* Enhanced Affected Dependencies Compact Styles */
        .affected-deps-compact {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }

        .affected-deps-compact th {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            font-size: 0.9em;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .affected-deps-compact td {
            padding: 10px;
            border-bottom: 1px solid #e3e6f0;
            vertical-align: middle;
        }

        .affected-deps-compact tr:hover {
            background-color: #f8f9fc;
        }

        .affected-deps-compact tr:nth-child(even) {
            background-color: #fbfcfd;
        }

        .dep-name-cell {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .dep-artifact {
            font-weight: 600;
            color: #2c3e50;
            font-size: 0.95em;
        }

        .dep-version {
            font-size: 0.85em;
            color: #667eea;
            font-weight: 500;
        }

        .dep-links {
            display: flex;
            gap: 6px;
            margin-top: 4px;
        }

        .dep-link {
            display: inline-flex;
            align-items: center;
            padding: 2px 6px;
            border-radius: 3px;
            text-decoration: none;
            font-size: 0.75em;
            font-weight: 500;
            transition: all 0.2s ease;
        }

        .dep-link.maven {
            background: #e74c3c;
            color: white;
        }

        .dep-link.maven:hover {
            background: #c0392b;
        }

        .dep-link.github {
            background: #333;
            color: white;
        }

        .dep-link.github:hover {
            background: #555;
        }

        .cve-chips {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            max-width: 280px;
        }

        .cve-chip {
            display: inline-block;
            padding: 3px 8px;
            background: #34495e;
            color: white;
            border-radius: 4px;
            font-size: 0.8em;
            font-family: 'Monaco', 'Menlo', monospace;
            text-decoration: none;
            transition: all 0.2s ease;
        }

        .cve-chip:hover {
            background: #667eea;
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }

        .cve-chip.critical {
            background: #dc3545;
        }

        .cve-chip.high {
            background: #fd7e14;
        }

        .cve-chip.medium {
            background: #ffc107;
            color: #212529;
        }

        .cve-chip.low {
            background: #28a745;
        }

        .dep-type-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.7em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .dep-type-badge.direct {
            background: #fee2e2;
            color: #dc2626;
        }

        .dep-type-badge.transitive {
            background: #fef3c7;
            color: #d97706;
        }

        .quick-actions {
            display: flex;
            gap: 4px;
        }

        .action-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.9em;
            transition: all 0.2s ease;
        }

        .action-btn.nvd {
            background: #e67e22;
            color: white;
        }

        .action-btn.nvd:hover {
            background: #d35400;
        }

        .action-btn.mitre {
            background: #27ae60;
            color: white;
        }

        .action-btn.mitre:hover {
            background: #229954;
        }

        .severity-indicator {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .severity-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }

        .severity-dot.critical { background: #dc3545; }
        .severity-dot.high { background: #fd7e14; }
        .severity-dot.medium { background: #ffc107; }
        .severity-dot.low { background: #28a745; }

        .vuln-count-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 24px;
            height: 24px;
            padding: 0 6px;
            border-radius: 12px;
            font-weight: 700;
            font-size: 0.85em;
        }

        .vuln-count-badge.critical { background: #dc3545; color: white; }
        .vuln-count-badge.high { background: #fd7e14; color: white; }
        .vuln-count-badge.medium { background: #ffc107; color: #212529; }
        .vuln-count-badge.low { background: #28a745; color: white; }

        /* Print/PDF Styles */
        @media print {
            body {
                background: white;
                font-size: 10pt;
            }

            .container {
                max-width: 100%;
                padding: 0;
            }

            .header {
                background: #667eea !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
                padding: 20px;
                margin-bottom: 15px;
            }

            .header h1 {
                font-size: 1.8em;
            }

            .summary-cards {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 10px;
                margin-bottom: 15px;
            }

            .summary-card {
                padding: 15px;
                box-shadow: none;
                border: 1px solid #dee2e6;
                page-break-inside: avoid;
            }

            .summary-card h3 {
                font-size: 1.5em;
            }

            .section {
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: none;
                border: 1px solid #dee2e6;
                page-break-inside: avoid;
            }

            .section h2 {
                font-size: 1.2em;
                margin-bottom: 10px;
            }

            .affected-deps-compact {
                font-size: 8pt;
            }

            .affected-deps-compact th,
            .affected-deps-compact td {
                padding: 6px 4px;
            }

            .cve-chip {
                padding: 2px 4px;
                font-size: 7pt;
                background: #333 !important;
                color: white !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            .dep-link, .action-btn {
                padding: 1px 3px;
                font-size: 7pt;
            }

            .severity-badge {
                padding: 2px 6px;
                font-size: 7pt;
            }

            /* Hide non-essential elements in print */
            .tree-legend,
            .dependency-tree,
            .footer .powered-by {
                display: none;
            }

            /* Enterprise banner - simplified for print */
            div[style*="linear-gradient(135deg, #667eea"] {
                display: none;
            }

            .footer {
                padding: 10px;
                margin-top: 15px;
            }

            /* Force colors to print */
            .severity-critical,
            .severity-high,
            .severity-medium,
            .severity-low {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }

            /* Ensure tables don't break across pages */
            table {
                page-break-inside: auto;
            }

            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }

            thead {
                display: table-header-group;
            }

            /* Links show URLs in print */
            a[href^="http"]::after {
                content: " (" attr(href) ")";
                font-size: 7pt;
                color: #666;
                word-break: break-all;
            }

            .cve-chip::after,
            .dep-link::after,
            .action-btn::after {
                content: none;
            }
        }

        @media (max-width: 768px) {
            .vulnerability-grid {
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .vulnerability-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }
            
            .severity-section {
                align-items: flex-start;
                flex-direction: row;
                gap: 15px;
            }
            
            .metadata-section {
                grid-template-columns: 1fr;
                gap: 8px;
            }
            
            .cve-documentation-table {
                font-size: 0.8em;
            }
            
            .cve-documentation-table th,
            .cve-documentation-table td {
                padding: 8px 6px;
            }
            
            .doc-link {
                padding: 4px 8px;
                font-size: 0.8em;
            }
            
            .cve-summary-stats {
                grid-template-columns: 1fr;
                gap: 10px;
                padding: 15px;
            }
            
            .stat-card {
                padding: 15px;
            }
            
            .stat-value {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Bastion Security Report</h1>
            <div class="subtitle">Comprehensive Vulnerability Assessment for ${scanResult.projectName}</div>
        </header>

        <div class="summary-cards">
            <div class="summary-card">
                <h3>${summary.totalVulnerabilities!0}</h3>
                <div class="label">Total Vulnerabilities</div>
            </div>
            <div class="summary-card critical">
                <h3>${summary.criticalCount!0}</h3>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <h3>${summary.highCount!0}</h3>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <h3>${summary.mediumCount!0}</h3>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <h3>${summary.lowCount!0}</h3>
                <div class="label">Low</div>
            </div>
            <div class="summary-card">
                <h3>${summary.riskScore!0.0}</h3>
                <div class="label">Risk Score</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Scan Overview</h2>
            <div class="meta-info">
                <div class="meta-item">
                    <div class="label">Project Name</div>
                    <div class="value">${scanResult.projectName}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scanner</div>
                    <div class="value">${scanResult.scanType!"OWASP Dependency-Check"}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scan Time</div>
                    <div class="value">${scanResult.startTime!"N/A"}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Duration</div>
                    <div class="value">${scanResult.scanDurationMs!0} ms</div>
                </div>
                <div class="meta-item">
                    <div class="label">Dependencies Scanned</div>
                    <div class="value">${summary.totalDependencies!0}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Project Type</div>
                    <div class="value">${(scanResult.multiModule!false)?then("Multi-Module", "Single Module")}</div>
                </div>
            </div>
        </div>

        <#if summary.hasVulnerabilities!false>
            <div class="section">
                <h2>🎯 Affected Dependencies</h2>
                <p style="color: #666; margin-bottom: 15px; font-size: 0.9em;">
                    Click on CVE IDs to view details on NVD. Click dependency names to view on Maven Central.
                </p>
                <#if summary.affectedJars?has_content>
                    <div class="table-container">
                        <table class="affected-deps-compact">
                            <thead>
                                <tr>
                                    <th>Dependency</th>
                                    <th>Type</th>
                                    <th>Severity</th>
                                    <th>CVEs</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <#list summary.affectedJars as jar>
                                    <tr>
                                        <td>
                                            <div class="dep-name-cell">
                                                <span class="dep-artifact">${jar.artifactId}</span>
                                                <span class="dep-version">${jar.groupId}:${jar.version}</span>
                                                <div class="dep-links">
                                                    <a href="https://mvnrepository.com/artifact/${jar.groupId}/${jar.artifactId}/${jar.version}"
                                                       target="_blank"
                                                       class="dep-link maven"
                                                       title="View on Maven Repository">
                                                        📦 Maven
                                                    </a>
                                                    <a href="https://central.sonatype.com/artifact/${jar.groupId}/${jar.artifactId}/${jar.version}"
                                                       target="_blank"
                                                       class="dep-link github"
                                                       title="View on Sonatype Central">
                                                        🔍 Central
                                                    </a>
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <#assign jarIsDirect = jar.direct!false>
                                            <span class="dep-type-badge <#if jarIsDirect>direct<#else>transitive</#if>">
                                                <#if jarIsDirect>Direct<#else>Transitive</#if>
                                            </span>
                                        </td>
                                        <td>
                                            <div class="severity-indicator">
                                                <span class="severity-dot ${jar.maxSeverity?lower_case}"></span>
                                                <span class="vuln-count-badge ${jar.maxSeverity?lower_case}">
                                                    ${jar.vulnerabilityCount!0}
                                                </span>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="cve-chips">
                                                <#list jar.vulnerabilityIds as cveId>
                                                    <#if cveId?starts_with("CVE-")>
                                                        <a href="https://nvd.nist.gov/vuln/detail/${cveId}"
                                                           target="_blank"
                                                           class="cve-chip"
                                                           title="View ${cveId} on NVD">
                                                            ${cveId}
                                                        </a>
                                                    <#else>
                                                        <span class="cve-chip" title="${cveId}">
                                                            ${cveId}
                                                        </span>
                                                    </#if>
                                                </#list>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="quick-actions">
                                                <#if jar.vulnerabilityIds?has_content>
                                                    <#assign firstCve = jar.vulnerabilityIds[0]>
                                                    <#if firstCve?starts_with("CVE-")>
                                                        <a href="https://nvd.nist.gov/vuln/detail/${firstCve}"
                                                           target="_blank"
                                                           class="action-btn nvd"
                                                           title="View on NVD Database">
                                                            🔗
                                                        </a>
                                                        <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${firstCve}"
                                                           target="_blank"
                                                           class="action-btn mitre"
                                                           title="View Official CVE">
                                                            📋
                                                        </a>
                                                    </#if>
                                                </#if>
                                            </div>
                                        </td>
                                    </tr>
                                </#list>
                            </tbody>
                        </table>
                    </div>

                    <!-- Quick Summary Stats -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                        <div style="text-align: center;">
                            <div style="font-size: 1.5em; font-weight: 700; color: #dc3545;">${summary.affectedJars?size}</div>
                            <div style="font-size: 0.8em; color: #666; text-transform: uppercase;">Affected Deps</div>
                        </div>
                        <div style="text-align: center;">
                            <div style="font-size: 1.5em; font-weight: 700; color: #2c3e50;">${summary.totalVulnerabilities!0}</div>
                            <div style="font-size: 0.8em; color: #666; text-transform: uppercase;">Total CVEs</div>
                        </div>
                        <div style="text-align: center;">
                            <#assign directCount = 0>
                            <#list summary.affectedJars as jar>
                                <#if jar.direct!false>
                                    <#assign directCount = directCount + 1>
                                </#if>
                            </#list>
                            <div style="font-size: 1.5em; font-weight: 700; color: #e74c3c;">${directCount}</div>
                            <div style="font-size: 0.8em; color: #666; text-transform: uppercase;">Direct</div>
                        </div>
                        <div style="text-align: center;">
                            <div style="font-size: 1.5em; font-weight: 700; color: #f39c12;">${summary.affectedJars?size - directCount}</div>
                            <div style="font-size: 0.8em; color: #666; text-transform: uppercase;">Transitive</div>
                        </div>
                    </div>
                <#else>
                    <p style="color: #666; font-style: italic;">No vulnerable dependencies detected in the scan results.</p>
                </#if>
            </div>
            
            <!-- Dependency Tree Visualization -->
            <div class="section">
                <h2>🌳 Vulnerable Dependency Tree</h2>
                
                <div class="tree-stats">
                    <div class="tree-stat-card">
                        <div class="tree-stat-value">${summary.totalDependencies!0}</div>
                        <div class="tree-stat-label">Total Dependencies</div>
                    </div>
                    <div class="tree-stat-card">
                        <div class="tree-stat-value">${summary.vulnerableDependencies!0}</div>
                        <div class="tree-stat-label">Vulnerable</div>
                    </div>
                    <div class="tree-stat-card">
                        <div class="tree-stat-value">${(summary.totalDependencies!0) - (summary.vulnerableDependencies!0)}</div>
                        <div class="tree-stat-label">Clean</div>
                    </div>
                    <div class="tree-stat-card">
                        <div class="tree-stat-value">
                            <#assign totalDeps = (summary.totalDependencies!0)>
                            <#assign vulnDeps = (summary.vulnerableDependencies!0)>
                            <#if totalDeps gt 0>
                                ${((vulnDeps * 100) / totalDeps)?string("0")}%
                            <#else>
                                0%
                            </#if>
                        </div>
                        <div class="tree-stat-label">Risk Coverage</div>
                    </div>
                </div>
                
                <div class="tree-legend">
                    <h4>🔍 Legend</h4>
                    <div class="legend-item">
                        <span class="legend-symbol">├──</span>
                        <span>Direct dependency</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-symbol">│   ├──</span>
                        <span>Transitive dependency</span>
                    </div>
                    <div class="legend-item">
                        <span class="legend-symbol">└──</span>
                        <span>Last dependency in branch</span>
                    </div>
                    <div class="legend-item">
                        <span class="vuln-badge critical">5</span>
                        <span>Number of vulnerabilities found</span>
                    </div>
                    <div class="legend-item">
                        <span style="color: #28a745;">✓ Clean</span>
                        <span>No vulnerabilities detected</span>
                    </div>
                </div>
                
                <div class="dependency-tree">
                    <!-- Project Root -->
                    <div class="tree-node root">
                        📦 ${scanResult.projectName!"Unknown Project"}
                        <span class="dependency-scope">(${scanResult.projectGroupId!""}:${scanResult.projectArtifactId!""}:${scanResult.projectVersion!""})</span>
                    </div>
                    
                    <!-- Direct Dependencies -->
                    <#if summary.affectedJars?has_content>
                        <#assign directDeps = []>
                        <#assign transitiveDeps = []>
                        
                        <#list summary.affectedJars as jar>
                            <#assign jarIsDirect = jar.direct!false>
                            <#if jarIsDirect>
                                <#assign directDeps = directDeps + [jar]>
                            <#else>
                                <#assign transitiveDeps = transitiveDeps + [jar]>
                            </#if>
                        </#list>
                        
                        <!-- Show Direct Dependencies -->
                        <#list directDeps as jar>
                            <#assign isLastDirect = jar_index == (directDeps?size - 1) && transitiveDeps?size == 0>
                            <div class="tree-node direct <#if isLastDirect>last-direct</#if>">
                                <span class="dependency-info">
                                    <span class="dependency-coords vulnerable-dependency">
                                        ${jar.groupId}:${jar.artifactId}:${jar.version}
                                    </span>
                                    <span class="dependency-scope">[${jar.scope!"compile"}]</span>
                                    <span class="vulnerability-indicator">
                                        <span class="vuln-count">${jar.vulnerabilityCount!0}</span>
                                        <#if jar.maxSeverity?has_content>
                                            <span class="vuln-badge ${jar.maxSeverity?lower_case}">${jar.maxSeverity}</span>
                                        </#if>
                                    </span>
                                </span>
                                <#if jar.filePath?has_content>
                                    <div class="dependency-path">
                                        📁 ${jar.filePath?replace("/.m2/repository/", "/...m2/.../")?replace(userHome, "~")}
                                    </div>
                                </#if>
                            </div>
                        </#list>
                        
                        <!-- Show Transitive Dependencies -->
                        <#list transitiveDeps as jar>
                            <#assign isLastTransitive = jar_index == (transitiveDeps?size - 1)>
                            <div class="tree-node transitive <#if isLastTransitive>last-transitive</#if>">
                                <span class="dependency-info">
                                    <span class="dependency-coords vulnerable-dependency">
                                        ${jar.groupId}:${jar.artifactId}:${jar.version}
                                    </span>
                                    <span class="dependency-scope">[${jar.scope!"compile"}]</span>
                                    <span class="vulnerability-indicator">
                                        <span class="vuln-count">${jar.vulnerabilityCount!0}</span>
                                        <#if jar.maxSeverity?has_content>
                                            <span class="vuln-badge ${jar.maxSeverity?lower_case}">${jar.maxSeverity}</span>
                                        </#if>
                                    </span>
                                </span>
                                <#if jar.filePath?has_content>
                                    <div class="dependency-path">
                                        📁 ${jar.filePath?replace("/.m2/repository/", "/...m2/.../")?replace(userHome, "~")}
                                    </div>
                                </#if>
                            </div>
                        </#list>
                        
                        <!-- Show some clean dependencies for context -->
                        <#assign cleanDepsShown = 0>
                        <#assign maxCleanToShow = 5>
                        <#list scanResult.dependencies![] as dep>
                            <#if cleanDepsShown < maxCleanToShow && !(dep.vulnerabilityIds?has_content && dep.vulnerabilityIds?size > 0)>
                                <#assign cleanDepsShown = cleanDepsShown + 1>
                                <#assign isLastClean = cleanDepsShown == maxCleanToShow>
                                <#assign depIsDirect = dep.direct!false>
                                <div class="tree-node <#if depIsDirect>direct<#else>transitive</#if> <#if isLastClean>last-<#if depIsDirect>direct<#else>transitive</#if></#if>">
                                    <span class="dependency-info">
                                        <span class="dependency-coords clean-dependency">
                                            ${dep.groupId}:${dep.artifactId}:${dep.version}
                                        </span>
                                        <span class="dependency-scope">[${dep.scope!"compile"}]</span>
                                        <span class="vulnerability-indicator">
                                            <span style="color: #28a745; font-size: 0.8em;">✓ Clean</span>
                                        </span>
                                    </span>
                                </div>
                            </#if>
                        </#list>
                        
                        <!-- Show summary if there are more clean dependencies -->
                        <#assign totalCleanDeps = (summary.totalDependencies!0) - (summary.vulnerableDependencies!0)>
                        <#if totalCleanDeps gt maxCleanToShow>
                            <div class="tree-node transitive">
                                <span class="dependency-info" style="color: #666; font-style: italic;">
                                    ... and ${totalCleanDeps - maxCleanToShow} more clean dependencies
                                </span>
                            </div>
                        </#if>
                        
                    <#else>
                        <div class="tree-node direct">
                            <span class="dependency-info clean-dependency">
                                🎉 No vulnerable dependencies found - all dependencies are clean!
                            </span>
                        </div>
                    </#if>
                </div>
                
                <!-- Additional Tree Information -->
                <div style="margin-top: 20px; padding: 15px; background: #e7f3ff; border-radius: 6px; border-left: 4px solid #0066cc;">
                    <h4 style="margin: 0 0 10px 0; color: #0066cc;">📊 Dependency Analysis</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; font-size: 0.9em;">
                        <div>
                            <strong>Direct Dependencies:</strong> 
                            <#assign directCount = 0>
                            <#assign directVulnerable = 0>
                            <#if summary.affectedJars?has_content>
                                <#list summary.affectedJars as jar>
                                    <#assign jarIsDirect = jar.direct!false>
                                    <#if jarIsDirect>
                                        <#assign directVulnerable = directVulnerable + 1>
                                    </#if>
                                </#list>
                            </#if>
                            <span style="color: #dc3545;">${directVulnerable} vulnerable</span>
                        </div>
                        <div>
                            <strong>Transitive Dependencies:</strong> 
                            <#assign transitiveVulnerable = (summary.vulnerableDependencies!0) - directVulnerable>
                            <span style="color: #fd7e14;">${transitiveVulnerable} vulnerable</span>
                        </div>
                        <div>
                            <strong>Risk Assessment:</strong>
                            <#if (summary.vulnerableDependencies!0) == 0>
                                <span style="color: #28a745;">✅ Low Risk</span>
                            <#elseif (directVulnerable!0) gt 0>
                                <span style="color: #dc3545;">🔴 High Risk</span>
                            <#else>
                                <span style="color: #fd7e14;">🟡 Medium Risk</span>
                            </#if>
                        </div>
                        <div>
                            <strong>Remediation Priority:</strong>
                            <#if (directVulnerable!0) gt 0>
                                Focus on direct dependencies first
                            <#elseif (transitiveVulnerable!0) gt 0>
                                Update parent dependencies to get fixes
                            <#else>
                                No immediate action required
                            </#if>
                        </div>
                    </div>
                </div>
            </div>
            
            <#if scanResult.vulnerabilities?has_content>
                <!-- CVE Documentation Table -->
                <div class="section">
                    <h2>📋 CVE Documentation &amp; References</h2>
                    <div class="table-container">
                        <table class="cve-documentation-table">
                            <thead>
                                <tr>
                                    <th>CVE ID</th>
                                    <th>Description</th>
                                    <th>Severity</th>
                                    <th>CVSS Score</th>
                                    <th>Official CVE Link</th>
                                    <th>NVD Database</th>
                                    <th>Additional References</th>
                                    <th>Affected Component</th>
                                </tr>
                            </thead>
                            <tbody>
                                <#list scanResult.vulnerabilities as vulnerability>
                                    <tr class="cve-row">
                                        <td>
                                            <div class="cve-id-cell">
                                                <span class="cve-badge">${vulnerability.cveId!"N/A"}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="description-cell" style="max-width: 350px;">
                                                ${vulnerability.description!"No description available"}
                                            </div>
                                        </td>
                                        <td>
                                            <span class="severity-badge severity-${vulnerability.severity?lower_case}">
                                                ${vulnerability.severity!"UNKNOWN"}
                                            </span>
                                        </td>
                                        <td>
                                            <#if vulnerability.cvssV3Score?has_content>
                                                <span class="cvss-score">${vulnerability.cvssV3Score?string("0.0")}</span>
                                            <#else>
                                                <span class="cvss-score">N/A</span>
                                            </#if>
                                        </td>
                                        <td>
                                            <div class="documentation-links">
                                                <#if vulnerability.cveId?has_content && vulnerability.cveId?starts_with("CVE-")>
                                                    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vulnerability.cveId}" 
                                                       target="_blank" 
                                                       class="doc-link official-cve"
                                                       title="View official CVE documentation">
                                                        <span class="link-icon">📋</span>
                                                        <span class="link-text">Official CVE</span>
                                                    </a>
                                                <#else>
                                                    <span class="no-link">Not Available</span>
                                                </#if>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="documentation-links">
                                                <#if vulnerability.cveId?has_content && vulnerability.cveId?starts_with("CVE-")>
                                                    <a href="https://nvd.nist.gov/vuln/detail/${vulnerability.cveId}" 
                                                       target="_blank" 
                                                       class="doc-link nvd-link"
                                                       title="View NIST NVD database entry">
                                                        <span class="link-icon">🔗</span>
                                                        <span class="link-text">NVD Database</span>
                                                    </a>
                                                <#else>
                                                    <span class="no-link">Not Available</span>
                                                </#if>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="additional-references">
                                                <#if vulnerability.references?has_content>
                                                    <#assign additionalRefCount = 0>
                                                    <#list vulnerability.references as ref>
                                                        <#if !ref?contains("cve.mitre.org") && !ref?contains("nvd.nist.gov") && additionalRefCount < 3>
                                                            <a href="${ref}" target="_blank" class="doc-link additional-ref" title="Additional reference">
                                                                <span class="link-icon">🌐</span>
                                                                <span class="link-text">Reference</span>
                                                            </a>
                                                            <#assign additionalRefCount = additionalRefCount + 1>
                                                        </#if>
                                                    </#list>
                                                    <#if (vulnerability.references?size > 5)>
                                                        <span class="no-link">+${vulnerability.references?size - 5} more</span>
                                                    </#if>
                                                <#else>
                                                    <#if vulnerability.referenceUrl?has_content && !vulnerability.referenceUrl?contains("cve.mitre.org") && !vulnerability.referenceUrl?contains("nvd.nist.gov")>
                                                        <a href="${vulnerability.referenceUrl}" target="_blank" class="doc-link additional-ref" title="Additional reference">
                                                            <span class="link-icon">🌐</span>
                                                            <span class="link-text">Reference</span>
                                                        </a>
                                                    <#else>
                                                        <span class="no-link">None</span>
                                                    </#if>
                                                </#if>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="component-cell compact">
                                                ${vulnerability.affectedComponent!"N/A"}
                                            </div>
                                        </td>
                                    </tr>
                                </#list>
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="cve-summary-stats">
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.vulnerabilities?size}</div>
                            <div class="stat-label">Total CVEs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">
                                <#assign cveCount = 0>
                                <#list scanResult.vulnerabilities as vuln>
                                    <#if vuln.cveId?has_content && vuln.cveId?starts_with("CVE-")>
                                        <#assign cveCount = cveCount + 1>
                                    </#if>
                                </#list>
                                ${cveCount}
                            </div>
                            <div class="stat-label">With Official CVE IDs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">
                                <#assign withRefsCount = 0>
                                <#list scanResult.vulnerabilities as vuln>
                                    <#if vuln.references?has_content || vuln.referenceUrl?has_content>
                                        <#assign withRefsCount = withRefsCount + 1>
                                    </#if>
                                </#list>
                                ${withRefsCount}
                            </div>
                            <div class="stat-label">With Documentation</div>
                        </div>
                    </div>
                </div>
            </#if>
        <#else>
            <div class="section">
                <div class="no-vulnerabilities">
                    <div class="icon">🎉</div>
                    <h2>No Vulnerabilities Found!</h2>
                    <p>Great job! Your project appears to be free from known security vulnerabilities.</p>
                    <#if summary.totalDependencies?has_content && summary.totalDependencies gt 0>
                        <p style="margin-top: 15px; color: #666;">Scanned <strong>${summary.totalDependencies}</strong> dependencies successfully.</p>
                    </#if>
                </div>
            </div>
        </#if>

        <!-- Statistics Section -->
        <#if scanResult.statistics?? || scanResult.performanceMetrics??>
            <section class="statistics-section">
                <h2><i class="icon">📊</i> Performance Metrics</h2>
                <div class="stats-grid">
                    <#if scanResult.statistics??>
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.statistics.totalJarsScanned!scanResult.totalDependencies!0}</div>
                            <div class="stat-label">JARs Scanned</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.statistics.uniqueGroupIds!0}</div>
                            <div class="stat-label">Unique Group IDs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.statistics.duplicateJars!0}</div>
                            <div class="stat-label">Duplicate JARs</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.statistics.totalCvesFound!scanResult.totalVulnerabilities!0}</div>
                            <div class="stat-label">CVEs Found</div>
                        </div>
                    </#if>
                    
                    <#if scanResult.performanceMetrics??>
                        <div class="stat-card">
                            <div class="stat-value">${(scanResult.performanceMetrics.totalScanTimeMs / 1000)?round}s</div>
                            <div class="stat-label">Total Scan Time</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${((scanResult.performanceMetrics.cacheHits + scanResult.performanceMetrics.cacheMisses) > 0)?then(((scanResult.performanceMetrics.cacheHits * 100) / (scanResult.performanceMetrics.cacheHits + scanResult.performanceMetrics.cacheMisses))?round, 0)}%</div>
                            <div class="stat-label">Cache Hit Rate</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${scanResult.performanceMetrics.peakMemoryUsageMB!0} MB</div>
                            <div class="stat-label">Peak Memory</div>
                        </div>
                        <div class="stat-card">
                            <#assign totalScanTime = (scanResult.performanceMetrics.totalScanTimeMs!0)>
                            <#assign totalDeps = (scanResult.totalDependencies!0)>
                            <div class="stat-value">
                                <#if totalScanTime gt 0>
                                    ${((totalDeps * 1000) / totalScanTime)?round}
                                <#else>
                                    0
                                </#if>
                            </div>
                            <div class="stat-label">Processing Speed</div>
                        </div>
                    </#if>
                </div>
            </section>
        </#if>

        <!-- Enterprise Edition Upgrade Banner -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border: 3px solid #5a67d8; border-radius: 12px; padding: 30px; margin: 40px 20px 30px 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.15);">
            <div style="text-align: center; color: white;">
                <h2 style="margin: 0 0 10px 0; font-size: 28px; font-weight: 700;">
                    🚀 Using Community Edition
                </h2>
                <p style="font-size: 16px; margin: 0 0 25px 0; opacity: 0.95;">
                    You're seeing <strong>vulnerability detection</strong>. Enterprise Edition adds powerful team features:
                </p>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 25px 0;">
                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">📧</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Email Alerts</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        Notify security@yourcompany.com on new CRITICAL findings
                    </p>
                </div>

                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">📄</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Compliance Reports</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        PDF exports for auditors, SARIF for GitHub Security tab
                    </p>
                </div>

                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">📊</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Trend Analysis</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        Track your security posture over time with unlimited history
                    </p>
                </div>

                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">💾</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Database Storage</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        Unlimited projects with PostgreSQL/MySQL persistence
                    </p>
                </div>

                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">🔍</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Advanced Filtering</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        Suppress false positives, custom severity thresholds
                    </p>
                </div>

                <div style="background: rgba(255, 255, 255, 0.15); border-radius: 8px; padding: 20px; backdrop-filter: blur(10px);">
                    <div style="color: #ffd700; font-size: 24px; margin-bottom: 10px;">⚡</div>
                    <h3 style="color: white; margin: 0 0 8px 0; font-size: 18px;">Priority Support</h3>
                    <p style="color: rgba(255,255,255,0.9); margin: 0; font-size: 14px; line-height: 1.5;">
                        4-hour SLA with direct access to security experts
                    </p>
                </div>
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <div style="background: rgba(255, 255, 255, 0.2); border-radius: 8px; padding: 15px; margin-bottom: 20px;">
                    <p style="color: white; margin: 0; font-size: 20px; font-weight: 700;">
                        💰 <strong>$89/month</strong> • Save 12+ hours/month on security workflows
                    </p>
                </div>
                <a href="https://bastion-plugin.lemonsqueezy.com/"
                   target="_blank"
                   rel="noopener noreferrer"
                   style="display: inline-block; background: #ffd700; color: #1a202c; padding: 15px 40px; text-decoration: none; font-weight: 700; font-size: 18px; border-radius: 8px; box-shadow: 0 4px 15px rgba(255, 215, 0, 0.4); transition: transform 0.2s, box-shadow 0.2s;"
                   onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 6px 20px rgba(255, 215, 0, 0.6)';"
                   onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 4px 15px rgba(255, 215, 0, 0.4)';">
                    🚀 Start 14-Day Free Trial →
                </a>
                <p style="color: rgba(255,255,255,0.8); margin: 15px 0 0 0; font-size: 14px;">
                    No credit card required • Full feature access • Cancel anytime
                </p>
            </div>
        </div>

        <footer class="footer">
            <div class="powered-by">
                <strong>Powered by Bastion Maven Plugin v${bastionVersion!"1.0.0"}</strong><br>
                Enterprise-grade vulnerability scanning for Maven projects
            </div>
            <div class="timestamp">
                Report generated on ${generatedTime!"N/A"}
            </div>
        </footer>
    </div>
</body>
</html>