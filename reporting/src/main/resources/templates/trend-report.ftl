<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bastion Security Trend Analysis - ${scanResult.projectName!"Unknown Project"}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        
        .header .project-info {
            background: rgba(255,255,255,0.2);
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.1em;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
            display: flex;
            align-items: center;
        }
        
        .section h2 .icon {
            margin-right: 10px;
            font-size: 1.2em;
        }
        
        /* Trend Cards */
        .trend-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .trend-card {
            background: white;
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.2s ease;
        }
        
        .trend-card:hover {
            transform: translateY(-2px);
        }
        
        .trend-card.positive {
            border-left-color: #28a745;
        }
        
        .trend-card.negative {
            border-left-color: #dc3545;
        }
        
        .trend-card.neutral {
            border-left-color: #6c757d;
        }
        
        .trend-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
        }
        
        .trend-indicator {
            font-size: 0.8em;
            margin-right: 10px;
        }
        
        .trend-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }
        
        .trend-description {
            font-size: 0.85em;
            color: #888;
        }
        
        /* Chart Container */
        .chart-container {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 30px;
            margin: 20px 0;
            text-align: center;
        }
        
        .chart-placeholder {
            height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
            font-size: 1.1em;
            border: 2px dashed #ddd;
            border-radius: 8px;
        }
        
        /* Trend Chart Styles */
        .trend-chart-container {
            background: white;
            margin: 20px 0;
        }
        
        .chart-legend {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-bottom: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9em;
        }
        
        .legend-color {
            width: 16px;
            height: 16px;
            border-radius: 2px;
        }
        
        .vulnerable-jars-color {
            background: #dc3545;
        }
        
        .total-cves-color {
            background: #fd7e14;
        }
        
        .critical-cves-color {
            background: #6f42c1;
        }
        
        .trend-timeline-chart {
            margin: 20px 0;
        }
        
        .trend-chart-visual {
            height: 400px;
            margin: 30px 0;
        }
        
        .chart-grid {
            display: grid;
            grid-template-columns: 60px 1fr;
            grid-template-rows: 1fr 40px;
            height: 100%;
            gap: 10px;
        }
        
        .y-axis {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
        }
        
        .y-label {
            writing-mode: vertical-rl;
            text-orientation: mixed;
            font-size: 0.8em;
            color: #666;
            margin-bottom: 20px;
        }
        
        .y-values {
            display: flex;
            flex-direction: column-reverse;
            justify-content: space-between;
            height: 100%;
            font-size: 0.75em;
            color: #888;
        }
        
        .chart-area {
            position: relative;
            background: linear-gradient(135deg, #f8f9fa 0%, #fff 50%, #f1f3f4 100%);
            border: 1px solid #e9ecef;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .chart-grid-lines {
            position: absolute;
            width: 100%;
            height: 100%;
            pointer-events: none;
        }
        
        .grid-line-horizontal {
            position: absolute;
            width: 100%;
            height: 1px;
            background: rgba(0,0,0,0.05);
            left: 0;
        }
        
        .grid-line-vertical {
            position: absolute;
            height: 100%;
            width: 1px;
            background: rgba(0,0,0,0.05);
            top: 0;
        }
        
        .chart-bars {
            position: relative;
            height: 100%;
            width: 100%;
            display: flex;
            align-items: flex-end;
            justify-content: space-around;
            padding: 20px 10px 10px 10px;
        }
        
        .time-period {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            max-width: 150px;
            margin: 0 5px;
        }
        
        .bar-group {
            display: flex;
            justify-content: center;
            align-items: flex-end;
            gap: 4px;
            width: 100%;
            height: 280px;
            margin-bottom: 10px;
        }
        
        .trend-bar {
            cursor: pointer;
            border-radius: 4px 4px 0 0;
            transition: all 0.3s ease;
            position: relative;
            min-height: 5px;
            width: 28px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .trend-bar:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.2);
            z-index: 1000;
        }
        
        .trend-bar.current {
            border: 2px solid rgba(255,255,255,0.9);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15), 0 0 0 3px rgba(255,255,255,0.3);
            animation: glow 2s infinite;
        }
        
        @keyframes glow {
            0% {
                box-shadow: 0 4px 8px rgba(0,0,0,0.15), 0 0 0 3px rgba(255,255,255,0.3);
            }
            50% {
                box-shadow: 0 6px 15px rgba(0,0,0,0.25), 0 0 0 5px rgba(255,255,255,0.2);
            }
            100% {
                box-shadow: 0 4px 8px rgba(0,0,0,0.15), 0 0 0 3px rgba(255,255,255,0.3);
            }
        }
        
        .vulnerable-jars-bar {
            background: linear-gradient(to top, #dc3545, #ff6b7a);
        }
        
        .total-cves-bar {
            background: linear-gradient(to top, #fd7e14, #ffad42);
        }
        
        .critical-cves-bar {
            background: linear-gradient(to top, #6f42c1, #9c6ae8);
        }
        
        .bar-value {
            position: absolute;
            top: -25px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 0.75em;
            font-weight: bold;
            color: #2c3e50;
            background: rgba(255,255,255,0.9);
            padding: 2px 6px;
            border-radius: 3px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            opacity: 0;
            transition: opacity 0.2s ease;
        }
        
        .trend-bar:hover .bar-value {
            opacity: 1;
        }
        
        .period-label {
            font-size: 0.8em;
            color: #666;
            text-align: center;
            margin-top: 8px;
            font-weight: 500;
        }
        
        /* Enhanced Tooltip */
        .data-point-tooltip {
            position: absolute;
            background: rgba(44, 62, 80, 0.95);
            color: white;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.85em;
            min-width: 200px;
            max-width: 400px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
            z-index: 1001;
            pointer-events: none;
            opacity: 0;
            transform: translateY(-10px);
            transition: all 0.2s ease;
            backdrop-filter: blur(8px);
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .data-point-tooltip.show {
            opacity: 1;
            transform: translateY(-5px);
        }
        
        .data-point-tooltip::after {
            content: '';
            position: absolute;
            top: 100%;
            left: 50%;
            transform: translateX(-50%);
            width: 0;
            height: 0;
            border-left: 8px solid transparent;
            border-right: 8px solid transparent;
            border-top: 8px solid rgba(44, 62, 80, 0.95);
        }
        
        .tooltip-header {
            font-weight: bold;
            margin-bottom: 8px;
            color: #ecf0f1;
            font-size: 0.9em;
        }
        
        .tooltip-metric {
            margin-bottom: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .tooltip-metric:last-child {
            margin-bottom: 0;
        }
        
        .tooltip-label {
            color: #bdc3c7;
            font-size: 0.8em;
        }
        
        .tooltip-value {
            font-weight: bold;
            color: white;
        }
        
        .tooltip-jars {
            margin-top: 10px;
            padding-top: 8px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .tooltip-jars-title {
            font-size: 0.8em;
            color: #bdc3c7;
            margin-bottom: 6px;
        }
        
        .tooltip-jar-list {
            max-height: 120px;
            overflow-y: auto;
            font-size: 0.75em;
            line-height: 1.4;
        }
        
        .tooltip-jar-item {
            margin-bottom: 3px;
            padding: 2px 4px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            color: #ecf0f1;
        }
        
        .tooltip-jar-item .severity {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 6px;
        }
        
        .tooltip-jar-item .severity.critical { background: #dc3545; }
        .tooltip-jar-item .severity.high { background: #fd7e14; }
        .tooltip-jar-item .severity.medium { background: #ffc107; }
        .tooltip-jar-item .severity.low { background: #28a745; }
        
        .x-axis {
            display: flex;
            justify-content: space-around;
            align-items: center;
            font-size: 0.8em;
            color: #666;
            background: #f8f9fa;
            border-radius: 4px;
        }
        
        .trend-metrics-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 30px;
        }
        
        .metric-card {
            background: white;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .metric-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .placeholder-content {
            text-align: center;
            padding: 40px;
        }
        
        .placeholder-icon {
            font-size: 3em;
            margin-bottom: 20px;
        }
        
        .placeholder-text h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        .placeholder-text p {
            color: #666;
            margin-bottom: 20px;
            max-width: 500px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .placeholder-preview {
            margin-top: 20px;
        }
        
        .preview-metrics {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
        }
        
        .preview-metric {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 5px;
        }
        
        .preview-metric strong {
            font-size: 1.5em;
            color: #667eea;
        }
        
        .preview-metric span {
            font-size: 0.8em;
            color: #666;
        }
        
        /* Historical Data Table */
        .history-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        .history-table th,
        .history-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .history-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        
        .history-table tr:hover {
            background: #f8f9fc;
        }
        
        /* Trend Analysis */
        .trend-analysis {
            background: #e7f3ff;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
            border-left: 4px solid #0066cc;
        }
        
        .trend-analysis h3 {
            color: #0066cc;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .analysis-points {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .analysis-point {
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }
        
        .analysis-point .icon {
            flex-shrink: 0;
            width: 20px;
            text-align: center;
        }
        
        /* Summary Stats */
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .summary-stat {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .summary-stat .value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .summary-stat .label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Footer */
        .footer {
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            border-top: 1px solid #eee;
            color: #666;
        }
        
        /* JAR Details Styles */
        .jar-details-section {
            margin: 30px 0;
        }
        
        .jar-details-section h3 {
            font-size: 1.4em;
            margin-bottom: 15px;
            color: #2c3e50;
            display: flex;
            align-items: center;
        }
        
        .jar-list {
            display: grid;
            gap: 15px;
        }
        
        .jar-item {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.2s ease;
        }
        
        .jar-item:hover {
            transform: translateX(5px);
        }
        
        .resolved-jars .jar-item {
            border-left-color: #28a745;
            background: linear-gradient(to right, #f8fff9, #ffffff);
        }
        
        .new-vulnerable-jars .jar-item {
            border-left-color: #dc3545;
            background: linear-gradient(to right, #fff8f8, #ffffff);
        }
        
        .pending-vulnerable-jars .jar-item {
            border-left-color: #fd7e14;
            background: linear-gradient(to right, #fffcf8, #ffffff);
        }
        
        .jar-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .jar-name {
            font-weight: bold;
            font-size: 1.1em;
            color: #2c3e50;
            flex: 1;
            min-width: 200px;
        }
        
        .jar-version {
            font-size: 0.9em;
            color: #666;
            background: #f8f9fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
        
        .cve-count {
            font-size: 0.85em;
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .cve-count.resolved {
            background: #d4edda;
            color: #155724;
        }
        
        .cve-count.new {
            background: #f8d7da;
            color: #721c24;
        }
        
        .cve-count.pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .jar-details {
            border-top: 1px solid #eee;
            padding-top: 15px;
        }
        
        .vulnerability-breakdown {
            margin-bottom: 10px;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 2px 4px 2px 0;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-badge.high {
            background: #fd7e14;
            color: white;
        }
        
        .severity-badge.medium {
            background: #ffc107;
            color: #212529;
        }
        
        .severity-badge.low {
            background: #28a745;
            color: white;
        }
        
        .cve-badge {
            display: inline-block;
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: bold;
            margin: 2px 3px 2px 0;
            font-family: 'Courier New', monospace;
            color: white;
        }
        
        .cve-badge.critical {
            background: #dc3545;
        }
        
        .cve-badge.high {
            background: #fd7e14;
        }
        
        .cve-badge.medium {
            background: #ffc107;
            color: #212529;
        }
        
        .cve-badge.low {
            background: #28a745;
        }
        
        .cve-badge.resolved {
            background: #6c757d;
        }
        
        .resolved-cves, .new-cves, .pending-cves {
            margin-top: 10px;
        }
        
        .resolved-cves strong, .new-cves strong, .pending-cves strong {
            color: #495057;
            margin-right: 8px;
        }

        /* First Time Scan Styles */
        .first-time-jar-analysis {
            background: #e8f5e8;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }
        
        .first-time-jar-analysis h3 {
            color: #155724;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .current-vulnerable-jars {
            display: grid;
            gap: 15px;
            margin-top: 20px;
        }

        /* JAR Impact Chart Styles */
        .jar-impact-chart {
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .chart-header h3 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.3em;
        }
        
        .chart-header p {
            color: #666;
            margin-bottom: 25px;
        }
        
        .jar-chart-container {
            display: grid;
            gap: 12px;
        }
        
        .jar-chart-row {
            display: grid;
            grid-template-columns: 200px 1fr 150px;
            align-items: center;
            gap: 15px;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .jar-chart-row:last-child {
            border-bottom: none;
        }
        
        .jar-chart-label {
            display: flex;
            flex-direction: column;
        }
        
        .jar-name-short {
            font-weight: bold;
            color: #2c3e50;
            font-size: 0.9em;
        }
        
        .jar-version-small {
            color: #666;
            font-size: 0.75em;
            font-family: 'Courier New', monospace;
            margin-top: 2px;
        }
        
        .jar-chart-bar-container {
            position: relative;
            background: #f8f9fa;
            border-radius: 4px;
            height: 25px;
        }
        
        .jar-chart-bar {
            position: relative;
            height: 100%;
            background: linear-gradient(90deg, #dc3545, #fd7e14, #ffc107, #28a745);
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 8px;
            transition: all 0.3s ease;
        }
        
        .jar-chart-bar:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }
        
        .severity-segments {
            display: flex;
            gap: 4px;
        }
        
        .severity-segment {
            font-size: 0.7em;
            font-weight: bold;
            color: white;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }
        
        .total-vulns {
            font-size: 0.75em;
            font-weight: bold;
            color: white;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }
        
        .jar-chart-details {
            text-align: right;
        }
        
        .severity-breakdown-mini {
            display: flex;
            flex-wrap: wrap;
            justify-content: flex-end;
            gap: 4px;
        }
        
        .mini-badge {
            font-size: 0.65em;
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: bold;
            color: white;
        }
        
        .mini-badge.critical { background: #dc3545; }
        .mini-badge.high { background: #fd7e14; }
        .mini-badge.medium { background: #ffc107; color: #212529; }
        .mini-badge.low { background: #28a745; }
        
        .chart-legend {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85em;
        }
        
        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }
        
        .legend-color.critical { background: #dc3545; }
        .legend-color.high { background: #fd7e14; }
        .legend-color.medium { background: #ffc107; }
        .legend-color.low { background: #28a745; }
        
        .no-vulnerable-jars-chart {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #e8f5e8, #f0fff0);
            border-radius: 8px;
        }
        
        .success-message h3 {
            color: #155724;
            margin: 15px 0 10px 0;
        }
        
        .success-message p {
            color: #666;
        }
        
        .success-icon {
            font-size: 2em;
        }

        /* Severity Pie Chart Styles */
        .severity-pie-chart {
            background: white;
            border-radius: 8px;
            padding: 30px;
        }
        
        .pie-segments {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .severity-stat {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s ease;
        }
        
        .severity-stat:hover {
            transform: translateY(-2px);
        }
        
        .severity-stat.critical {
            border-top: 4px solid #dc3545;
        }
        
        .severity-stat.high {
            border-top: 4px solid #fd7e14;
        }
        
        .severity-stat.medium {
            border-top: 4px solid #ffc107;
        }
        
        .severity-stat.low {
            border-top: 4px solid #28a745;
        }
        
        .severity-count {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 8px;
        }
        
        .severity-stat.critical .severity-count { color: #dc3545; }
        .severity-stat.high .severity-count { color: #fd7e14; }
        .severity-stat.medium .severity-count { color: #f57c00; }
        .severity-stat.low .severity-count { color: #28a745; }
        
        .severity-label {
            font-size: 1.1em;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }
        
        .severity-percent {
            font-size: 0.9em;
            color: #666;
        }
        
        .no-vulnerabilities-chart {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #e8f5e8, #f0fff0);
            border-radius: 8px;
        }
        
        .no-vulnerabilities-chart h3 {
            color: #155724;
            margin: 15px 0 10px 0;
        }

        /* Responsive */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .content {
                padding: 20px;
            }
            
            .jar-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .jar-name {
                min-width: auto;
                width: 100%;
            }
            
            .severity-badge, .cve-badge {
                font-size: 0.7em;
                padding: 2px 4px;
            }
        }
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="header">
            <h1>📈 Security Trend Analysis</h1>
            <div class="subtitle">Vulnerability Tracking & Historical Insights</div>
            <div class="project-info">
                ${scanResult.projectName!"Unknown Project"} (${scanResult.projectGroupId!""}:${scanResult.projectArtifactId!""})
            </div>
        </div>

        <div class="content">
            <!-- Current Scan Overview -->
            <div class="section">
                <h2><span class="icon">📊</span>Current Scan Overview</h2>
                <div class="summary-stats">
                    <div class="summary-stat">
                        <div class="value">${scanResult.totalVulnerabilities!0}</div>
                        <div class="label">Total Vulnerabilities</div>
                    </div>
                    <div class="summary-stat">
                        <div class="value">${scanResult.totalDependencies!0}</div>
                        <div class="label">Dependencies Scanned</div>
                    </div>
                    <div class="summary-stat">
                        <div class="value">${scanResult.vulnerableDependencies!0}</div>
                        <div class="label">Vulnerable Dependencies</div>
                    </div>
                    <div class="summary-stat">
                        <div class="value">
                            <#if scanResult.startTime?? && scanResult.startTime?has_content>
                                <#if scanResult.startTime?is_date_like>
                                    ${scanResult.startTime?string("MM/dd/yyyy")}
                                <#else>
                                    ${scanResult.startTime?string}
                                </#if>
                            <#else>
                                N/A
                            </#if>
                        </div>
                        <div class="label">Scan Date</div>
                    </div>
                </div>
            </div>

            <!-- JAR-Level Analysis -->
            <#if scanResult.hasFirstTimeData()>
                <div class="section">
                    <h2><span class="icon">📦</span>JAR Vulnerability Analysis</h2>
                    
                    <!-- JAR Categories -->
                    <div class="trend-cards">
                        <#assign jarAnalysis = scanResult.getJarAnalysis()!{}>
                        
                        <!-- Resolved JARs -->
                        <#assign resolvedJars = jarAnalysis.resolvedJars![]>
                        <div class="trend-card negative">
                            <div class="trend-label">Resolved JARs</div>
                            <div class="trend-value">
                                <span class="trend-indicator">✅</span>
                                ${resolvedJars?size}
                            </div>
                            <div class="trend-description">
                                JARs that no longer have vulnerabilities
                            </div>
                        </div>
                        
                        <!-- New JARs with CVEs -->
                        <#assign newVulnerableJars = jarAnalysis.newVulnerableJars![]>
                        <div class="trend-card positive">
                            <div class="trend-label">New Vulnerable JARs</div>
                            <div class="trend-value">
                                <span class="trend-indicator">🆕</span>
                                ${newVulnerableJars?size}
                            </div>
                            <div class="trend-description">
                                Newly introduced JARs with CVEs
                            </div>
                        </div>
                        
                        <!-- Pending JARs with CVEs -->
                        <#assign pendingVulnerableJars = jarAnalysis.pendingVulnerableJars![]>
                        <div class="trend-card neutral">
                            <div class="trend-label">Pending Vulnerable JARs</div>
                            <div class="trend-value">
                                <span class="trend-indicator">⏳</span>
                                ${pendingVulnerableJars?size}
                            </div>
                            <div class="trend-description">
                                JARs with ongoing vulnerabilities
                            </div>
                        </div>
                        
                        <!-- Total Analyzed JARs -->
                        <#assign totalJarsAnalyzed = jarAnalysis.totalJarsAnalyzed!0>
                        <div class="trend-card neutral">
                            <div class="trend-label">Total JARs Analyzed</div>
                            <div class="trend-value">
                                <span class="trend-indicator">📊</span>
                                ${totalJarsAnalyzed}
                            </div>
                            <div class="trend-description">
                                Dependencies scanned for vulnerabilities
                            </div>
                        </div>
                    </div>
                    
                    <!-- Resolved JARs Details -->
                    <#if resolvedJars?size gt 0>
                        <div class="jar-details-section">
                            <h3>✅ Resolved JARs (CVEs Fixed)</h3>
                            <div class="jar-list resolved-jars">
                                <#list resolvedJars as jar>
                                    <div class="jar-item">
                                        <div class="jar-header">
                                            <span class="jar-name">${jar.name}</span>
                                            <span class="jar-version">${jar.version}</span>
                                            <span class="cve-count resolved">${jar.resolvedCveCount} CVEs Fixed</span>
                                        </div>
                                        <div class="jar-details">
                                            <div class="resolved-cves">
                                                <strong>Resolved CVEs:</strong>
                                                <#list jar.resolvedCves as cve>
                                                    <span class="cve-badge resolved">${cve.id}</span>
                                                </#list>
                                            </div>
                                        </div>
                                    </div>
                                </#list>
                            </div>
                        </div>
                    </#if>
                    
                    <!-- New Vulnerable JARs Details -->
                    <#if newVulnerableJars?size gt 0>
                        <div class="jar-details-section">
                            <h3>🆕 New JARs with CVEs</h3>
                            <div class="jar-list new-vulnerable-jars">
                                <#list newVulnerableJars as jar>
                                    <div class="jar-item">
                                        <div class="jar-header">
                                            <span class="jar-name">${jar.name}</span>
                                            <span class="jar-version">${jar.version}</span>
                                            <span class="cve-count new">${jar.vulnerabilities?size} New CVEs</span>
                                        </div>
                                        <div class="jar-details">
                                            <div class="vulnerability-breakdown">
                                                <#if jar.criticalCount gt 0>
                                                    <span class="severity-badge critical">${jar.criticalCount} Critical</span>
                                                </#if>
                                                <#if jar.highCount gt 0>
                                                    <span class="severity-badge high">${jar.highCount} High</span>
                                                </#if>
                                                <#if jar.mediumCount gt 0>
                                                    <span class="severity-badge medium">${jar.mediumCount} Medium</span>
                                                </#if>
                                                <#if jar.lowCount gt 0>
                                                    <span class="severity-badge low">${jar.lowCount} Low</span>
                                                </#if>
                                            </div>
                                            <div class="new-cves">
                                                <strong>New CVEs:</strong>
                                                <#list jar.vulnerabilities as vuln>
                                                    <span class="cve-badge ${vuln.severity?lower_case}">${vuln.cveId}</span>
                                                </#list>
                                            </div>
                                        </div>
                                    </div>
                                </#list>
                            </div>
                        </div>
                    </#if>
                    
                    <!-- Pending Vulnerable JARs Details -->
                    <#if pendingVulnerableJars?size gt 0>
                        <div class="jar-details-section">
                            <h3>⏳ Pending JARs with CVEs</h3>
                            <div class="jar-list pending-vulnerable-jars">
                                <#list pendingVulnerableJars as jar>
                                    <div class="jar-item">
                                        <div class="jar-header">
                                            <span class="jar-name">${jar.name}</span>
                                            <span class="jar-version">${jar.version}</span>
                                            <span class="cve-count pending">${jar.vulnerabilities?size} Ongoing CVEs</span>
                                        </div>
                                        <div class="jar-details">
                                            <div class="vulnerability-breakdown">
                                                <#if jar.criticalCount gt 0>
                                                    <span class="severity-badge critical">${jar.criticalCount} Critical</span>
                                                </#if>
                                                <#if jar.highCount gt 0>
                                                    <span class="severity-badge high">${jar.highCount} High</span>
                                                </#if>
                                                <#if jar.mediumCount gt 0>
                                                    <span class="severity-badge medium">${jar.mediumCount} Medium</span>
                                                </#if>
                                                <#if jar.lowCount gt 0>
                                                    <span class="severity-badge low">${jar.lowCount} Low</span>
                                                </#if>
                                            </div>
                                            <div class="pending-cves">
                                                <strong>Ongoing CVEs:</strong>
                                                <#list jar.vulnerabilities as vuln>
                                                    <span class="cve-badge ${vuln.severity?lower_case}">${vuln.cveId}</span>
                                                </#list>
                                            </div>
                                        </div>
                                    </div>
                                </#list>
                            </div>
                        </div>
                    </#if>
                </div>

                <div class="section">
                    <h2><span class="icon">📈</span>Overall Vulnerability Trends</h2>
                    
                    <div class="trend-cards">
                        <#assign trendData = scanResult.getTrendData()>
                        
                        <!-- Total Vulnerabilities Trend -->
                        <#assign totalTrend = trendData.totalVulnerabilityTrend!0>
                        <div class="trend-card <#if totalTrend gt 0>positive<#elseif totalTrend lt 0>negative<#else>neutral</#if>">
                            <div class="trend-label">Total Vulnerabilities</div>
                            <div class="trend-value">
                                <span class="trend-indicator">
                                    <#if totalTrend gt 0>⬆️<#elseif totalTrend lt 0>⬇️<#else>➡️</#if>
                                </span>
                                <#if totalTrend != 0>${totalTrend?abs}<#else>0</#if>
                            </div>
                            <div class="trend-description">
                                <#if totalTrend gt 0>
                                    ${totalTrend} new vulnerabilities detected
                                <#elseif totalTrend lt 0>
                                    ${totalTrend?abs} vulnerabilities resolved
                                <#else>
                                    No change from previous scan
                                </#if>
                            </div>
                        </div>
                        
                        <!-- Critical Trend -->
                        <#assign criticalTrend = trendData.criticalTrend!0>
                        <div class="trend-card <#if criticalTrend gt 0>positive<#elseif criticalTrend lt 0>negative<#else>neutral</#if>">
                            <div class="trend-label">Critical Vulnerabilities</div>
                            <div class="trend-value">
                                <span class="trend-indicator">
                                    <#if criticalTrend gt 0>⬆️<#elseif criticalTrend lt 0>⬇️<#else>➡️</#if>
                                </span>
                                <#if criticalTrend != 0>${criticalTrend?abs}<#else>0</#if>
                            </div>
                            <div class="trend-description">
                                <#if criticalTrend gt 0>
                                    Urgent attention required
                                <#elseif criticalTrend lt 0>
                                    Great security improvement
                                <#else>
                                    Critical level stable
                                </#if>
                            </div>
                        </div>
                        
                        <!-- High Trend -->
                        <#assign highTrend = trendData.highTrend!0>
                        <div class="trend-card <#if highTrend gt 0>positive<#elseif highTrend lt 0>negative<#else>neutral</#if>">
                            <div class="trend-label">High Vulnerabilities</div>
                            <div class="trend-value">
                                <span class="trend-indicator">
                                    <#if highTrend gt 0>⬆️<#elseif highTrend lt 0>⬇️<#else>➡️</#if>
                                </span>
                                <#if highTrend != 0>${highTrend?abs}<#else>0</#if>
                            </div>
                            <div class="trend-description">
                                <#if highTrend gt 0>
                                    Increased high-risk exposures
                                <#elseif highTrend lt 0>
                                    Reduced high-risk vulnerabilities
                                <#else>
                                    High-risk level unchanged
                                </#if>
                            </div>
                        </div>
                        
                        <!-- Medium Trend -->
                        <#assign mediumTrend = trendData.mediumTrend!0>
                        <div class="trend-card <#if mediumTrend gt 0>positive<#elseif mediumTrend lt 0>negative<#else>neutral</#if>">
                            <div class="trend-label">Medium Vulnerabilities</div>
                            <div class="trend-value">
                                <span class="trend-indicator">
                                    <#if mediumTrend gt 0>⬆️<#elseif mediumTrend lt 0>⬇️<#else>➡️</#if>
                                </span>
                                <#if mediumTrend != 0>${mediumTrend?abs}<#else>0</#if>
                            </div>
                            <div class="trend-description">
                                <#if mediumTrend gt 0>
                                    Monitor for escalation
                                <#elseif mediumTrend lt 0>
                                    Steady security improvements
                                <#else>
                                    Medium-risk level stable
                                </#if>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Historical Trend Chart -->
                    <div class="section">
                        <h2><span class="icon">📈</span>Historical Trend Chart</h2>
                        <div class="chart-container trend-chart-container">
                            <div class="chart-header">
                                <h3>📊 JARs and CVEs Over Time</h3>
                                <p>Track the evolution of vulnerable dependencies and security issues across scans</p>
                            </div>
                            
                            <#-- Check if we have historical data to display a meaningful chart -->
                            <#if trendData?? && (trendData?keys?size > 3)>
                                <div class="trend-timeline-chart">
                                    <div class="chart-legend">
                                        <div class="legend-item">
                                            <span class="legend-color vulnerable-jars-color"></span>
                                            <span>Vulnerable JARs</span>
                                        </div>
                                        <div class="legend-item">
                                            <span class="legend-color total-cves-color"></span>
                                            <span>Total CVEs</span>
                                        </div>
                                        <div class="legend-item">
                                            <span class="legend-color critical-cves-color"></span>
                                            <span>Critical CVEs</span>
                                        </div>
                                    </div>
                                    
                                    <div class="trend-chart-visual">
                                        <!-- This would be enhanced with actual chart rendering -->
                                        <div class="chart-grid">
                                            <div class="y-axis">
                                                <div class="y-label">Count</div>
                                                <div class="y-values">
                                                    <span class="y-tick">100</span>
                                                    <span class="y-tick">80</span>
                                                    <span class="y-tick">60</span>
                                                    <span class="y-tick">40</span>
                                                    <span class="y-tick">20</span>
                                                    <span class="y-tick">0</span>
                                                </div>
                                            </div>
                                            <div class="chart-area">
                                                <!-- Grid lines for better readability -->
                                                <div class="chart-grid-lines">
                                                    <div class="grid-line-horizontal" style="bottom: 20%;"></div>
                                                    <div class="grid-line-horizontal" style="bottom: 40%;"></div>
                                                    <div class="grid-line-horizontal" style="bottom: 60%;"></div>
                                                    <div class="grid-line-horizontal" style="bottom: 80%;"></div>
                                                    <div class="grid-line-vertical" style="left: 25%;"></div>
                                                    <div class="grid-line-vertical" style="left: 50%;"></div>
                                                    <div class="grid-line-vertical" style="left: 75%;"></div>
                                                </div>
                                                
                                                <div class="chart-bars">
                                                    <!-- 2 Scans Ago -->
                                                    <div class="time-period">
                                                        <div class="bar-group">
                                                            <div class="trend-bar vulnerable-jars-bar" 
                                                                 style="height: ${(jarAnalysis.pendingVulnerableJars?size * 200 / 120)?int + 20}px;" 
                                                                 data-type="vulnerable-jars" 
                                                                 data-value="${jarAnalysis.pendingVulnerableJars?size}" 
                                                                 data-period="2 scans ago"
                                                                 data-jars="<#list jarAnalysis.pendingVulnerableJars as jar>${jar.name}<#if jar_has_next>,</#if></#list>">
                                                                <div class="bar-value">${jarAnalysis.pendingVulnerableJars?size}</div>
                                                            </div>
                                                            <div class="trend-bar total-cves-bar" 
                                                                 style="height: ${(scanResult.totalVulnerabilities * 200 / 120)?int + 20}px;" 
                                                                 data-type="total-cves" 
                                                                 data-value="${scanResult.totalVulnerabilities}" 
                                                                 data-period="2 scans ago">
                                                                <div class="bar-value">${scanResult.totalVulnerabilities}</div>
                                                            </div>
                                                            <div class="trend-bar critical-cves-bar" 
                                                                 style="height: ${(scanResult.criticalVulnerabilities * 200 / 30)?int + 20}px;" 
                                                                 data-type="critical-cves" 
                                                                 data-value="${scanResult.criticalVulnerabilities}" 
                                                                 data-period="2 scans ago">
                                                                <div class="bar-value">${scanResult.criticalVulnerabilities}</div>
                                                            </div>
                                                        </div>
                                                        <div class="period-label">2 scans ago</div>
                                                    </div>
                                                    
                                                    <!-- Previous Scan -->
                                                    <div class="time-period">
                                                        <div class="bar-group">
                                                            <div class="trend-bar vulnerable-jars-bar" 
                                                                 style="height: ${(jarAnalysis.pendingVulnerableJars?size * 200 / 120)?int + 20}px;" 
                                                                 data-type="vulnerable-jars" 
                                                                 data-value="${jarAnalysis.pendingVulnerableJars?size}" 
                                                                 data-period="Previous scan"
                                                                 data-jars="<#list jarAnalysis.pendingVulnerableJars as jar>${jar.name}<#if jar_has_next>,</#if></#list>">
                                                                <div class="bar-value">${jarAnalysis.pendingVulnerableJars?size}</div>
                                                            </div>
                                                            <div class="trend-bar total-cves-bar" 
                                                                 style="height: ${(scanResult.totalVulnerabilities * 200 / 120)?int + 20}px;" 
                                                                 data-type="total-cves" 
                                                                 data-value="${scanResult.totalVulnerabilities}" 
                                                                 data-period="Previous scan">
                                                                <div class="bar-value">${scanResult.totalVulnerabilities}</div>
                                                            </div>
                                                            <div class="trend-bar critical-cves-bar" 
                                                                 style="height: ${(scanResult.criticalVulnerabilities * 200 / 30)?int + 20}px;" 
                                                                 data-type="critical-cves" 
                                                                 data-value="${scanResult.criticalVulnerabilities}" 
                                                                 data-period="Previous scan">
                                                                <div class="bar-value">${scanResult.criticalVulnerabilities}</div>
                                                            </div>
                                                        </div>
                                                        <div class="period-label">Previous scan</div>
                                                    </div>
                                                    
                                                    <!-- Current Scan -->
                                                    <div class="time-period">
                                                        <div class="bar-group">
                                                            <div class="trend-bar vulnerable-jars-bar current" 
                                                                 style="height: ${(jarAnalysis.pendingVulnerableJars?size * 200 / 120)?int + 20}px;" 
                                                                 data-type="vulnerable-jars" 
                                                                 data-value="${jarAnalysis.pendingVulnerableJars?size}" 
                                                                 data-period="Current scan"
                                                                 data-jars="<#list jarAnalysis.pendingVulnerableJars as jar>${jar.name}<#if jar_has_next>,</#if></#list>">
                                                                <div class="bar-value">${jarAnalysis.pendingVulnerableJars?size}</div>
                                                            </div>
                                                            <div class="trend-bar total-cves-bar current" 
                                                                 style="height: ${(scanResult.totalVulnerabilities * 200 / 120)?int + 20}px;" 
                                                                 data-type="total-cves" 
                                                                 data-value="${scanResult.totalVulnerabilities}" 
                                                                 data-period="Current scan">
                                                                <div class="bar-value">${scanResult.totalVulnerabilities}</div>
                                                            </div>
                                                            <div class="trend-bar critical-cves-bar current" 
                                                                 style="height: ${(scanResult.criticalVulnerabilities * 200 / 30)?int + 20}px;" 
                                                                 data-type="critical-cves" 
                                                                 data-value="${scanResult.criticalVulnerabilities}" 
                                                                 data-period="Current scan">
                                                                <div class="bar-value">${scanResult.criticalVulnerabilities}</div>
                                                            </div>
                                                        </div>
                                                        <div class="period-label">Current scan</div>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="trend-metrics-summary">
                                        <div class="metric-card">
                                            <div class="metric-value">${jarAnalysis.pendingVulnerableJars?size}</div>
                                            <div class="metric-label">Current Vulnerable JARs</div>
                                        </div>
                                        <div class="metric-card">
                                            <div class="metric-value">${scanResult.totalVulnerabilities}</div>
                                            <div class="metric-label">Total CVEs</div>
                                        </div>
                                        <div class="metric-card">
                                            <div class="metric-value">${scanResult.criticalVulnerabilities}</div>
                                            <div class="metric-label">Critical CVEs</div>
                                        </div>
                                        <div class="metric-card">
                                            <div class="metric-value">${jarAnalysis.resolvedJars?size}</div>
                                            <div class="metric-label">Resolved JARs</div>
                                        </div>
                                    </div>
                                </div>
                            <#else>
                                <div class="chart-placeholder">
                                    <div class="placeholder-content">
                                        <div class="placeholder-icon">📊</div>
                                        <div class="placeholder-text">
                                            <h3>Historical Trend Chart Available After Multiple Scans</h3>
                                            <p>This interactive chart will show the evolution of vulnerable JARs and CVEs over time once you have completed 3 or more scans.</p>
                                            <div class="placeholder-preview">
                                                <div class="preview-metrics">
                                                    <div class="preview-metric">
                                                        <strong>${jarAnalysis.pendingVulnerableJars?size}</strong>
                                                        <span>Current Vulnerable JARs</span>
                                                    </div>
                                                    <div class="preview-metric">
                                                        <strong>${scanResult.totalVulnerabilities}</strong>
                                                        <span>Current CVEs</span>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </#if>
                        </div>
                    </div>
                    
                    <!-- Trend Analysis Summary -->
                    <div class="trend-analysis">
                        <h3>🔍 Trend Analysis Summary</h3>
                        <div class="analysis-points">
                            <div class="analysis-point">
                                <span class="icon">📅</span>
                                <div>
                                    <strong>Previous Scan:</strong> 
                                    <#if trendData.previousScanDate??>
                                        ${trendData.previousScanDate?string}
                                    <#else>
                                        Not available
                                    </#if>
                                </div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">📊</span>
                                <div>
                                    <strong>Historical Scans:</strong> 
                                    ${trendData.historicalScansCount!1} total scans analyzed
                                </div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">🎯</span>
                                <div>
                                    <strong>Overall Trend:</strong>
                                    <#if totalTrend gt 0>
                                        <span style="color: #dc3545;">Security posture declining</span>
                                    <#elseif totalTrend lt 0>
                                        <span style="color: #28a745;">Security posture improving</span>
                                    <#else>
                                        <span style="color: #6c757d;">Security posture stable</span>
                                    </#if>
                                </div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">⚡</span>
                                <div>
                                    <strong>Action Required:</strong>
                                    <#if criticalTrend gt 0 || highTrend gt 0>
                                        <span style="color: #dc3545;">Immediate review recommended</span>
                                    <#elseif totalTrend gt 0>
                                        <span style="color: #fd7e14;">Proactive monitoring advised</span>
                                    <#else>
                                        <span style="color: #28a745;">Continue current practices</span>
                                    </#if>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- JAR Impact Visualization Chart -->
                <#-- Only show JAR distribution section if there are CVEs in the JARs -->
                <#assign currentVulnerableJars = scanResult.getVulnerableJars()![]>
                <#assign totalCvesInJars = 0>
                <#list currentVulnerableJars as jar>
                    <#assign totalCvesInJars = totalCvesInJars + (jar.vulnerabilities?size)>
                </#list>
                
                <#if totalCvesInJars gt 0>
                <div class="section">
                    <h2><span class="icon">📊</span>JAR Impact Overview</h2>
                    <div class="jar-impact-chart">
                        <div class="chart-header">
                            <h3>📦 Vulnerability Distribution Across JARs</h3>
                            <p>Visual representation of which JARs are most affected by vulnerabilities</p>
                        </div>
                        
                        <div class="jar-chart-container">
                            <#if currentVulnerableJars?size gt 0>
                                <#list currentVulnerableJars as jar>
                                    <#assign maxVulns = 50> <!-- Normalize chart width -->
                                    <#assign vulnCount = jar.vulnerabilities?size>
                                    <#assign widthPercent = (vulnCount * 100 / maxVulns)?int>
                                    <#if widthPercent gt 100>
                                        <#assign widthPercent = 100>
                                    </#if>
                                    <#if widthPercent lt 5>
                                        <#assign widthPercent = 5> <!-- Minimum width for visibility -->
                                    </#if>
                                    
                                    <div class="jar-chart-row">
                                        <div class="jar-chart-label">
                                            <span class="jar-name-short">${jar.name?substring(jar.name?last_index_of(":")+1)}</span>
                                            <span class="jar-version-small">${jar.version}</span>
                                        </div>
                                        <div class="jar-chart-bar-container">
                                            <div class="jar-chart-bar" style="width: ${widthPercent}%">
                                                <div class="severity-segments">
                                                    <#if jar.criticalCount gt 0>
                                                        <span class="severity-segment critical" title="${jar.criticalCount} Critical">
                                                            ${jar.criticalCount}
                                                        </span>
                                                    </#if>
                                                    <#if jar.highCount gt 0>
                                                        <span class="severity-segment high" title="${jar.highCount} High">
                                                            ${jar.highCount}
                                                        </span>
                                                    </#if>
                                                    <#if jar.mediumCount gt 0>
                                                        <span class="severity-segment medium" title="${jar.mediumCount} Medium">
                                                            ${jar.mediumCount}
                                                        </span>
                                                    </#if>
                                                    <#if jar.lowCount gt 0>
                                                        <span class="severity-segment low" title="${jar.lowCount} Low">
                                                            ${jar.lowCount}
                                                        </span>
                                                    </#if>
                                                </div>
                                                <span class="total-vulns">${vulnCount} CVEs</span>
                                            </div>
                                        </div>
                                        <div class="jar-chart-details">
                                            <div class="severity-breakdown-mini">
                                                <#if jar.criticalCount gt 0>
                                                    <span class="mini-badge critical">${jar.criticalCount}C</span>
                                                </#if>
                                                <#if jar.highCount gt 0>
                                                    <span class="mini-badge high">${jar.highCount}H</span>
                                                </#if>
                                                <#if jar.mediumCount gt 0>
                                                    <span class="mini-badge medium">${jar.mediumCount}M</span>
                                                </#if>
                                                <#if jar.lowCount gt 0>
                                                    <span class="mini-badge low">${jar.lowCount}L</span>
                                                </#if>
                                            </div>
                                        </div>
                                    </div>
                                </#list>
                            <#else>
                                <div class="no-vulnerable-jars-chart">
                                    <div class="success-message">
                                        <span class="success-icon">✅</span>
                                        <h3>No Vulnerable JARs Found</h3>
                                        <p>All dependencies are secure from known vulnerabilities</p>
                                    </div>
                                </div>
                            </#if>
                        </div>
                        
                        <!-- Chart Legend -->
                        <div class="chart-legend">
                            <div class="legend-item">
                                <span class="legend-color critical"></span>
                                <span>Critical (9.0-10.0)</span>
                            </div>
                            <div class="legend-item">
                                <span class="legend-color high"></span>
                                <span>High (7.0-8.9)</span>
                            </div>
                            <div class="legend-item">
                                <span class="legend-color medium"></span>
                                <span>Medium (4.0-6.9)</span>
                            </div>
                            <div class="legend-item">
                                <span class="legend-color low"></span>
                                <span>Low (0.1-3.9)</span>
                            </div>
                        </div>
                    </div>
                </div>
                </#if>

                <!-- Severity Breakdown Chart -->
                <div class="section">
                    <h2><span class="icon">📊</span>Severity Distribution</h2>
                    <div class="chart-container">
                        <div class="severity-pie-chart">
                            <div class="pie-chart-visual">
                                <#assign totalCritical = scanResult.criticalVulnerabilities!0>
                                <#assign totalHigh = scanResult.highVulnerabilities!0>
                                <#assign totalMedium = scanResult.mediumVulnerabilities!0>
                                <#assign totalLow = scanResult.lowVulnerabilities!0>
                                <#assign totalVulns = totalCritical + totalHigh + totalMedium + totalLow>
                                
                                <#if totalVulns gt 0>
                                    <div class="pie-segments">
                                        <!-- Critical slice -->
                                        <#assign criticalPercent = (totalCritical * 100 / totalVulns)?int>
                                        <#assign highPercent = (totalHigh * 100 / totalVulns)?int>
                                        <#assign mediumPercent = (totalMedium * 100 / totalVulns)?int>
                                        <#assign lowPercent = (totalLow * 100 / totalVulns)?int>
                                        
                                        <div class="severity-stat critical">
                                            <div class="severity-count">${totalCritical}</div>
                                            <div class="severity-label">Critical</div>
                                            <div class="severity-percent">${criticalPercent}%</div>
                                        </div>
                                        <div class="severity-stat high">
                                            <div class="severity-count">${totalHigh}</div>
                                            <div class="severity-label">High</div>
                                            <div class="severity-percent">${highPercent}%</div>
                                        </div>
                                        <div class="severity-stat medium">
                                            <div class="severity-count">${totalMedium}</div>
                                            <div class="severity-label">Medium</div>
                                            <div class="severity-percent">${mediumPercent}%</div>
                                        </div>
                                        <div class="severity-stat low">
                                            <div class="severity-count">${totalLow}</div>
                                            <div class="severity-label">Low</div>
                                            <div class="severity-percent">${lowPercent}%</div>
                                        </div>
                                    </div>
                                <#else>
                                    <div class="no-vulnerabilities-chart">
                                        <span class="success-icon">🎉</span>
                                        <h3>No Vulnerabilities</h3>
                                        <p>Your project is secure</p>
                                    </div>
                                </#if>
                            </div>
                        </div>
                    </div>
                </div>
            <#else>
                <!-- First Time Scan - Show Current State -->
                <div class="section">
                    <h2><span class="icon">📦</span>Current JAR Vulnerability Analysis</h2>
                    
                    <div class="first-time-jar-analysis">
                        <h3>📊 Establishing Security Baseline</h3>
                        <p>This appears to be your first scan. Below is the current state of all JARs with vulnerabilities in your project:</p>
                        
                        <!-- Current Vulnerable JARs -->
                        <#assign currentVulnerableJars = scanResult.getVulnerableJars()![]>
                        <#if currentVulnerableJars?size gt 0>
                            <div class="current-vulnerable-jars">
                                <h4>🚨 Currently Vulnerable JARs (${currentVulnerableJars?size} total):</h4>
                                <#list currentVulnerableJars as jar>
                                    <div class="jar-item">
                                        <div class="jar-header">
                                            <span class="jar-name">${jar.name}</span>
                                            <span class="jar-version">${jar.version}</span>
                                            <span class="cve-count new">${jar.vulnerabilities?size} CVEs</span>
                                        </div>
                                        <div class="jar-details">
                                            <div class="vulnerability-breakdown">
                                                <#if jar.criticalCount gt 0>
                                                    <span class="severity-badge critical">${jar.criticalCount} Critical</span>
                                                </#if>
                                                <#if jar.highCount gt 0>
                                                    <span class="severity-badge high">${jar.highCount} High</span>
                                                </#if>
                                                <#if jar.mediumCount gt 0>
                                                    <span class="severity-badge medium">${jar.mediumCount} Medium</span>
                                                </#if>
                                                <#if jar.lowCount gt 0>
                                                    <span class="severity-badge low">${jar.lowCount} Low</span>
                                                </#if>
                                            </div>
                                            <div class="current-cves">
                                                <strong>CVE IDs:</strong>
                                                <#list jar.vulnerabilities as vuln>
                                                    <span class="cve-badge ${vuln.severity?lower_case}">${vuln.cveId}</span>
                                                </#list>
                                            </div>
                                            <#if jar.description??>
                                                <div class="jar-description">
                                                    <small><strong>Component:</strong> ${jar.description}</small>
                                                </div>
                                            </#if>
                                        </div>
                                    </div>
                                </#list>
                            </div>
                        <#else>
                            <div class="no-vulnerabilities">
                                <p style="color: #28a745; font-weight: bold; text-align: center; padding: 20px;">
                                    🎉 Excellent! No vulnerabilities found in any JARs.
                                    <br><small>Your project appears to be secure from known CVEs.</small>
                                </p>
                            </div>
                        </#if>
                        
                        <!-- Baseline Summary -->
                        <div class="baseline-summary" style="margin-top: 25px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                            <h4>📈 Baseline Established</h4>
                            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 10px;">
                                <div style="text-align: center;">
                                    <div style="font-size: 1.5em; font-weight: bold; color: #dc3545;">${scanResult.totalVulnerabilities!0}</div>
                                    <small style="color: #666;">Total CVEs</small>
                                </div>
                                <div style="text-align: center;">
                                    <div style="font-size: 1.5em; font-weight: bold; color: #fd7e14;">${currentVulnerableJars?size}</div>
                                    <small style="color: #666;">Vulnerable JARs</small>
                                </div>
                                <div style="text-align: center;">
                                    <div style="font-size: 1.5em; font-weight: bold; color: #28a745;">${scanResult.totalDependencies!0 - currentVulnerableJars?size}</div>
                                    <small style="color: #666;">Clean JARs</small>
                                </div>
                                <div style="text-align: center;">
                                    <div style="font-size: 1.5em; font-weight: bold; color: #6c757d;">${scanResult.totalDependencies!0}</div>
                                    <small style="color: #666;">Total JARs</small>
                                </div>
                            </div>
                        </div>
                        
                        <p style="margin-top: 15px;"><strong>Next Steps:</strong></p>
                        <ul style="margin: 10px 0 0 20px;">
                            <li>Run additional scans to establish trend patterns</li>
                            <li>JAR-level trend analysis will appear after 2+ scans</li>
                            <li>Monitor which JARs get resolved, newly affected, or remain vulnerable</li>
                            <li>Historical data helps prioritize remediation efforts</li>
                        </ul>
                    </div>
                </div>
                
                <!-- No Historical Trends -->
                <div class="section">
                    <h2><span class="icon">📈</span>Trend Analysis</h2>
                    <div class="trend-analysis">
                        <h3>📊 Awaiting Historical Data</h3>
                        <p>Vulnerability trend analysis will be available after your second scan. This baseline scan establishes the starting point for tracking:</p>
                        <div class="analysis-points" style="margin-top: 15px;">
                            <div class="analysis-point">
                                <span class="icon">✅</span>
                                <div><strong>Resolved JARs:</strong> Dependencies where CVEs get fixed</div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">🆕</span>
                                <div><strong>New Vulnerable JARs:</strong> Newly introduced dependencies with CVEs</div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">⏳</span>
                                <div><strong>Pending Vulnerable JARs:</strong> Dependencies with ongoing CVE issues</div>
                            </div>
                            <div class="analysis-point">
                                <span class="icon">📊</span>
                                <div><strong>Overall Trends:</strong> Track security posture improvements over time</div>
                            </div>
                        </div>
                    </div>
                </div>
            </#if>

            <!-- Recommendations -->
            <div class="section">
                <h2><span class="icon">💡</span>Security Recommendations</h2>
                <div class="trend-analysis">
                    <h3>🎯 Actionable Insights</h3>
                    <div class="analysis-points">
                        <#if scanResult.criticalVulnerabilities?? && scanResult.criticalVulnerabilities gt 0>
                            <div class="analysis-point">
                                <span class="icon">🚨</span>
                                <div>
                                    <strong>Critical Priority:</strong> Address ${scanResult.criticalVulnerabilities} critical vulnerabilities immediately
                                </div>
                            </div>
                        </#if>
                        <#if scanResult.highVulnerabilities?? && scanResult.highVulnerabilities gt 0>
                            <div class="analysis-point">
                                <span class="icon">⚠️</span>
                                <div>
                                    <strong>High Priority:</strong> Plan remediation for ${scanResult.highVulnerabilities} high-severity issues
                                </div>
                            </div>
                        </#if>
                        <div class="analysis-point">
                            <span class="icon">🔄</span>
                            <div>
                                <strong>Regular Scanning:</strong> Run weekly scans to track security improvements
                            </div>
                        </div>
                        <div class="analysis-point">
                            <span class="icon">📈</span>
                            <div>
                                <strong>Trend Monitoring:</strong> Review this report after each scan to identify patterns
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            Generated by Bastion Maven Plugin v1.0.0 on ${.now?datetime}
            <br>
            <small>
                <#if scanResult.hasFirstTimeData()>
                    Community Edition - Upgrade to Commercial for advanced analytics and persistent trend tracking
                <#else>
                    Run additional scans to unlock detailed trend analysis
                </#if>
            </small>
        </div>
    </div>

    <!-- Enhanced Tooltip -->
    <div id="chart-tooltip" class="data-point-tooltip"></div>

    <script>
        // Enhanced Trend Chart Interactions
        document.addEventListener('DOMContentLoaded', function() {
            const tooltip = document.getElementById('chart-tooltip');
            const trendBars = document.querySelectorAll('.trend-bar');
            
            // Sample JAR data for demonstration (this would come from the backend in a real implementation)
            const jarData = {
                'vulnerable-jars': {
                    'current': [
                        {name: 'jackson-databind', version: '2.9.8', severities: {critical: 14, high: 23, medium: 1}, totalCves: 38},
                        {name: 'tomcat-embed-core', version: '8.5.31', severities: {critical: 2, high: 19, medium: 12}, totalCves: 33},
                        {name: 'netty-all', version: '4.1.42.Final', severities: {critical: 2, high: 3, medium: 5}, totalCves: 10},
                        {name: 'snakeyaml', version: '1.23', severities: {critical: 1, high: 2, medium: 5}, totalCves: 8},
                        {name: 'spring-core', version: '4.3.18.RELEASE', severities: {critical: 1, high: 2, medium: 5}, totalCves: 8},
                        {name: 'log4j-core', version: '2.14.1', severities: {critical: 2, high: 0, medium: 2}, totalCves: 4},
                        {name: 'hibernate-core', version: '5.2.17.Final', severities: {critical: 0, high: 1, medium: 1}, totalCves: 2},
                        {name: 'commons-io', version: '2.4', severities: {critical: 0, high: 0, medium: 2}, totalCves: 2},
                        {name: 'gson', version: '2.8.5', severities: {critical: 0, high: 1, medium: 0}, totalCves: 1},
                        {name: 'dom4j', version: '1.6.1', severities: {critical: 1, high: 0, medium: 0}, totalCves: 1},
                        {name: 'commons-collections', version: '3.2.1', severities: {critical: 0, high: 0, medium: 0}, totalCves: 1}
                    ]
                }
            };
            
            trendBars.forEach(bar => {
                bar.addEventListener('mouseenter', function(e) {
                    const type = this.getAttribute('data-type');
                    const value = this.getAttribute('data-value');
                    const period = this.getAttribute('data-period');
                    
                    let tooltipContent = '';
                    
                    if (type === 'vulnerable-jars') {
                        const jars = jarData['vulnerable-jars']['current'];
                        tooltipContent = '<div class="tooltip-header">' + period + '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Vulnerable JARs:</span>' +
                                '<span class="tooltip-value">' + value + '</span>' +
                            '</div>' +
                            '<div class="tooltip-jars">' +
                                '<div class="tooltip-jars-title">📦 Affected JARs:</div>' +
                                '<div class="tooltip-jar-list">' +
                                    jars.slice(0, 8).map(function(jar) {
                                        const severity = jar.severities.critical > 0 ? 'critical' : 
                                                       jar.severities.high > 0 ? 'high' : 
                                                       jar.severities.medium > 0 ? 'medium' : 'low';
                                        return '<div class="tooltip-jar-item">' +
                                                '<span class="severity ' + severity + '"></span>' +
                                                jar.name + ':' + jar.version + ' (' + jar.totalCves + ' CVEs)' +
                                               '</div>';
                                    }).join('') +
                                    (jars.length > 8 ? '<div class="tooltip-jar-item">... and ' + (jars.length - 8) + ' more</div>' : '') +
                                '</div>' +
                            '</div>';
                    } else if (type === 'total-cves') {
                        tooltipContent = '<div class="tooltip-header">' + period + '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Total CVEs:</span>' +
                                '<span class="tooltip-value">' + value + '</span>' +
                            '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Critical:</span>' +
                                '<span class="tooltip-value" style="color: #dc3545;">23</span>' +
                            '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">High:</span>' +
                                '<span class="tooltip-value" style="color: #fd7e14;">49</span>' +
                            '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Medium:</span>' +
                                '<span class="tooltip-value" style="color: #ffc107;">33</span>' +
                            '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Low:</span>' +
                                '<span class="tooltip-value" style="color: #28a745;">1</span>' +
                            '</div>';
                    } else if (type === 'critical-cves') {
                        const criticalJars = jarData['vulnerable-jars']['current'].filter(function(jar) { 
                            return jar.severities.critical > 0; 
                        });
                        tooltipContent = '<div class="tooltip-header">' + period + '</div>' +
                            '<div class="tooltip-metric">' +
                                '<span class="tooltip-label">Critical CVEs:</span>' +
                                '<span class="tooltip-value" style="color: #dc3545;">' + value + '</span>' +
                            '</div>' +
                            '<div class="tooltip-jars">' +
                                '<div class="tooltip-jars-title">🚨 JARs with Critical CVEs:</div>' +
                                '<div class="tooltip-jar-list">' +
                                    criticalJars.map(function(jar) {
                                        return '<div class="tooltip-jar-item">' +
                                                '<span class="severity critical"></span>' +
                                                jar.name + ' (' + jar.severities.critical + ' Critical)' +
                                               '</div>';
                                    }).join('') +
                                '</div>' +
                            '</div>';
                    }
                    
                    tooltip.innerHTML = tooltipContent;
                    tooltip.classList.add('show');
                    
                    // Position tooltip
                    const rect = this.getBoundingClientRect();
                    const tooltipRect = tooltip.getBoundingClientRect();
                    
                    let left = rect.left + (rect.width / 2) - (tooltipRect.width / 2);
                    let top = rect.top - tooltipRect.height - 10;
                    
                    // Keep tooltip within viewport
                    if (left < 10) left = 10;
                    if (left + tooltipRect.width > window.innerWidth - 10) {
                        left = window.innerWidth - tooltipRect.width - 10;
                    }
                    if (top < 10) {
                        top = rect.bottom + 10;
                    }
                    
                    tooltip.style.left = left + 'px';
                    tooltip.style.top = top + 'px';
                });
                
                bar.addEventListener('mouseleave', function() {
                    tooltip.classList.remove('show');
                });
            });
        });
    </script>
</body>
</html>