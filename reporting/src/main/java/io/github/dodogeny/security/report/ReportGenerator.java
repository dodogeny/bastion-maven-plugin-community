package io.github.dodogeny.security.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import io.github.dodogeny.security.database.VulnerabilityDatabase;
import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xhtmlrenderer.pdf.ITextRenderer;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class ReportGenerator {
    
    private static final Logger logger = LoggerFactory.getLogger(ReportGenerator.class);
    
    private final Configuration freemarkerConfig;
    private final ObjectMapper objectMapper;
    
    public ReportGenerator() {
        this.freemarkerConfig = new Configuration(Configuration.VERSION_2_3_31);
        this.freemarkerConfig.setDefaultEncoding("UTF-8");
        this.freemarkerConfig.setClassLoaderForTemplateLoading(getClass().getClassLoader(), "/templates");
        
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }
    
    public void generateTrendReport(ScanResult scanResult, String outputPath) throws IOException, TemplateException {
        generateTrendReport(scanResult, outputPath, null);
    }
    
    public void generateTrendReport(ScanResult scanResult, String outputPath, VulnerabilityDatabase database) throws IOException, TemplateException {
        logger.info("Generating trend analysis report for project: {}", scanResult.getProjectName());
        
        Template template = freemarkerConfig.getTemplate("trend-report.ftl");
        
        Map<String, Object> model = createTemplateModel(scanResult);
        
        // Add trend data from database if available
        if (database != null) {
            try {
                // Add trend-specific data to the model
                model.put("hasTrendData", true);
                model.put("database", database);
                
                // Fetch trend data asynchronously if needed
                if (scanResult.getProjectGroupId() != null && scanResult.getProjectArtifactId() != null) {
                    try {
                        List<VulnerabilityDatabase.TrendData> trendData = database.getCveTrendsAsync(
                            scanResult.getProjectGroupId(),
                            scanResult.getProjectArtifactId(),
                            12
                        ).get();
                        model.put("trendData", trendData);
                        
                        // Add multi-module data if available
                        if (scanResult.isMultiModule() && scanResult.getRootGroupId() != null) {
                            try {
                                List<ScanResult.ScanSummary> multiModuleHistory = database.getMultiModuleScanHistory(
                                    scanResult.getRootGroupId(),
                                    12
                                );
                                model.put("multiModuleHistory", multiModuleHistory);
                            } catch (Exception multiModuleEx) {
                                logger.warn("Failed to fetch multi-module scan history: {}", multiModuleEx.getMessage());
                                model.put("multiModuleHistory", java.util.Collections.emptyList());
                            }
                        }
                        
                    } catch (java.util.concurrent.ExecutionException e) {
                        logger.error("Failed to fetch trend data asynchronously: {}", e.getCause().getMessage());
                        throw new RuntimeException("Database connection failed", e.getCause());
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        logger.error("Trend data fetch was interrupted: {}", e.getMessage());
                        throw new RuntimeException("Trend data fetch was interrupted", e);
                    }
                }
            } catch (RuntimeException e) {
                // Re-throw RuntimeExceptions (like database connection failures) to propagate them to the caller
                throw e;
            } catch (Exception e) {
                logger.warn("Failed to fetch trend data from database: {}", e.getMessage());
                model.put("hasTrendData", false);
            }
        } else {
            model.put("hasTrendData", false);
        }
        
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
            template.process(model, writer);
        }
    }

    public void generateReport(ScanResult scanResult, ReportFormat format, String outputPath) {
        try {
            logger.info("Generating {} report for project: {}", format, scanResult.getProjectName());
            
            switch (format) {
                case HTML:
                    generateHtmlReport(scanResult, outputPath);
                    break;
                case JSON:
                    generateJsonReport(scanResult, outputPath);
                    break;
                case CSV:
                    generateCsvReport(scanResult, outputPath);
                    break;
                case SARIF:
                    generateSarifReport(scanResult, outputPath);
                    break;
                case PDF:
                    generatePdfReport(scanResult, outputPath);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported report format: " + format);
            }
            
            logger.info("Report generated successfully: {}", outputPath);
            
        } catch (Exception e) {
            logger.error("Failed to generate {} report", format, e);
            throw new RuntimeException("Report generation failed", e);
        }
    }
    
    private void generateHtmlReport(ScanResult scanResult, String outputPath) throws IOException, TemplateException {
        Template template = freemarkerConfig.getTemplate("security-report.ftl");
        
        Map<String, Object> model = createTemplateModel(scanResult);
        
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
            template.process(model, writer);
        }
    }
    
    private void generateJsonReport(ScanResult scanResult, String outputPath) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("sechive", createSecHiveMetadata());
        report.put("scan", createScanMetadata(scanResult));
        report.put("summary", createSummary(scanResult));
        report.put("dependencies", scanResult.getDependencies());
        
        // Add vulnerabilities with descriptions to JSON report
        List<Vulnerability> vulnerabilities = scanResult.getVulnerabilities();
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            List<Map<String, Object>> vulnDetails = new ArrayList<>();
            for (Vulnerability vuln : vulnerabilities) {
                Map<String, Object> vulnMap = new LinkedHashMap<>();
                vulnMap.put("cveId", vuln.getCveId() != null ? vuln.getCveId() : "N/A");
                vulnMap.put("description", vuln.getDescription() != null ? vuln.getDescription() : "No description available");
                vulnMap.put("severity", vuln.getSeverity() != null ? vuln.getSeverity() : "UNKNOWN");
                vulnMap.put("cvssV3Score", vuln.getCvssV3Score());
                vulnMap.put("affectedComponent", vuln.getAffectedComponent() != null ? vuln.getAffectedComponent() : "N/A");
                vulnMap.put("source", vuln.getSource() != null ? vuln.getSource() : "Unknown");
                vulnMap.put("referenceUrl", vuln.getReferenceUrl() != null ? vuln.getReferenceUrl() : "");
                vulnMap.put("references", vuln.getReferences() != null ? vuln.getReferences() : java.util.Collections.emptyList());
                vulnMap.put("detectionMethod", vuln.getDetectionMethod() != null ? vuln.getDetectionMethod() : "N/A");
                vulnDetails.add(vulnMap);
            }
            report.put("vulnerabilities", vulnDetails);
        } else {
            // Even if no vulnerabilities, include empty array for consistency
            report.put("vulnerabilities", new ArrayList<>());
        }
        
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
            objectMapper.writeValue(writer, report);
        }
    }
    
    private void generateCsvReport(ScanResult scanResult, String outputPath) throws IOException {
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8))) {
            // Enhanced CSV with vulnerability details
            writer.println("CVE ID,Severity,CVSS Score,Affected Component,Description,Official CVE Link,Additional References,Source,Detection Method");
            
            // Get vulnerabilities from scan result
            List<Vulnerability> vulnerabilities = scanResult.getVulnerabilities();
            if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
                for (Vulnerability vuln : vulnerabilities) {
                    String cveId = vuln.getCveId() != null ? vuln.getCveId() : "N/A";
                    String severity = vuln.getSeverity() != null ? vuln.getSeverity() : "UNKNOWN";
                    Double cvssScore = vuln.getCvssV3Score();
                    String affectedComponent = vuln.getAffectedComponent() != null ? vuln.getAffectedComponent() : "N/A";
                    String description = vuln.getDescription() != null ? vuln.getDescription() : "No description available";
                    String referenceUrl = vuln.getReferenceUrl() != null ? vuln.getReferenceUrl() : "";
                    List<String> references = vuln.getReferences() != null ? vuln.getReferences() : java.util.Collections.emptyList();
                    String source = vuln.getSource() != null ? vuln.getSource() : "Unknown";
                    String detectionMethod = vuln.getDetectionMethod() != null ? vuln.getDetectionMethod() : "N/A";
                        
                        // Find official CVE link
                        String officialCveLink = "";
                        String additionalRefs = "";
                        if (references != null && !references.isEmpty()) {
                            java.util.List<String> officialLinks = new java.util.ArrayList<>();
                            java.util.List<String> otherLinks = new java.util.ArrayList<>();
                            
                            for (String ref : references) {
                                if (ref.contains("cve.mitre.org") || ref.contains("nvd.nist.gov")) {
                                    officialLinks.add(ref);
                                } else {
                                    otherLinks.add(ref);
                                }
                            }
                            
                            officialCveLink = String.join("; ", officialLinks);
                            additionalRefs = String.join("; ", otherLinks);
                        } else if (!referenceUrl.isEmpty()) {
                            if (referenceUrl.contains("cve.mitre.org") || referenceUrl.contains("nvd.nist.gov")) {
                                officialCveLink = referenceUrl;
                            } else {
                                additionalRefs = referenceUrl;
                            }
                        }
                        
                        writer.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                            escapeCsv(cveId),
                            escapeCsv(severity),
                            cvssScore != null ? cvssScore.toString() : "N/A",
                            escapeCsv(affectedComponent),
                            escapeCsv(description),
                            escapeCsv(officialCveLink),
                            escapeCsv(additionalRefs),
                            escapeCsv(source),
                            escapeCsv(detectionMethod)
                        );
                }
            } else {
                // Fallback to dependency-based CSV if no vulnerabilities are available
                writer.println("Dependency,Group ID,Artifact ID,Version,Scope,Vulnerability Count");
                
                if (scanResult.getDependencies() != null) {
                    for (ScanResult.DependencyResult dep : scanResult.getDependencies()) {
                        writer.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d%n",
                            escapeCsv(dep.getGroupId() + ":" + dep.getArtifactId()),
                            escapeCsv(dep.getGroupId()),
                            escapeCsv(dep.getArtifactId()),
                            escapeCsv(dep.getVersion()),
                            escapeCsv(dep.getScope()),
                            dep.getVulnerabilityIds() != null ? dep.getVulnerabilityIds().size() : 0
                        );
                    }
                }
            }
        }
    }
    
    @SuppressWarnings("unchecked")
    private <T> T getFieldValue(Object obj, String fieldName, Class<T> expectedType, T defaultValue) {
        try {
            String getterName = "get" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
            java.lang.reflect.Method getter = obj.getClass().getMethod(getterName);
            Object value = getter.invoke(obj);
            if (value != null && expectedType.isAssignableFrom(value.getClass())) {
                return (T) value;
            }
        } catch (Exception e) {
            // Ignore reflection errors
        }
        return defaultValue;
    }
    
    private void generateSarifReport(ScanResult scanResult, String outputPath) throws IOException {
        Map<String, Object> sarif = createSarifReport(scanResult);
        
        try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
            objectMapper.writeValue(writer, sarif);
        }
    }
    
    private void generatePdfReport(ScanResult scanResult, String outputPath) throws IOException, TemplateException {
        logger.info("Generating PDF report: {}", outputPath);

        try {
            // First generate HTML content
            String htmlContent = generateHtmlContent(scanResult);

            // Convert HTML to PDF using Flying Saucer (iText)
            try (FileOutputStream outputStream = new FileOutputStream(outputPath)) {
                ITextRenderer renderer = new ITextRenderer();
                renderer.setDocumentFromString(htmlContent);
                renderer.layout();
                renderer.createPDF(outputStream);
            }

            logger.info("PDF report generated successfully: {}", outputPath);

        } catch (Exception e) {
            logger.error("Failed to generate PDF report", e);
            throw new IOException("PDF report generation failed: " + e.getMessage(), e);
        }
    }
    
    private String generateHtmlContent(ScanResult scanResult) throws IOException, TemplateException {
        Template template = freemarkerConfig.getTemplate("security-report.ftl");
        Map<String, Object> model = createTemplateModel(scanResult);
        
        try (StringWriter writer = new StringWriter()) {
            template.process(model, writer);
            return writer.toString();
        }
    }
    
    private Map<String, Object> createTemplateModel(ScanResult scanResult) {
        Map<String, Object> model = new HashMap<>();
        model.put("scanResult", scanResult);
        model.put("sechiveVersion", "2.0.0");
        model.put("generatedTime", java.time.LocalDateTime.now());
        model.put("summary", createSummary(scanResult));
        model.put("dependencyBreakdown", createDependencyBreakdown(scanResult));
        model.put("topVulnerableDependencies", getTopVulnerableDependencies(scanResult, 10));
        model.put("System", System.class);
        model.put("userHome", System.getProperty("user.home"));
        
        return model;
    }
    
    private Map<String, Object> createSecHiveMetadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("version", "2.0.0");
        metadata.put("name", "SecHive Maven Plugin");
        metadata.put("description", "Open source vulnerability scanner for Maven projects");
        metadata.put("website", "https://github.com/dodogeny/sechive-maven-plugin");

        return metadata;
    }
    
    private Map<String, Object> createScanMetadata(ScanResult scanResult) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("projectName", scanResult.getProjectName());
        metadata.put("startTime", scanResult.getStartTime());
        metadata.put("endTime", scanResult.getEndTime());
        metadata.put("scanType", scanResult.getScanType());
        
        return metadata;
    }
    
    private Map<String, Object> createSummary(ScanResult scanResult) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalVulnerabilities", scanResult.getTotalVulnerabilities());
        summary.put("totalDependencies", scanResult.getTotalDependencies());
        summary.put("vulnerableDependencies", scanResult.getVulnerableDependencies());
        summary.put("riskScore", calculateDependencyRiskScore(scanResult));
        
        // Add severity counts for template
        summary.put("criticalCount", scanResult.getCriticalVulnerabilities());
        summary.put("highCount", scanResult.getHighVulnerabilities());
        summary.put("mediumCount", scanResult.getMediumVulnerabilities());
        summary.put("lowCount", scanResult.getLowVulnerabilities());
        
        // Add detailed affected JAR information even on first run
        summary.put("affectedJars", getAffectedJarsDetails(scanResult));
        summary.put("hasVulnerabilities", scanResult.getTotalVulnerabilities() > 0);
        summary.put("hasFirstTimeData", true); // Always show stats even without trend data
        
        return summary;
    }
    
    private Map<String, Integer> createDependencyBreakdown(ScanResult scanResult) {
        Map<String, Integer> breakdown = new LinkedHashMap<>();
        int clean = 0, vulnerable = 0;
        
        if (scanResult.getDependencies() != null) {
            for (ScanResult.DependencyResult dep : scanResult.getDependencies()) {
                if (dep.getVulnerabilityIds() != null && !dep.getVulnerabilityIds().isEmpty()) {
                    vulnerable++;
                } else {
                    clean++;
                }
            }
        }
        
        breakdown.put("CLEAN", clean);
        breakdown.put("VULNERABLE", vulnerable);
        breakdown.put("TOTAL", clean + vulnerable);
        
        return breakdown;
    }
    
    private List<Map<String, Object>> getAffectedJarsDetails(ScanResult scanResult) {
        List<Map<String, Object>> affectedJars = new ArrayList<>();
        
        if (scanResult.getDependencies() != null) {
            for (ScanResult.DependencyResult dep : scanResult.getDependencies()) {
                if (dep.getVulnerabilityIds() != null && !dep.getVulnerabilityIds().isEmpty()) {
                    Map<String, Object> jarInfo = new LinkedHashMap<>();
                    jarInfo.put("coordinates", dep.getCoordinates());
                    jarInfo.put("groupId", dep.getGroupId());
                    jarInfo.put("artifactId", dep.getArtifactId());
                    jarInfo.put("version", dep.getVersion());
                    jarInfo.put("filePath", dep.getFilePath());
                    jarInfo.put("vulnerabilityCount", dep.getVulnerabilityIds().size());
                    jarInfo.put("vulnerabilityIds", new ArrayList<>(dep.getVulnerabilityIds()));
                    jarInfo.put("isDirect", dep.isDirect());
                    jarInfo.put("scope", dep.getScope());
                    
                    // Add severity distribution for this JAR if available
                    Map<String, Integer> severityBreakdown = calculateJarSeverityBreakdown(dep, scanResult);
                    jarInfo.put("severityBreakdown", severityBreakdown);
                    jarInfo.put("maxSeverity", getMaxSeverityForJar(dep, scanResult));
                    
                    affectedJars.add(jarInfo);
                }
            }
            
            // Sort by vulnerability count (descending) then by severity
            affectedJars.sort((a, b) -> {
                int countCompare = Integer.compare(
                    (Integer) b.get("vulnerabilityCount"), 
                    (Integer) a.get("vulnerabilityCount")
                );
                if (countCompare != 0) return countCompare;
                
                // If same count, sort by max severity
                return getSeverityPriority((String) b.get("maxSeverity")) - 
                       getSeverityPriority((String) a.get("maxSeverity"));
            });
        }
        
        return affectedJars;
    }
    
    private Map<String, Integer> calculateJarSeverityBreakdown(ScanResult.DependencyResult dep, ScanResult scanResult) {
        Map<String, Integer> breakdown = new LinkedHashMap<>();
        breakdown.put("CRITICAL", 0);
        breakdown.put("HIGH", 0);
        breakdown.put("MEDIUM", 0);
        breakdown.put("LOW", 0);
        breakdown.put("UNKNOWN", 0);
        
        // This would require vulnerability details - for now return placeholder
        // In a real implementation, you'd need to track severity per vulnerability
        return breakdown;
    }
    
    private String getMaxSeverityForJar(ScanResult.DependencyResult dep, ScanResult scanResult) {
        // This would require vulnerability details - for now return placeholder
        // In a real implementation, you'd determine the highest severity for this JAR
        if (dep.getVulnerabilityIds() != null && dep.getVulnerabilityIds().size() > 0) {
            return "HIGH"; // Placeholder - would be calculated from actual vulnerability data
        }
        return "UNKNOWN";
    }
    
    private int getSeverityPriority(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }
    
    private List<ScanResult.DependencyResult> getTopVulnerableDependencies(ScanResult scanResult, int limit) {
        if (scanResult.getDependencies() == null) {
            return new ArrayList<>();
        }
        
        return scanResult.getDependencies().stream()
                .filter(dep -> dep.getVulnerabilityIds() != null && !dep.getVulnerabilityIds().isEmpty())
                .sorted((d1, d2) -> Integer.compare(d2.getVulnerabilityIds().size(), d1.getVulnerabilityIds().size()))
                .limit(limit)
                .collect(Collectors.toList());
    }
    
    private double calculateDependencyRiskScore(ScanResult scanResult) {
        if (scanResult.getDependencies() == null || scanResult.getTotalDependencies() == 0) {
            return 0.0;
        }
        
        double vulnerableRatio = (double) scanResult.getVulnerableDependencies() / scanResult.getTotalDependencies();
        double vulnerabilityDensity = (double) scanResult.getTotalVulnerabilities() / scanResult.getTotalDependencies();
        
        double riskScore = (vulnerableRatio * 50.0) + (vulnerabilityDensity * 50.0);
        return Math.round(riskScore * 10.0) / 10.0;
    }
    
    private Map<String, Object> createSarifReport(ScanResult scanResult) {
        Map<String, Object> sarif = new LinkedHashMap<>();
        sarif.put("version", "2.1.0");
        sarif.put("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json");
        
        List<Map<String, Object>> runs = new ArrayList<>();
        Map<String, Object> run = new LinkedHashMap<>();
        
        Map<String, Object> tool = new LinkedHashMap<>();
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", "SecHive Maven Plugin");
        driver.put("version", "1.0.0");
        tool.put("driver", driver);
        run.put("tool", tool);
        
        List<Map<String, Object>> results = new ArrayList<>();
        if (scanResult.getDependencies() != null) {
            for (ScanResult.DependencyResult dep : scanResult.getDependencies()) {
                if (dep.getVulnerabilityIds() != null && !dep.getVulnerabilityIds().isEmpty()) {
                    for (String vulnId : dep.getVulnerabilityIds()) {
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("ruleId", vulnId);
                        result.put("level", "error"); // Default to error for vulnerabilities
                        
                        Map<String, Object> message = new LinkedHashMap<>();
                        message.put("text", "Vulnerability found in dependency: " + dep.getGroupId() + ":" + dep.getArtifactId() + ":" + dep.getVersion());
                        result.put("message", message);
                        
                        results.add(result);
                    }
                }
            }
        }
        run.put("results", results);
        runs.add(run);
        sarif.put("runs", runs);
        
        return sarif;
    }
    
    
    private String escapeCsv(String value) {
        if (value == null) return "";
        return value.replace("\"", "\"\"");
    }
    
    private String truncate(String text, int maxLength) {
        if (text == null) return "";
        return text.length() > maxLength ? text.substring(0, maxLength) + "..." : text;
    }
    
    public enum ReportFormat {
        HTML, JSON, CSV, SARIF, PDF
    }
}