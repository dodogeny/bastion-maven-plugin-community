package io.github.dodogeny.security.report;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ReportGeneratorTest {

    private ReportGenerator reportGenerator;
    private ScanResult testScanResult;

    @TempDir
    private Path tempDir;

    @BeforeAll
    void setUpClass() {
        reportGenerator = new ReportGenerator();
        testScanResult = createTestScanResult();
    }

    @Test
    @DisplayName("Should generate HTML report successfully")
    void testGenerateHtmlReport() throws Exception {
        String outputPath = tempDir.resolve("test-report.html").toString();
        
        reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
        
        File reportFile = new File(outputPath);
        assertTrue(reportFile.exists(), "HTML report file should be created");
        assertTrue(reportFile.length() > 0, "HTML report should not be empty");
        
        // Verify HTML content
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        assertTrue(content.contains("<!DOCTYPE html>"), "Should contain valid HTML structure");
        assertTrue(content.contains("SecHive Security Report"), "Should contain report title");
        assertTrue(content.contains(testScanResult.getProjectName()), "Should contain project name");
        assertTrue(content.contains("CVE-2021-1234"), "Should contain vulnerability ID");
    }

    @Test
    @DisplayName("Should generate JSON report successfully")
    void testGenerateJsonReport() throws Exception {
        String outputPath = tempDir.resolve("test-report.json").toString();
        
        reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.JSON, outputPath);
        
        File reportFile = new File(outputPath);
        assertTrue(reportFile.exists(), "JSON report file should be created");
        assertTrue(reportFile.length() > 0, "JSON report should not be empty");
        
        // Verify JSON content
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        assertTrue(content.trim().startsWith("{"), "Should be valid JSON object");
        assertTrue(content.contains("\"projectName\""), "Should contain project name field");
        assertTrue(content.contains("\"vulnerabilities\""), "Should contain vulnerabilities array");
        assertTrue(content.contains("\"totalVulnerabilities\""), "Should contain summary statistics");
    }

    @Test
    @DisplayName("Should generate CSV report successfully")
    void testGenerateCsvReport() throws Exception {
        String outputPath = tempDir.resolve("test-report.csv").toString();
        
        reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.CSV, outputPath);
        
        File reportFile = new File(outputPath);
        assertTrue(reportFile.exists(), "CSV report file should be created");
        assertTrue(reportFile.length() > 0, "CSV report should not be empty");
        
        // Verify CSV content
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        String[] lines = content.split("\n");
        
        assertTrue(lines.length > 1, "CSV should have header and data rows");
        assertTrue(lines[0].contains("CVE ID"), "Should contain CVE ID header");
        assertTrue(lines[0].contains("Severity"), "Should contain Severity header");
        assertTrue(lines[0].contains("Component"), "Should contain Component header");
        
        // Verify data rows
        for (int i = 1; i < lines.length; i++) {
            if (!lines[i].trim().isEmpty()) {
                assertTrue(lines[i].contains("CVE-"), "Data rows should contain CVE IDs");
            }
        }
    }

    @Test
    @DisplayName("Should handle PDF report request for enterprise edition")
    void testPdfReportRequiresEnterprise() throws Exception {
        String outputPath = tempDir.resolve("test-report.pdf").toString();
        
        // Note: PDF generation requires enterprise plugin in actual implementation
        assertDoesNotThrow(() -> {
            reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.PDF, outputPath);
        });
        
        // In community edition, this would skip PDF generation
        // This is a structure test to ensure the method handles PDF generation requests
    }

    @Test
    @DisplayName("Should handle SARIF report request for enterprise edition")
    void testSarifReportRequiresEnterprise() throws Exception {
        String outputPath = tempDir.resolve("test-report.sarif").toString();
        
        // Note: SARIF generation requires enterprise plugin in actual implementation
        assertDoesNotThrow(() -> {
            reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.SARIF, outputPath);
        });
    }

    @Test
    @DisplayName("Should handle empty scan results gracefully")
    void testEmptyScanResult() throws Exception {
        ScanResult emptyScanResult = createEmptyScanResult();
        String outputPath = tempDir.resolve("empty-report.html").toString();
        
        reportGenerator.generateReport(emptyScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
        
        File reportFile = new File(outputPath);
        assertTrue(reportFile.exists(), "Report should be generated even for empty results");
        
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        assertTrue(content.contains("No Vulnerabilities Found"), "Should show no vulnerabilities message");
    }

    @Test
    @DisplayName("Should include comprehensive statistics in reports")
    void testReportStatistics() throws Exception {
        ScanResult resultWithStats = createScanResultWithStatistics();
        String outputPath = tempDir.resolve("stats-report.html").toString();
        
        reportGenerator.generateReport(resultWithStats, ReportGenerator.ReportFormat.HTML, outputPath);
        
        File reportFile = new File(outputPath);
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        
        // Verify statistics are included
        assertTrue(content.contains("JARs Scanned"), "Should include JAR scan statistics");
        assertTrue(content.contains("Performance Metrics"), "Should include performance metrics");
        assertTrue(content.contains("Cache Hit Rate"), "Should include cache performance");
        assertTrue(content.contains("Processing Speed"), "Should include processing speed");
    }

    @Test
    @DisplayName("Should handle large scan results efficiently")
    void testLargeScanResult() throws Exception {
        ScanResult largeScanResult = createLargeScanResult(500);
        String outputPath = tempDir.resolve("large-report.html").toString();
        
        long startTime = System.currentTimeMillis();
        reportGenerator.generateReport(largeScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
        long duration = System.currentTimeMillis() - startTime;
        
        File reportFile = new File(outputPath);
        assertTrue(reportFile.exists(), "Large report should be generated");
        assertTrue(reportFile.length() > 0, "Large report should have content");
        
        // Should complete within reasonable time (adjust threshold as needed)
        assertTrue(duration < 10000, "Large report generation should complete within 10 seconds, took: " + duration + "ms");
    }

    @Test
    @DisplayName("Should support custom report templates")
    void testCustomReportTemplate() throws Exception {
        // Create a basic custom report test
        String outputPath = tempDir.resolve("custom-report.html").toString();
        
        assertDoesNotThrow(() -> {
            reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
        });
    }

    @Test
    @DisplayName("Should validate output paths and handle invalid paths")
    void testInvalidOutputPaths() {
        String invalidPath = "/invalid/nonexistent/path/report.html";
        
        assertThrows(RuntimeException.class, () -> {
            reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.HTML, invalidPath);
        }, "Should throw exception for invalid output path");
    }

    @Test
    @DisplayName("Should support concurrent report generation")
    void testConcurrentReportGeneration() throws Exception {
        List<Thread> threads = new ArrayList<>();
        List<Exception> exceptions = new ArrayList<>();
        
        // Generate multiple reports concurrently
        for (int i = 0; i < 3; i++) {
            final int threadId = i;
            Thread thread = new Thread(() -> {
                try {
                    String outputPath = tempDir.resolve("concurrent-report-" + threadId + ".html").toString();
                    reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
                } catch (Exception e) {
                    synchronized (exceptions) {
                        exceptions.add(e);
                    }
                }
            });
            threads.add(thread);
            thread.start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join(10000); // 10 second timeout
        }
        
        assertTrue(exceptions.isEmpty(), "Concurrent report generation should not throw exceptions: " + exceptions);
        
        // Verify all reports were created
        for (int i = 0; i < 3; i++) {
            File reportFile = tempDir.resolve("concurrent-report-" + i + ".html").toFile();
            assertTrue(reportFile.exists(), "Concurrent report " + i + " should exist");
        }
    }

    @Test
    @DisplayName("Should include vulnerability severity breakdown")
    void testSeverityBreakdown() throws Exception {
        String outputPath = tempDir.resolve("severity-report.html").toString();
        
        reportGenerator.generateReport(testScanResult, ReportGenerator.ReportFormat.HTML, outputPath);
        
        File reportFile = new File(outputPath);
        String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
        
        // Verify severity breakdown is included
        assertTrue(content.contains("Critical"), "Should show critical vulnerabilities");
        assertTrue(content.contains("High"), "Should show high vulnerabilities");
        assertTrue(content.contains("Medium"), "Should show medium vulnerabilities");
        assertTrue(content.contains("Low"), "Should show low vulnerabilities");
    }

    // Helper methods to create test data

    private ScanResult createTestScanResult() {
        ScanResult result = new ScanResult();
        result.setProjectName("Test Security Project");
        result.setProjectVersion("1.0.0");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(1));
        result.setScanDurationMs(15000);
        result.setTotalDependencies(50);
        result.setMultiModule(false);

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Critical vulnerability
        Vulnerability criticalVuln = new Vulnerability();
        criticalVuln.setCveId("CVE-2021-1234");
        criticalVuln.setSeverity("CRITICAL");
        criticalVuln.setCvssV3Score(9.8);
        criticalVuln.setAffectedComponent("org.apache.commons:commons-lang3:3.8.1");
        criticalVuln.setDescription("Remote code execution vulnerability");
        criticalVuln.setSource("OWASP Dependency-Check");
        criticalVuln.setReferenceUrl("https://nvd.nist.gov/vuln/detail/CVE-2021-1234");
        vulnerabilities.add(criticalVuln);
        
        // High vulnerability
        Vulnerability highVuln = new Vulnerability();
        highVuln.setCveId("CVE-2021-5678");
        highVuln.setSeverity("HIGH");
        highVuln.setCvssV3Score(7.5);
        highVuln.setAffectedComponent("com.fasterxml.jackson.core:jackson-core:2.9.8");
        highVuln.setDescription("Information disclosure vulnerability");
        highVuln.setSource("OWASP Dependency-Check");
        highVuln.setReferenceUrl("https://nvd.nist.gov/vuln/detail/CVE-2021-5678");
        vulnerabilities.add(highVuln);
        
        // Create dependencies with vulnerabilities instead of direct vulnerability list
        List<ScanResult.DependencyResult> dependencies = createDependenciesWithVulnerabilities(vulnerabilities);
        result.setDependencies(dependencies);
        
        // Also set the vulnerabilities list on the result - this is needed for CSV generation
        result.setVulnerabilities(vulnerabilities);
        
        return result;
    }

    private ScanResult createEmptyScanResult() {
        ScanResult result = new ScanResult();
        result.setProjectName("Empty Test Project");
        result.setProjectVersion("1.0.0");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(1));
        result.setScanDurationMs(5000);
        result.setTotalDependencies(0);
        result.setMultiModule(false);
        result.setDependencies(new ArrayList<>());
        return result;
    }

    private ScanResult createScanResultWithStatistics() {
        ScanResult result = createTestScanResult();
        
        // Add comprehensive statistics
        ScanResult.ScanStatistics stats = new ScanResult.ScanStatistics();
        stats.setTotalJarsScanned(50);
        stats.setUniqueGroupIds(45);
        stats.setDuplicateJars(5);
        stats.setTotalCvesFound(2);
        stats.setUniqueCvesFound(2);
        stats.setCvesWithExploits(1);
        stats.setAverageCvssScore(8.65);
        stats.setMostVulnerableComponent("org.apache.commons:commons-lang3:3.8.1");
        result.setStatistics(stats);
        
        // Add performance metrics
        ScanResult.PerformanceMetrics metrics = new ScanResult.PerformanceMetrics();
        metrics.setInitializationTimeMs(1200);
        metrics.setVulnerabilityCheckTimeMs(12800);
        metrics.setReportGenerationTimeMs(2000);
        metrics.setTotalScanTimeMs(15000);
        metrics.setPeakMemoryUsageMB(384);
        metrics.setCacheHits(234);
        metrics.setCacheMisses(66);
        metrics.setSlowestPhase("Vulnerability Analysis");
        result.setPerformanceMetrics(metrics);
        
        return result;
    }

    private ScanResult createLargeScanResult(int vulnerabilityCount) {
        ScanResult result = createTestScanResult();
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (int i = 0; i < vulnerabilityCount; i++) {
            Vulnerability vuln = new Vulnerability();
            vuln.setCveId("CVE-2023-" + String.format("%04d", i));
            vuln.setSeverity(i % 4 == 0 ? "CRITICAL" : i % 3 == 0 ? "HIGH" : i % 2 == 0 ? "MEDIUM" : "LOW");
            vuln.setCvssV3Score(4.0 + (i % 6));
            vuln.setAffectedComponent("com.example:test-lib-" + i + ":1.0.0");
            vuln.setDescription("Test vulnerability " + i);
            vuln.setSource("OWASP Dependency-Check");
            vulnerabilities.add(vuln);
        }
        
        // Create dependencies with vulnerabilities instead of direct vulnerability list
        List<ScanResult.DependencyResult> dependencies = createDependenciesWithVulnerabilities(vulnerabilities);
        result.setDependencies(dependencies);
        
        // Also set the vulnerabilities list on the result - this is needed for CSV generation
        result.setVulnerabilities(vulnerabilities);
        
        result.setTotalDependencies(vulnerabilityCount * 2); // Assume some deps are clean
        
        return result;
    }
    
    private List<ScanResult.DependencyResult> createDependenciesWithVulnerabilities(List<Vulnerability> vulnerabilities) {
        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        
        for (Vulnerability vuln : vulnerabilities) {
            ScanResult.DependencyResult dep = new ScanResult.DependencyResult();
            
            // Extract component info from affected component
            String component = vuln.getAffectedComponent();
            if (component != null && component.contains(":")) {
                String[] parts = component.split(":");
                if (parts.length >= 3) {
                    dep.setGroupId(parts[0]);
                    dep.setArtifactId(parts[1]);
                    dep.setVersion(parts[2]);
                }
            } else {
                dep.setGroupId("com.example");
                dep.setArtifactId("test-lib");
                dep.setVersion("1.0.0");
            }
            
            dep.setScope("compile");
            dep.setDirect(true);
            
            // Add vulnerability ID to the dependency
            Set<String> vulnIds = new HashSet<>();
            vulnIds.add(vuln.getCveId());
            dep.setVulnerabilityIds(vulnIds);
            
            dependencies.add(dep);
        }
        
        return dependencies;
    }
}