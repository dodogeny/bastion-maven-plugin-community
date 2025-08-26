package io.github.dodogeny.security.report;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import io.github.dodogeny.security.database.VulnerabilityDatabase;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.*;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("Trend Analysis Report Tests")
@Ign
class TrendAnalysisReportTest {

    @Mock
    private VulnerabilityDatabase mockDatabase;
    
    private ReportGenerator reportGenerator;
    private ScanResult scanResult;
    
    @TempDir
    private Path tempDir;

    @BeforeEach
    void setUp() {
        reportGenerator = new ReportGenerator();
        scanResult = createTestScanResult();
    }

    @Nested
    @DisplayName("Trend Report Generation Tests")
    class TrendReportGenerationTest {

//        @Test
//        @DisplayName("Should generate trend report with historical data")
//        void testGenerateTrendReportWithHistoricalData() throws Exception {
//            // Mock trend data
//            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
//            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
//                .thenReturn(CompletableFuture.completedFuture(trendData));
//            when(mockDatabase.getMultiModuleScanHistory(anyString(), anyInt()))
//                .thenReturn(createMockScanHistory());
//
//            String outputPath = tempDir.resolve("trend-report.html").toString();
//
//            // Generate trend report
//            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
//
//            File reportFile = new File(outputPath);
//            assertTrue(reportFile.exists(), "Trend report file should be created");
//            assertTrue(reportFile.length() > 0, "Trend report should not be empty");
//
//            // Verify database interactions
//            verify(mockDatabase).getCveTrendsAsync(eq("com.example"), eq("test-project"), eq(12));
//        }

        @Test
        @DisplayName("Should generate trend report with bar chart visualization")
        void testTrendReportBarChartVisualization() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("bar-chart-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify bar chart elements are present
            assertTrue(content.contains("trend-bar"), "Should contain bar chart elements");
            assertTrue(content.contains("JARs and CVEs Over Time"), "Should contain trend section title");
            assertTrue(content.contains("data-type=\"vulnerable-jars\""), "Should contain vulnerable JARs data");
            assertTrue(content.contains("data-type=\"total-cves\""), "Should contain total CVEs data");
        }

        @Test
        @DisplayName("Should include interactive tooltips in trend report")
        void testTrendReportInteractiveTooltips() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("interactive-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify tooltip functionality
            assertTrue(content.contains("chart-tooltip"), "Should contain tooltip element");
            assertTrue(content.contains("addEventListener('mouseenter'"), "Should contain mouseenter event handlers");
            assertTrue(content.contains("Affected JARs:"), "Should contain JAR tooltip content");
            assertTrue(content.contains("tooltip-jar-list"), "Should contain JAR list in tooltips");
        }

        @Test
        @DisplayName("Should handle empty trend data gracefully")
        void testTrendReportWithEmptyData() throws Exception {
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(new ArrayList<>()));
            when(mockDatabase.getMultiModuleScanHistory(anyString(), anyInt()))
                .thenReturn(new ArrayList<>());

            String outputPath = tempDir.resolve("empty-trend-report.html").toString();
            
            assertDoesNotThrow(() -> {
                reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            });
            
            File reportFile = new File(outputPath);
            assertTrue(reportFile.exists(), "Trend report should be generated even with empty data");
            
            String content = readFileContent(reportFile);
            assertTrue(content.contains("No Historical Data Available"), "Should show no data message");
        }

        @Test
        @DisplayName("Should handle database errors during trend report generation")
        void testTrendReportWithDatabaseErrors() throws Exception {
            // Create a failed CompletableFuture using JDK 8 compatible approach
            CompletableFuture<List<VulnerabilityDatabase.TrendData>> failedFuture = new CompletableFuture<>();
            failedFuture.completeExceptionally(new RuntimeException("Database connection failed"));
            
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(failedFuture);

            String outputPath = tempDir.resolve("error-trend-report.html").toString();
            
            assertThrows(RuntimeException.class, () -> {
                reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            }, "Should throw exception when database fails");
        }
    }

    @Nested
    @DisplayName("Trend Data Processing Tests")
    class TrendDataProcessingTest {

        @Test
        @DisplayName("Should process trend data correctly for visualization")
        void testTrendDataProcessing() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("processed-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify trend data is processed and included
            assertTrue(content.contains("data-value=\"15\""), "Should contain vulnerability count data");
            assertTrue(content.contains("data-value=\"8\""), "Should contain critical vulnerability data");
            assertTrue(content.contains("data-period=\""), "Should contain time period data");
        }

        @Test
        @DisplayName("Should calculate severity breakdowns correctly")
        void testSeverityBreakdownCalculation() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("severity-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify severity data is included
            assertTrue(content.contains("Critical"), "Should include critical severity");
            assertTrue(content.contains("High"), "Should include high severity");
            assertTrue(content.contains("Medium"), "Should include medium severity");
            assertTrue(content.contains("Low"), "Should include low severity");
        }

        @Test
        @DisplayName("Should handle multi-module trend data correctly")
        void testMultiModuleTrendData() throws Exception {
            List<ScanResult.ScanSummary> multiModuleHistory = createMockMultiModuleScanHistory();
            when(mockDatabase.getMultiModuleScanHistory(anyString(), anyInt()))
                .thenReturn(multiModuleHistory);
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(createMockTrendData()));

            // Set up multi-module scan result
            scanResult.setMultiModule(true);
            scanResult.setRootGroupId("com.example");

            String outputPath = tempDir.resolve("multi-module-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify multi-module data is processed
            assertTrue(content.contains("Multi-Module Analysis"), "Should include multi-module section");
            verify(mockDatabase).getMultiModuleScanHistory(eq("com.example"), anyInt());
        }
    }

    @Nested
    @DisplayName("Trend Chart Styling Tests")
    class TrendChartStylingTest {

        @Test
        @DisplayName("Should include enhanced CSS styling for trend charts")
        void testTrendChartStyling() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("styled-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify enhanced styling is present
            assertTrue(content.contains(".trend-bar"), "Should contain bar chart CSS");
            assertTrue(content.contains("transition: all 0.3s ease"), "Should contain smooth transitions");
            assertTrue(content.contains("box-shadow"), "Should contain visual enhancements");
            assertTrue(content.contains("border-radius"), "Should contain rounded corners");
            assertTrue(content.contains("gradient"), "Should contain gradient effects");
        }

        @Test
        @DisplayName("Should include responsive design elements")
        void testResponsiveDesign() throws Exception {
            List<VulnerabilityDatabase.TrendData> trendData = createMockTrendData();
            when(mockDatabase.getCveTrendsAsync(anyString(), anyString(), anyInt()))
                .thenReturn(CompletableFuture.completedFuture(trendData));

            String outputPath = tempDir.resolve("responsive-trend-report.html").toString();
            
            reportGenerator.generateTrendReport(scanResult, outputPath, mockDatabase);
            
            File reportFile = new File(outputPath);
            String content = readFileContent(reportFile);
            
            // Verify responsive elements
            assertTrue(content.contains("@media"), "Should contain media queries");
            assertTrue(content.contains("max-width"), "Should contain responsive breakpoints");
        }
    }

    // Helper methods
    private ScanResult createTestScanResult() {
        ScanResult result = new ScanResult();
        result.setProjectName("Test Security Project");
        result.setProjectGroupId("com.example");
        result.setProjectArtifactId("test-project");
        result.setProjectVersion("1.0.0");
        result.setStartTime(LocalDateTime.now().minusMinutes(10));
        result.setEndTime(LocalDateTime.now());
        result.setScanDurationMs(60000);
        result.setTotalDependencies(25);
        
        // Add vulnerabilities
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        vulnerabilities.add(createVulnerability("CVE-2021-1001", "CRITICAL"));
        vulnerabilities.add(createVulnerability("CVE-2021-1002", "HIGH"));
        vulnerabilities.add(createVulnerability("CVE-2021-1003", "MEDIUM"));
        result.setVulnerabilities(vulnerabilities);
        
        // Add dependencies
        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        ScanResult.DependencyResult dep1 = createDependency("com.example", "vulnerable-lib", "1.0.0");
        dep1.getVulnerabilityIds().add("CVE-2021-1001");
        dep1.getVulnerabilityIds().add("CVE-2021-1002");
        dependencies.add(dep1);
        
        ScanResult.DependencyResult dep2 = createDependency("org.apache", "another-lib", "2.0.0");
        dep2.getVulnerabilityIds().add("CVE-2021-1003");
        dependencies.add(dep2);
        
        result.setDependencies(dependencies);
        
        return result;
    }

    private List<VulnerabilityDatabase.TrendData> createMockTrendData() {
        List<VulnerabilityDatabase.TrendData> trendData = new ArrayList<>();
        
        LocalDate baseDate = LocalDate.now().minusMonths(6);
        for (int i = 0; i < 6; i++) {
            VulnerabilityDatabase.TrendData data = new VulnerabilityDatabase.TrendData();
            data.setPeriod(baseDate.plusMonths(i));
            data.setTotalVulnerabilities(15 + (i * 3));
            data.setCriticalCount(2 + i);
            data.setHighCount(5 + (i * 2));
            data.setMediumCount(6 + i);
            data.setLowCount(2);
            data.setVulnerableJarCount(8 + i);
            trendData.add(data);
        }
        
        return trendData;
    }

    private List<ScanResult.ScanSummary> createMockScanHistory() {
        List<ScanResult.ScanSummary> history = new ArrayList<>();
        
        LocalDateTime baseTime = LocalDateTime.now().minusMonths(6);
        for (int i = 0; i < 6; i++) {
            ScanResult.ScanSummary summary = new ScanResult.ScanSummary();
            summary.setProjectName("Test Project");
            summary.setProjectVersion("1.0." + i);
            summary.setStartTime(baseTime.plusMonths(i));
            summary.setTotalVulnerabilities(10 + (i * 2));
            summary.setVulnerableDependencies(5 + i);
            history.add(summary);
        }
        
        return history;
    }

    private List<ScanResult.ScanSummary> createMockMultiModuleScanHistory() {
        List<ScanResult.ScanSummary> history = new ArrayList<>();
        
        // Module 1
        ScanResult.ScanSummary module1 = new ScanResult.ScanSummary();
        module1.setProjectName("Test Module 1");
        module1.setProjectArtifactId("module1");
        module1.setStartTime(LocalDateTime.now().minusDays(7));
        module1.setTotalVulnerabilities(8);
        module1.setVulnerableDependencies(3);
        history.add(module1);
        
        // Module 2
        ScanResult.ScanSummary module2 = new ScanResult.ScanSummary();
        module2.setProjectName("Test Module 2");
        module2.setProjectArtifactId("module2");
        module2.setStartTime(LocalDateTime.now().minusDays(7));
        module2.setTotalVulnerabilities(12);
        module2.setVulnerableDependencies(5);
        history.add(module2);
        
        return history;
    }

    private Vulnerability createVulnerability(String cveId, String severity) {
        Vulnerability vuln = new Vulnerability();
        vuln.setCveId(cveId);
        vuln.setId(cveId);
        vuln.setSeverity(severity);
        vuln.setDescription("Test vulnerability: " + cveId);
        vuln.setCvssV3Score(severity.equals("CRITICAL") ? 9.5 : 
                           severity.equals("HIGH") ? 7.5 : 
                           severity.equals("MEDIUM") ? 5.5 : 3.0);
        return vuln;
    }

    private ScanResult.DependencyResult createDependency(String groupId, String artifactId, String version) {
        ScanResult.DependencyResult dep = new ScanResult.DependencyResult();
        dep.setGroupId(groupId);
        dep.setArtifactId(artifactId);
        dep.setVersion(version);
        dep.setScope("compile");
        dep.setDirect(true);
        dep.setVulnerabilityIds(new HashSet<>());
        dep.setScanTimeMs(150);
        dep.setScannerUsed("OWASP");
        return dep;
    }
    
    // Helper method for reading file content (JDK 8 compatible)
    private String readFileContent(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            return IOUtils.toString(fis, StandardCharsets.UTF_8);
        }
    }
}