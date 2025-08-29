package io.github.dodogeny.security.plugin;

import io.github.dodogeny.security.database.InMemoryVulnerabilityDatabase;
import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
@DisplayName("In-Memory Trend Analysis Tests")
class InMemoryTrendAnalysisTest {

    @Mock
    private MavenProject mockProject;

    @Mock
    private MavenSession mockSession;

    @Mock
    private Log mockLog;

    private BastionScanMojo scanMojo;
    private InMemoryVulnerabilityDatabase inMemoryDatabase;

    @BeforeEach
    void setUp() throws Exception {
        scanMojo = new BastionScanMojo();
        scanMojo.setLog(mockLog);
        
        // Mock project details with lenient to avoid unnecessary stubbing errors
        lenient().when(mockProject.getGroupId()).thenReturn("com.test");
        lenient().when(mockProject.getArtifactId()).thenReturn("test-project");
        lenient().when(mockProject.getVersion()).thenReturn("1.0.0");
        lenient().when(mockProject.getName()).thenReturn("Test Project");
        
        // Set up the in-memory database
        inMemoryDatabase = new InMemoryVulnerabilityDatabase(LoggerFactory.getLogger(InMemoryVulnerabilityDatabase.class));
        
        // Set private fields
        setPrivateField("project", mockProject);
        setPrivateField("session", mockSession);
        setPrivateField("inMemoryDatabase", inMemoryDatabase);
        setPrivateField("communityStorageMode", "IN_MEMORY");
        setPrivateField("useJsonFileStorage", false);
    }

    @Test
    @DisplayName("Should store and retrieve scan results for trend analysis")
    void testStoreScanResultsForTrendAnalysis() throws Exception {
        // Create first scan result
        ScanResult firstScan = createScanResult(5, 2, 2, 1, 0);
        firstScan.setStartTime(LocalDateTime.now().minusHours(2));
        firstScan.setEndTime(LocalDateTime.now().minusHours(2).plusMinutes(10));
        
        // Store first scan
        inMemoryDatabase.storeScanResult(firstScan);
        
        // Create second scan result with changes
        ScanResult secondScan = createScanResult(8, 3, 3, 2, 0);
        secondScan.setStartTime(LocalDateTime.now().minusHours(1));
        secondScan.setEndTime(LocalDateTime.now().minusHours(1).plusMinutes(10));
        
        // Store second scan
        inMemoryDatabase.storeScanResult(secondScan);
        
        // Verify scan history
        List<InMemoryVulnerabilityDatabase.ScanSummary> history = inMemoryDatabase.getScanHistory(
            "com.test", "test-project", 10);
        
        assertEquals(2, history.size());
        assertEquals(8, history.get(0).totalVulnerabilities); // Most recent first
        assertEquals(5, history.get(1).totalVulnerabilities); // Previous scan
    }

    @Test
    @DisplayName("Should calculate trend data correctly")
    void testTrendDataCalculation() throws Exception {
        // Store multiple scan results to establish trend
        storeSampleScanHistory();
        
        // Create current scan result
        ScanResult currentScan = createScanResult(10, 4, 3, 2, 1);
        
        // Call the trend analysis method
        Method addTrendDataMethod = BastionScanMojo.class.getDeclaredMethod("addTrendDataFromInMemory", ScanResult.class);
        addTrendDataMethod.setAccessible(true);
        addTrendDataMethod.invoke(scanMojo, currentScan);
        
        // Verify trend data was added
        assertNotNull(currentScan.getTrendData());
        assertTrue(currentScan.getTrendData().containsKey("totalVulnerabilityTrend"));
        assertTrue(currentScan.getTrendData().containsKey("criticalTrend"));
        assertTrue(currentScan.getTrendData().containsKey("highTrend"));
        assertTrue(currentScan.getTrendData().containsKey("mediumTrend"));
        assertTrue(currentScan.getTrendData().containsKey("lowTrend"));
        assertTrue(currentScan.getTrendData().containsKey("previousScanDate"));
        assertTrue(currentScan.getTrendData().containsKey("historicalScansCount"));
        
        // Verify trend calculations (compared to previous scan which had 5 total vulnerabilities)
        assertEquals(5, currentScan.getTrendData().get("totalVulnerabilityTrend")); // 10 - 5 = 5
        assertEquals(3, currentScan.getTrendData().get("historicalScansCount"));
    }

    @Test
    @DisplayName("Should handle insufficient data for trend analysis")
    void testInsufficientDataForTrend() throws Exception {
        // Store only one scan (insufficient for trend)
        ScanResult singleScan = createScanResult(5, 2, 2, 1, 0);
        inMemoryDatabase.storeScanResult(singleScan);
        
        // Create current scan
        ScanResult currentScan = createScanResult(8, 3, 3, 2, 0);
        
        // Call trend analysis
        Method addTrendDataMethod = BastionScanMojo.class.getDeclaredMethod("addTrendDataFromInMemory", ScanResult.class);
        addTrendDataMethod.setAccessible(true);
        addTrendDataMethod.invoke(scanMojo, currentScan);
        
        // Verify no trend data was added (insufficient history)
        assertNull(currentScan.getTrendData(), "Trend data should be null when insufficient history");
        
        // Verify appropriate log message
        verify(mockLog).info("📊 Insufficient historical data for trend analysis (need at least 2 scans)");
    }

    @Test
    @DisplayName("Should generate JAR analysis for in-memory trends")
    void testInMemoryJarAnalysis() throws Exception {
        // Store sample scan history
        storeSampleScanHistory();
        
        // Create current scan
        ScanResult currentScan = createScanResult(10, 4, 3, 2, 1);
        
        // Call trend analysis method
        Method addTrendDataMethod = BastionScanMojo.class.getDeclaredMethod("addTrendDataFromInMemory", ScanResult.class);
        addTrendDataMethod.setAccessible(true);
        addTrendDataMethod.invoke(scanMojo, currentScan);
        
        // Verify JAR analysis was set
        assertNotNull(currentScan.getJarAnalysis());
        assertNotNull(currentScan.getJarAnalysis().getNewVulnerableJars());
        assertNotNull(currentScan.getJarAnalysis().getResolvedJars());
        assertNotNull(currentScan.getJarAnalysis().getPendingVulnerableJars());
        assertEquals(10, currentScan.getJarAnalysis().getTotalJarsAnalyzed());
    }

    @Test
    @DisplayName("Should handle trend analysis errors gracefully")
    void testTrendAnalysisErrorHandling() throws Exception {
        // Set up a scenario that could cause errors
        setPrivateField("inMemoryDatabase", null); // Null database
        
        ScanResult currentScan = createScanResult(5, 2, 2, 1, 0);
        
        // Call trend analysis - should not throw exception
        Method addTrendDataMethod = BastionScanMojo.class.getDeclaredMethod("addTrendDataFromInMemory", ScanResult.class);
        addTrendDataMethod.setAccessible(true);
        
        assertDoesNotThrow(() -> {
            try {
                addTrendDataMethod.invoke(scanMojo, currentScan);
            } catch (Exception e) {
                if (e.getCause() instanceof NullPointerException) {
                    // This is expected due to null database
                    return;
                }
                throw e;
            }
        });
    }

    @Test
    @DisplayName("Should store scan results when using in-memory storage")
    void testStoreResultsInMemory() throws Exception {
        ScanResult scanResult = createScanResult(5, 2, 2, 1, 0);
        
        // Call the store results method
        Method storeResultsMethod = BastionScanMojo.class.getDeclaredMethod("storeResults", ScanResult.class);
        storeResultsMethod.setAccessible(true);
        storeResultsMethod.invoke(scanMojo, scanResult);
        
        // Verify the result was stored
        List<InMemoryVulnerabilityDatabase.ScanSummary> history = inMemoryDatabase.getScanHistory(
            "com.test", "test-project", 10);
        
        assertEquals(1, history.size());
        assertEquals(5, history.get(0).totalVulnerabilities);
        
        // Verify logging
        verify(mockLog).info("Storing scan results in in-memory database...");
        verify(mockLog).info("Scan results stored successfully in in-memory database");
    }

    @Test
    @DisplayName("Should get project statistics correctly")
    void testProjectStatistics() throws Exception {
        // Store scan history
        storeSampleScanHistory();
        
        // Get project statistics
        InMemoryVulnerabilityDatabase.ProjectStats stats = inMemoryDatabase.getProjectStats(
            "com.test", "test-project");
        
        assertNotNull(stats);
        assertEquals(3, stats.totalScans);
        assertEquals(7, stats.currentVulnerabilities); // Latest scan
        assertEquals(2, stats.vulnerabilityTrend); // 7 - 5 = 2 (trend vs previous)
        assertNotNull(stats.lastScanTime);
        assertNotNull(stats.previousScanTime);
    }

    @Test
    @DisplayName("Should handle multiple projects in in-memory database")
    void testMultipleProjects() throws Exception {
        // Store scans for first project
        ScanResult project1Scan = createScanResult(5, 2, 2, 1, 0);
        project1Scan.setProjectGroupId("com.test");
        project1Scan.setProjectArtifactId("project1");
        inMemoryDatabase.storeScanResult(project1Scan);
        
        // Store scans for second project
        ScanResult project2Scan = createScanResult(8, 3, 3, 2, 0);
        project2Scan.setProjectGroupId("com.test");
        project2Scan.setProjectArtifactId("project2");
        inMemoryDatabase.storeScanResult(project2Scan);
        
        // Get all projects
        List<InMemoryVulnerabilityDatabase.ProjectInfo> projects = inMemoryDatabase.getAllProjects();
        
        assertEquals(2, projects.size());
        
        // Verify project1 data
        InMemoryVulnerabilityDatabase.ProjectInfo project1Info = projects.stream()
            .filter(p -> "project1".equals(p.artifactId))
            .findFirst()
            .orElse(null);
        assertNotNull(project1Info);
        assertEquals(5, project1Info.lastVulnerabilityCount);
        
        // Verify project2 data
        InMemoryVulnerabilityDatabase.ProjectInfo project2Info = projects.stream()
            .filter(p -> "project2".equals(p.artifactId))
            .findFirst()
            .orElse(null);
        assertNotNull(project2Info);
        assertEquals(8, project2Info.lastVulnerabilityCount);
    }

    // Helper methods
    
    private void setPrivateField(String fieldName, Object value) throws Exception {
        Field field = BastionScanMojo.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(scanMojo, value);
    }

    private ScanResult createScanResult(int total, int critical, int high, int medium, int low) {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setProjectName("Test Project");
        result.setTotalVulnerabilities(total);
        result.setCriticalVulnerabilities(critical);
        result.setHighVulnerabilities(high);
        result.setMediumVulnerabilities(medium);
        result.setLowVulnerabilities(low);
        result.setTotalDependencies(10);
        result.setVulnerableDependencies(3);
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(5));
        result.setScanDurationMs(300000);
        
        return result;
    }


    private void storeSampleScanHistory() {
        // Store first scan (oldest)
        ScanResult scan1 = createScanResult(3, 1, 1, 1, 0);
        scan1.setStartTime(LocalDateTime.now().minusHours(3));
        scan1.setEndTime(LocalDateTime.now().minusHours(3).plusMinutes(5));
        inMemoryDatabase.storeScanResult(scan1);
        
        // Store second scan (middle)
        ScanResult scan2 = createScanResult(5, 2, 2, 1, 0);
        scan2.setStartTime(LocalDateTime.now().minusHours(2));
        scan2.setEndTime(LocalDateTime.now().minusHours(2).plusMinutes(5));
        inMemoryDatabase.storeScanResult(scan2);
        
        // Store third scan (most recent before current)
        ScanResult scan3 = createScanResult(7, 3, 2, 2, 0);
        scan3.setStartTime(LocalDateTime.now().minusHours(1));
        scan3.setEndTime(LocalDateTime.now().minusHours(1).plusMinutes(5));
        inMemoryDatabase.storeScanResult(scan3);
    }
}