package io.github.dodogeny.security.plugin;

import io.github.dodogeny.security.database.InMemoryVulnerabilityDatabase;
import io.github.dodogeny.security.model.ScanResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * Tests for enhanced in-memory JAR analysis functionality
 * Tests the improved logging and trend analysis for in-memory database mode
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Enhanced In-Memory JAR Analysis Tests")
class EnhancedInMemoryJarAnalysisTest {

    @Mock
    private MavenProject mockProject;

    @Mock
    private MavenSession mockSession;

    @Mock
    private Log mockLog;

    private BastionScanMojo scanMojo;

    @BeforeEach
    void setUp() {
        scanMojo = new BastionScanMojo();
        scanMojo.setLog(mockLog);

        lenient().when(mockProject.getGroupId()).thenReturn("com.test");
        lenient().when(mockProject.getArtifactId()).thenReturn("test-project");
        lenient().when(mockProject.getVersion()).thenReturn("1.0.0");
        lenient().when(mockProject.getName()).thenReturn("Test Project");
    }

    @Test
    @DisplayName("Should generate correct in-memory JAR analysis with vulnerability details")
    void testInMemoryJarAnalysisWithDetails() throws Exception {
        // Create a previous scan summary
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        // Create current scan with vulnerable JARs
        ScanResult currentScan = createCurrentScanWithVulnerableJars();

        // Call the in-memory jar analysis method
        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify JAR analysis was set
        assertNotNull(currentScan.getJarAnalysis());
        ScanResult.JarAnalysis jarAnalysis = currentScan.getJarAnalysis();

        // Verify pending vulnerable JARs (all current vulnerable JARs)
        assertEquals(3, jarAnalysis.getPendingVulnerableJars().size());
        assertEquals(0, jarAnalysis.getResolvedJars().size());
        assertEquals(0, jarAnalysis.getNewVulnerableJars().size());
        // Total JARs analyzed should match the total dependencies set in the scan result
        assertEquals(currentScan.getTotalDependencies(), jarAnalysis.getTotalJarsAnalyzed());
    }

    @Test
    @DisplayName("Should correctly analyze trend when vulnerabilities increase")
    void testInMemoryJarAnalysisWithIncreasingVulnerabilities() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        ScanResult currentScan = createCurrentScanWithVulnerableJars();
        currentScan.setTotalVulnerabilities(15); // Increased from 5
        currentScan.setTotalDependencies(12); // Increased from 10

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify trend message for new dependencies with vulnerabilities
        verify(mockLog).info(contains("New dependencies with vulnerabilities detected"));
    }

    @Test
    @DisplayName("Should correctly analyze trend when vulnerabilities decrease")
    void testInMemoryJarAnalysisWithDecreasingVulnerabilities() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            10, 15, 5, 3, 2
        );

        ScanResult currentScan = createCurrentScanWithVulnerableJars();
        currentScan.setTotalVulnerabilities(5); // Decreased from 10
        currentScan.setTotalDependencies(15); // Same

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify trend message for vulnerabilities resolved
        verify(mockLog).info(contains("Vulnerabilities resolved in existing dependencies"));
    }

    @Test
    @DisplayName("Should display top vulnerable JARs sorted by severity")
    void testTopVulnerableJarsSorting() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        // Create scan with multiple JARs with different severity levels
        ScanResult currentScan = createCurrentScanWithMultipleSeverities();

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify that top JARs are displayed with severity breakdown
        verify(mockLog, atLeastOnce()).info(contains("Top Vulnerable JARs"));
        verify(mockLog, atLeastOnce()).info(contains("Critical:"));
        verify(mockLog, atLeastOnce()).info(contains("High:"));
    }

    @Test
    @DisplayName("Should show limited JARs when many vulnerabilities exist")
    void testLimitedJarDisplay() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        // Create scan with 10 vulnerable JARs (should show only top 5)
        ScanResult currentScan = createCurrentScanWithManyVulnerableJars(10);

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify message about showing limited results
        verify(mockLog, atLeastOnce()).info(contains("Top 5 Vulnerable JARs"));
        verify(mockLog, atLeastOnce()).info(contains("of 10 total"));
    }

    @Test
    @DisplayName("Should calculate correct CVE severity totals")
    void testCveSeverityTotals() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        ScanResult currentScan = createCurrentScanWithKnownSeverities();

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify severity breakdown is logged
        verify(mockLog).info(contains("Critical CVEs: 2"));
        verify(mockLog).info(contains("High CVEs: 3"));
        verify(mockLog).info(contains("Medium CVEs: 1"));
        verify(mockLog).info(contains("Low CVEs: 0"));
    }

    @Test
    @DisplayName("Should handle stable vulnerability and dependency counts")
    void testStableCountsTrend() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            10, 15, 5, 3, 2
        );

        ScanResult currentScan = createCurrentScanWithVulnerableJars();
        currentScan.setTotalVulnerabilities(10); // Same as previous
        currentScan.setTotalDependencies(15); // Same as previous

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify trend message for no change
        verify(mockLog).info(contains("No change in vulnerabilities or dependencies"));
    }

    @Test
    @DisplayName("Should provide guidance about JSON storage and Enterprise Edition")
    void testStorageGuidanceMessage() throws Exception {
        InMemoryVulnerabilityDatabase.ScanSummary previousScan = createPreviousScanSummary(
            5, 10, 3, 2, 0
        );

        ScanResult currentScan = createCurrentScanWithVulnerableJars();

        Method jarAnalysisMethod = BastionScanMojo.class.getDeclaredMethod(
            "generateInMemoryJarAnalysis",
            ScanResult.class,
            InMemoryVulnerabilityDatabase.ScanSummary.class
        );
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentScan, previousScan);

        // Verify informational message about better tracking options
        verify(mockLog).info(contains("Note: For detailed JAR-level tracking"));
        verify(mockLog).info(contains("use JSON storage or Enterprise Edition"));
    }

    // Helper methods

    private InMemoryVulnerabilityDatabase.ScanSummary createPreviousScanSummary(
        int totalVulns, int totalDeps, int critical, int high, int medium) {

        InMemoryVulnerabilityDatabase.ScanSummary summary = new InMemoryVulnerabilityDatabase.ScanSummary();
        summary.sessionId = 12345L;
        summary.startTime = LocalDateTime.now().minusHours(1);
        summary.endTime = LocalDateTime.now().minusHours(1).plusMinutes(10);
        summary.totalVulnerabilities = totalVulns;
        summary.totalDependencies = totalDeps;
        summary.vulnerableDependencies = 3;
        summary.criticalCount = critical;
        summary.highCount = high;
        summary.mediumCount = medium;
        summary.lowCount = 0;

        return summary;
    }

    private ScanResult createCurrentScanWithVulnerableJars() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(10));
        result.setTotalDependencies(15);
        result.setTotalVulnerabilities(8);

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        // Add 3 vulnerable JARs
        addVulnerableJar(dependencies, vulnerabilities, "log4j", "log4j-core", "2.14.0",
            Arrays.asList(
                createVuln("CVE-2021-44228", "CRITICAL"),
                createVuln("CVE-2021-45046", "CRITICAL")
            ));

        addVulnerableJar(dependencies, vulnerabilities, "commons-io", "commons-io", "2.6",
            Arrays.asList(
                createVuln("CVE-2021-29425", "MEDIUM")
            ));

        addVulnerableJar(dependencies, vulnerabilities, "spring", "spring-core", "5.2.0",
            Arrays.asList(
                createVuln("CVE-2022-22965", "CRITICAL"),
                createVuln("CVE-2020-5421", "HIGH")
            ));

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);

        return result;
    }

    private ScanResult createCurrentScanWithMultipleSeverities() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(10));
        result.setTotalDependencies(20);

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        // JAR with only critical
        addVulnerableJar(dependencies, vulnerabilities, "jar1", "artifact1", "1.0",
            Arrays.asList(
                createVuln("CVE-2023-00001", "CRITICAL"),
                createVuln("CVE-2023-00002", "CRITICAL")
            ));

        // JAR with high
        addVulnerableJar(dependencies, vulnerabilities, "jar2", "artifact2", "2.0",
            Arrays.asList(
                createVuln("CVE-2023-00003", "HIGH")
            ));

        // JAR with medium and low
        addVulnerableJar(dependencies, vulnerabilities, "jar3", "artifact3", "3.0",
            Arrays.asList(
                createVuln("CVE-2023-00004", "MEDIUM"),
                createVuln("CVE-2023-00005", "LOW")
            ));

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);

        return result;
    }

    private ScanResult createCurrentScanWithManyVulnerableJars(int count) {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(10));
        result.setTotalDependencies(count + 10);

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            addVulnerableJar(dependencies, vulnerabilities,
                "test-group-" + i, "test-artifact-" + i, "1.0." + i,
                Arrays.asList(
                    createVuln("CVE-2023-" + String.format("%05d", i),
                              i % 2 == 0 ? "CRITICAL" : "HIGH")
                ));
        }

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);

        return result;
    }

    private ScanResult createCurrentScanWithKnownSeverities() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(10));
        result.setTotalDependencies(15);

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        // JAR with 2 critical
        addVulnerableJar(dependencies, vulnerabilities, "jar1", "artifact1", "1.0",
            Arrays.asList(
                createVuln("CVE-2023-00001", "CRITICAL"),
                createVuln("CVE-2023-00002", "CRITICAL")
            ));

        // JAR with 3 high
        addVulnerableJar(dependencies, vulnerabilities, "jar2", "artifact2", "2.0",
            Arrays.asList(
                createVuln("CVE-2023-00003", "HIGH"),
                createVuln("CVE-2023-00004", "HIGH"),
                createVuln("CVE-2023-00005", "HIGH")
            ));

        // JAR with 1 medium
        addVulnerableJar(dependencies, vulnerabilities, "jar3", "artifact3", "3.0",
            Arrays.asList(
                createVuln("CVE-2023-00006", "MEDIUM")
            ));

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);

        return result;
    }

    private void addVulnerableJar(List<ScanResult.DependencyResult> dependencies,
                                  List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities,
                                  String groupId, String artifactId, String version,
                                  List<ScanResult.VulnerabilityInfo> vulns) {
        ScanResult.DependencyResult dependency = new ScanResult.DependencyResult();
        dependency.setGroupId(groupId);
        dependency.setArtifactId(artifactId);
        dependency.setVersion(version);

        Set<String> vulnIds = new HashSet<>();
        for (ScanResult.VulnerabilityInfo vuln : vulns) {
            vulnIds.add(vuln.getCveId());

            io.github.dodogeny.security.model.Vulnerability v =
                new io.github.dodogeny.security.model.Vulnerability();
            v.setCveId(vuln.getCveId());
            v.setSeverity(vuln.getSeverity());
            vulnerabilities.add(v);
        }
        dependency.setVulnerabilityIds(vulnIds);
        dependencies.add(dependency);
    }

    private ScanResult.VulnerabilityInfo createVuln(String cveId, String severity) {
        ScanResult.VulnerabilityInfo vuln = new ScanResult.VulnerabilityInfo();
        vuln.setCveId(cveId);
        vuln.setSeverity(severity);
        return vuln;
    }
}
