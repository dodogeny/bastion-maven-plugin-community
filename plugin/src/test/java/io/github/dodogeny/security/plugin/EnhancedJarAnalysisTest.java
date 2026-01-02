package io.github.dodogeny.security.plugin;

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

import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * Comprehensive tests for enhanced JAR-level vulnerability analysis
 * Tests the detailed tracking of resolved, new, and pending vulnerable JARs
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Enhanced JAR Analysis Tests")
class EnhancedJarAnalysisTest {

    @Mock
    private MavenProject mockProject;

    @Mock
    private MavenSession mockSession;

    @Mock
    private Log mockLog;

    private SecHiveScanMojo scanMojo;

    @BeforeEach
    void setUp() {
        scanMojo = new SecHiveScanMojo();
        scanMojo.setLog(mockLog);

        lenient().when(mockProject.getGroupId()).thenReturn("com.test");
        lenient().when(mockProject.getArtifactId()).thenReturn("test-project");
        lenient().when(mockProject.getVersion()).thenReturn("1.0.0");
        lenient().when(mockProject.getName()).thenReturn("Test Project");
    }

    @Test
    @DisplayName("Should correctly identify resolved JARs with all CVE details")
    void testResolvedJarsWithCveDetails() throws Exception {
        // Create previous scan with vulnerable JAR
        ScanResult previousResult = createScanResultWithVulnerableJar(
            "log4j:log4j-core", "2.14.0",
            Arrays.asList(
                createVulnerability("CVE-2021-44228", "CRITICAL"),
                createVulnerability("CVE-2021-45046", "CRITICAL"),
                createVulnerability("CVE-2021-45105", "HIGH")
            )
        );

        // Create current scan where log4j is no longer vulnerable (upgraded)
        ScanResult currentResult = createScanResultWithoutVulnerability();

        // Call the jar analysis method
        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        // Verify JAR analysis
        assertNotNull(currentResult.getJarAnalysis());
        ScanResult.JarAnalysis jarAnalysis = currentResult.getJarAnalysis();

        // Check resolved JARs
        assertEquals(1, jarAnalysis.getResolvedJars().size());
        ScanResult.VulnerableJar resolvedJar = jarAnalysis.getResolvedJars().get(0);

        assertEquals("log4j:log4j-core", resolvedJar.getName());
        assertEquals("2.14.0", resolvedJar.getVersion());
        assertEquals(3, resolvedJar.getResolvedCveCount());
        assertEquals(3, resolvedJar.getResolvedCves().size());

        // Verify all CVEs are tracked
        Set<String> resolvedCveIds = new HashSet<>();
        for (ScanResult.ResolvedCve cve : resolvedJar.getResolvedCves()) {
            resolvedCveIds.add(cve.getId());
            assertNotNull(cve.getSeverity());
        }
        assertTrue(resolvedCveIds.contains("CVE-2021-44228"));
        assertTrue(resolvedCveIds.contains("CVE-2021-45046"));
        assertTrue(resolvedCveIds.contains("CVE-2021-45105"));

        // Verify no new or pending JARs
        assertEquals(0, jarAnalysis.getNewVulnerableJars().size());
        assertEquals(0, jarAnalysis.getPendingVulnerableJars().size());
    }

    @Test
    @DisplayName("Should correctly identify new vulnerable JARs")
    void testNewVulnerableJars() throws Exception {
        // Create previous scan with no vulnerable dependencies
        ScanResult previousResult = createScanResultWithoutVulnerability();

        // Create current scan with new vulnerable JAR
        ScanResult currentResult = createScanResultWithVulnerableJar(
            "commons-io:commons-io", "2.6",
            Arrays.asList(
                createVulnerability("CVE-2021-29425", "MEDIUM"),
                createVulnerability("CVE-2024-47554", "HIGH")
            )
        );

        // Call the jar analysis method
        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        // Verify JAR analysis
        ScanResult.JarAnalysis jarAnalysis = currentResult.getJarAnalysis();

        // Check new vulnerable JARs
        assertEquals(1, jarAnalysis.getNewVulnerableJars().size());
        ScanResult.VulnerableJar newJar = jarAnalysis.getNewVulnerableJars().get(0);

        assertEquals("commons-io:commons-io", newJar.getName());
        assertEquals("2.6", newJar.getVersion());
        assertEquals(2, newJar.getVulnerabilities().size());

        // Verify severity counts
        assertEquals(0, newJar.getCriticalCount());
        assertEquals(1, newJar.getHighCount());
        assertEquals(1, newJar.getMediumCount());
        assertEquals(0, newJar.getLowCount());

        // Verify no resolved or pending JARs
        assertEquals(0, jarAnalysis.getResolvedJars().size());
        assertEquals(0, jarAnalysis.getPendingVulnerableJars().size());
    }

    @Test
    @DisplayName("Should correctly identify pending JARs with partial CVE resolution")
    void testPendingJarsWithPartialResolution() throws Exception {
        // Create previous scan with vulnerable JAR having 4 CVEs
        ScanResult previousResult = createScanResultWithVulnerableJar(
            "spring:spring-core", "5.2.0",
            Arrays.asList(
                createVulnerability("CVE-2020-5398", "CRITICAL"),
                createVulnerability("CVE-2020-5421", "HIGH"),
                createVulnerability("CVE-2021-22060", "MEDIUM"),
                createVulnerability("CVE-2022-22965", "CRITICAL")
            )
        );

        // Create current scan where same JAR has 2 CVEs resolved and 1 new CVE
        ScanResult currentResult = createScanResultWithVulnerableJar(
            "spring:spring-core", "5.2.0",
            Arrays.asList(
                createVulnerability("CVE-2020-5421", "HIGH"),      // Still present
                createVulnerability("CVE-2022-22965", "CRITICAL"), // Still present
                createVulnerability("CVE-2023-20861", "HIGH")      // New CVE
            )
        );

        // Call the jar analysis method
        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        // Verify JAR analysis
        ScanResult.JarAnalysis jarAnalysis = currentResult.getJarAnalysis();

        // Check pending vulnerable JARs
        assertEquals(1, jarAnalysis.getPendingVulnerableJars().size());
        ScanResult.VulnerableJar pendingJar = jarAnalysis.getPendingVulnerableJars().get(0);

        assertEquals("spring:spring-core", pendingJar.getName());
        assertEquals("5.2.0", pendingJar.getVersion());
        assertEquals(3, pendingJar.getVulnerabilities().size()); // 2 ongoing + 1 new

        // Check resolved CVEs within pending JAR
        assertEquals(2, pendingJar.getResolvedCveCount());
        assertEquals(2, pendingJar.getResolvedCves().size());

        Set<String> resolvedCveIds = new HashSet<>();
        for (ScanResult.ResolvedCve cve : pendingJar.getResolvedCves()) {
            resolvedCveIds.add(cve.getId());
        }
        assertTrue(resolvedCveIds.contains("CVE-2020-5398"));
        assertTrue(resolvedCveIds.contains("CVE-2021-22060"));

        // Verify no fully resolved or new JARs
        assertEquals(0, jarAnalysis.getResolvedJars().size());
        assertEquals(0, jarAnalysis.getNewVulnerableJars().size());
    }

    @Test
    @DisplayName("Should handle complex scenario with multiple JAR states")
    void testComplexMultiJarScenario() throws Exception {
        // Create previous scan with 3 vulnerable JARs
        ScanResult previousResult = createComplexPreviousScan();

        // Create current scan with:
        // - 1 JAR fully resolved (log4j)
        // - 1 JAR still pending (commons-io)
        // - 1 new vulnerable JAR (jackson)
        ScanResult currentResult = createComplexCurrentScan();

        // Call the jar analysis method
        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        // Verify JAR analysis
        ScanResult.JarAnalysis jarAnalysis = currentResult.getJarAnalysis();

        // Verify counts
        assertEquals(1, jarAnalysis.getResolvedJars().size());
        assertEquals(1, jarAnalysis.getNewVulnerableJars().size());
        assertEquals(1, jarAnalysis.getPendingVulnerableJars().size());

        // Verify resolved JAR
        assertEquals("log4j:log4j-core", jarAnalysis.getResolvedJars().get(0).getName());

        // Verify new JAR
        assertEquals("jackson:jackson-databind", jarAnalysis.getNewVulnerableJars().get(0).getName());

        // Verify pending JAR
        assertEquals("commons-io:commons-io", jarAnalysis.getPendingVulnerableJars().get(0).getName());
    }

    @Test
    @DisplayName("Should calculate correct total JARs analyzed")
    void testTotalJarsAnalyzedCalculation() throws Exception {
        ScanResult previousResult = createScanResultWithoutVulnerability();
        ScanResult currentResult = createScanResultWithVulnerableJar(
            "test:jar", "1.0",
            Arrays.asList(createVulnerability("CVE-2023-00001", "HIGH"))
        );
        currentResult.setTotalDependencies(25);

        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        assertEquals(25, currentResult.getJarAnalysis().getTotalJarsAnalyzed());
    }

    @Test
    @DisplayName("Should handle empty dependency lists gracefully")
    void testEmptyDependencyLists() throws Exception {
        ScanResult previousResult = new ScanResult();
        previousResult.setDependencies(new ArrayList<>());
        previousResult.setVulnerabilities(new ArrayList<>());

        ScanResult currentResult = new ScanResult();
        currentResult.setDependencies(new ArrayList<>());
        currentResult.setVulnerabilities(new ArrayList<>());
        currentResult.setTotalDependencies(0);

        Method jarAnalysisMethod = SecHiveScanMojo.class.getDeclaredMethod(
            "generateJarAnalysis", ScanResult.class, ScanResult.class);
        jarAnalysisMethod.setAccessible(true);
        jarAnalysisMethod.invoke(scanMojo, currentResult, previousResult);

        ScanResult.JarAnalysis jarAnalysis = currentResult.getJarAnalysis();
        assertNotNull(jarAnalysis);
        assertEquals(0, jarAnalysis.getResolvedJars().size());
        assertEquals(0, jarAnalysis.getNewVulnerableJars().size());
        assertEquals(0, jarAnalysis.getPendingVulnerableJars().size());
        assertEquals(0, jarAnalysis.getTotalJarsAnalyzed());
    }

    // Helper methods

    private ScanResult createScanResultWithVulnerableJar(String jarName, String version,
                                                          List<ScanResult.VulnerabilityInfo> vulnerabilities) {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(5));

        // Create a dependency with vulnerabilities
        ScanResult.DependencyResult dependency = new ScanResult.DependencyResult();
        dependency.setGroupId(jarName.split(":")[0]);
        dependency.setArtifactId(jarName.split(":")[1]);
        dependency.setVersion(version);

        Set<String> vulnIds = new HashSet<>();
        for (ScanResult.VulnerabilityInfo vuln : vulnerabilities) {
            vulnIds.add(vuln.getCveId());
        }
        dependency.setVulnerabilityIds(vulnIds);

        result.setDependencies(Arrays.asList(dependency));

        // Create vulnerabilities
        List<io.github.dodogeny.security.model.Vulnerability> vulnList = new ArrayList<>();
        for (ScanResult.VulnerabilityInfo vulnInfo : vulnerabilities) {
            io.github.dodogeny.security.model.Vulnerability vuln =
                new io.github.dodogeny.security.model.Vulnerability();
            vuln.setCveId(vulnInfo.getCveId());
            vuln.setSeverity(vulnInfo.getSeverity());
            vulnList.add(vuln);
        }
        result.setVulnerabilities(vulnList);
        result.setTotalDependencies(1);

        return result;
    }

    private ScanResult createScanResultWithoutVulnerability() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(5));
        result.setDependencies(new ArrayList<>());
        result.setVulnerabilities(new ArrayList<>());
        result.setTotalDependencies(0);
        return result;
    }

    private ScanResult.VulnerabilityInfo createVulnerability(String cveId, String severity) {
        ScanResult.VulnerabilityInfo vuln = new ScanResult.VulnerabilityInfo();
        vuln.setCveId(cveId);
        vuln.setSeverity(severity);
        return vuln;
    }

    private ScanResult createComplexPreviousScan() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(5));

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        // log4j with 2 CVEs (will be resolved)
        addDependency(dependencies, vulnerabilities, "log4j", "log4j-core", "2.14.0",
            Arrays.asList(
                createVulnerability("CVE-2021-44228", "CRITICAL"),
                createVulnerability("CVE-2021-45046", "CRITICAL")
            ));

        // commons-io with 1 CVE (will be pending)
        addDependency(dependencies, vulnerabilities, "commons-io", "commons-io", "2.6",
            Arrays.asList(
                createVulnerability("CVE-2021-29425", "MEDIUM")
            ));

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);
        result.setTotalDependencies(dependencies.size());

        return result;
    }

    private ScanResult createComplexCurrentScan() {
        ScanResult result = new ScanResult();
        result.setProjectGroupId("com.test");
        result.setProjectArtifactId("test-project");
        result.setStartTime(LocalDateTime.now());
        result.setEndTime(LocalDateTime.now().plusMinutes(5));

        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();

        // log4j is no longer in the list (resolved)

        // commons-io still has CVE (pending)
        addDependency(dependencies, vulnerabilities, "commons-io", "commons-io", "2.6",
            Arrays.asList(
                createVulnerability("CVE-2021-29425", "MEDIUM")
            ));

        // jackson is new with vulnerabilities
        addDependency(dependencies, vulnerabilities, "jackson", "jackson-databind", "2.9.0",
            Arrays.asList(
                createVulnerability("CVE-2020-36518", "HIGH")
            ));

        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);
        result.setTotalDependencies(dependencies.size());

        return result;
    }

    private void addDependency(List<ScanResult.DependencyResult> dependencies,
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
}
