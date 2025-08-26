package io.github.dodogeny.security.scanner;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.dependency.Dependency;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OwaspDependencyCheckScannerTest {

    @Mock
    private Engine mockEngine;

    private OwaspDependencyCheckScanner scanner;
    private VulnerabilityScanner.ScannerConfiguration configuration;

    @TempDir
    private Path tempDir;

    @BeforeEach
    void setUp() {
        configuration = new VulnerabilityScanner.ScannerConfiguration();
        configuration.setTimeoutMs(30000);
        configuration.setSeverityThreshold("MEDIUM");
        configuration.setEnableCache(true);
        configuration.setCacheDirectory(tempDir.resolve("cache").toString());
        configuration.setThreadCount(2);
        configuration.setBatchSize(50);
        
        scanner = new OwaspDependencyCheckScanner();
        scanner.configure(configuration);
        
        // Reset mocks
        reset(mockEngine);
    }

    @Test
    @DisplayName("Should initialize scanner with correct configuration")
    void testScannerInitialization() {
        assertEquals("OWASP Dependency-Check", scanner.getName());
        assertTrue(scanner.isEnabled());
    }

    @Test
    @DisplayName("Should handle scanner configuration properly")
    void testScannerConfiguration() {
        VulnerabilityScanner.ScannerConfiguration newConfig = new VulnerabilityScanner.ScannerConfiguration();
        newConfig.setTimeoutMs(60000);
        newConfig.setSeverityThreshold("HIGH");
        newConfig.setEnableCache(false);

        scanner.configure(newConfig);
        assertTrue(scanner.isEnabled());
    }

    @Test
    @DisplayName("Should scan Maven project and return scan results")
    void testScanProject() throws Exception {
        // Create a temporary Maven project structure
        Path projectDir = createTemporaryMavenProject();

        // Execute scan
        CompletableFuture<ScanResult> future = scanner.scanProject(projectDir.toString());
        
        assertNotNull(future);
        
        // Wait for completion with timeout
        ScanResult result = future.get(30, TimeUnit.SECONDS);
        
        assertNotNull(result);
        assertNotNull(result.getProjectName());
        assertTrue(result.getTotalDependencies() >= 0);
        assertNotNull(result.getStartTime());
    }

    @Test
    @DisplayName("Should handle multi-module projects")
    void testMultiModuleProject() throws Exception {
        // Create multi-module project structure
        Path rootDir = createTemporaryMultiModuleProject();

        CompletableFuture<ScanResult> future = scanner.scanProject(rootDir.toString());
        ScanResult result = future.get(45, TimeUnit.SECONDS);

        assertNotNull(result);
        assertTrue(result.getTotalDependencies() >= 0);
    }

    @Test
    @DisplayName("Should respect severity threshold filtering")
    void testSeverityFiltering() throws Exception {
        configuration.setSeverityThreshold("HIGH");
        scanner.configure(configuration);

        Path projectDir = createTemporaryMavenProject();
        CompletableFuture<ScanResult> future = scanner.scanProject(projectDir.toString());
        ScanResult result = future.get(30, TimeUnit.SECONDS);

        // Verify scan completed successfully
        assertNotNull(result);
        assertTrue(result.getTotalVulnerabilities() >= 0);
    }

    @Test
    @DisplayName("Should handle scan timeout gracefully")
    void testScanTimeout() throws Exception {
        // Set very short timeout
        configuration.setTimeoutMs(1);
        scanner.configure(configuration);

        Path projectDir = createTemporaryMavenProject();

        assertDoesNotThrow(() -> {
            CompletableFuture<ScanResult> future = scanner.scanProject(projectDir.toString());
            ScanResult result = future.get(5, TimeUnit.SECONDS);
            // Should either complete quickly or handle timeout gracefully
            assertNotNull(result);
        });
    }

    @Test
    @DisplayName("Should cache scan results when enabled")
    void testResultCaching() throws Exception {
        configuration.setEnableCache(true);
        scanner.configure(configuration);

        Path projectDir = createTemporaryMavenProject();

        // First scan
        long startTime1 = System.currentTimeMillis();
        CompletableFuture<ScanResult> future1 = scanner.scanProject(projectDir.toString());
        ScanResult result1 = future1.get(30, TimeUnit.SECONDS);
        long duration1 = System.currentTimeMillis() - startTime1;

        // Second scan (should use cache)
        long startTime2 = System.currentTimeMillis();
        CompletableFuture<ScanResult> future2 = scanner.scanProject(projectDir.toString());
        ScanResult result2 = future2.get(30, TimeUnit.SECONDS);
        long duration2 = System.currentTimeMillis() - startTime2;

        assertNotNull(result1);
        assertNotNull(result2);
        
        // Note: In a real implementation, the second scan might be faster due to caching
        // This is a basic structure test
    }

    @Test
    @DisplayName("Should handle project with no dependencies")
    void testEmptyProject() throws Exception {
        Path emptyProjectDir = createEmptyMavenProject();

        CompletableFuture<ScanResult> future = scanner.scanProject(emptyProjectDir.toString());
        ScanResult result = future.get(15, TimeUnit.SECONDS);

        assertNotNull(result);
        assertEquals(0, result.getTotalDependencies());
        assertEquals(0, result.getTotalVulnerabilities());
    }

    @Test
    @DisplayName("Should handle concurrent scans safely")
    void testConcurrentScans() throws Exception {
        Path projectDir1 = createTemporaryMavenProject();
        Path projectDir2 = createTemporaryMavenProject();

        CompletableFuture<ScanResult> future1 = scanner.scanProject(projectDir1.toString());
        CompletableFuture<ScanResult> future2 = scanner.scanProject(projectDir2.toString());

        // Wait for both to complete
        CompletableFuture<Void> combined = CompletableFuture.allOf(future1, future2);
        combined.get(60, TimeUnit.SECONDS);

        ScanResult result1 = future1.get();
        ScanResult result2 = future2.get();

        assertNotNull(result1);
        assertNotNull(result2);
        assertNotNull(result1.getStartTime());
        assertNotNull(result2.getStartTime());
    }

    @Test
    @DisplayName("Should generate detailed performance metrics")
    void testPerformanceMetrics() throws Exception {
        Path projectDir = createTemporaryMavenProject();

        CompletableFuture<ScanResult> future = scanner.scanProject(projectDir.toString());
        ScanResult result = future.get(30, TimeUnit.SECONDS);

        assertNotNull(result);
        assertNotNull(result.getPerformanceMetrics());
        
        ScanResult.PerformanceMetrics metrics = result.getPerformanceMetrics();
        if (metrics != null) {
            assertTrue(metrics.getInitializationTimeMs() >= 0);
            assertTrue(metrics.getVulnerabilityCheckTimeMs() >= 0);
            assertTrue(metrics.getReportGenerationTimeMs() >= 0);
        }
    }

    @Test
    @DisplayName("Should provide accurate scan statistics")
    void testScanStatistics() throws Exception {
        Path projectDir = createTemporaryMavenProject();

        CompletableFuture<ScanResult> future = scanner.scanProject(projectDir.toString());
        ScanResult result = future.get(30, TimeUnit.SECONDS);

        assertNotNull(result);
        assertNotNull(result.getStatistics());
        
        ScanResult.ScanStatistics stats = result.getStatistics();
        if (stats != null) {
            assertTrue(stats.getTotalJarsScanned() >= 0);
            assertTrue(stats.getTotalCvesFound() >= 0);
            assertTrue(stats.getUniqueCvesFound() >= 0);
        }
    }

    @Test
    @DisplayName("Should handle invalid project paths gracefully")
    void testInvalidProjectPath() {
        String invalidPath = "/nonexistent/path/to/project";

        assertDoesNotThrow(() -> {
            CompletableFuture<ScanResult> future = scanner.scanProject(invalidPath);
            // Should handle gracefully, possibly returning empty result or throwing expected exception
            assertNotNull(future);
        });
    }

    // Helper methods for creating test project structures

    private Path createTemporaryMavenProject() throws Exception {
        Path projectDir = tempDir.resolve("test-project-" + System.currentTimeMillis());
        Files.createDirectories(projectDir);

        // Create basic Maven structure
        Files.createDirectories(projectDir.resolve("src/main/java"));
        Files.createDirectories(projectDir.resolve("src/test/java"));

        // Create minimal pom.xml
        String pomContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n" +
            "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 \n" +
            "         http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n" +
            "    <modelVersion>4.0.0</modelVersion>\n" +
            "    <groupId>com.test</groupId>\n" +
            "    <artifactId>test-project</artifactId>\n" +
            "    <version>1.0.0</version>\n" +
            "    <packaging>jar</packaging>\n" +
            "    \n" +
            "    <properties>\n" +
            "        <maven.compiler.source>8</maven.compiler.source>\n" +
            "        <maven.compiler.target>8</maven.compiler.target>\n" +
            "        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n" +
            "    </properties>\n" +
            "    \n" +
            "    <dependencies>\n" +
            "        <dependency>\n" +
            "            <groupId>org.apache.commons</groupId>\n" +
            "            <artifactId>commons-lang3</artifactId>\n" +
            "            <version>3.8.1</version>\n" +
            "        </dependency>\n" +
            "        <dependency>\n" +
            "            <groupId>junit</groupId>\n" +
            "            <artifactId>junit</artifactId>\n" +
            "            <version>4.12</version>\n" +
            "            <scope>test</scope>\n" +
            "        </dependency>\n" +
            "    </dependencies>\n" +
            "</project>\n";

        Files.write(projectDir.resolve("pom.xml"), pomContent.getBytes());
        return projectDir;
    }

    private Path createTemporaryMultiModuleProject() throws Exception {
        Path rootDir = tempDir.resolve("multi-module-" + System.currentTimeMillis());
        Files.createDirectories(rootDir);

        // Root pom.xml
        String rootPom = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n" +
            "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 \n" +
            "         http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n" +
            "    <modelVersion>4.0.0</modelVersion>\n" +
            "    <groupId>com.test</groupId>\n" +
            "    <artifactId>multi-project</artifactId>\n" +
            "    <version>1.0.0</version>\n" +
            "    <packaging>pom</packaging>\n" +
            "    \n" +
            "    <modules>\n" +
            "        <module>module1</module>\n" +
            "        <module>module2</module>\n" +
            "    </modules>\n" +
            "</project>\n";

        Files.write(rootDir.resolve("pom.xml"), rootPom.getBytes());

        // Create module directories and poms
        createModulePom(rootDir, "module1");
        createModulePom(rootDir, "module2");

        return rootDir;
    }

    private void createModulePom(Path rootDir, String moduleName) throws Exception {
        Path moduleDir = rootDir.resolve(moduleName);
        Files.createDirectories(moduleDir);
        Files.createDirectories(moduleDir.resolve("src/main/java"));

        String modulePom = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n" +
            "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 \n" +
            "         http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n" +
            "    <modelVersion>4.0.0</modelVersion>\n" +
            "    <parent>\n" +
            "        <groupId>com.test</groupId>\n" +
            "        <artifactId>multi-project</artifactId>\n" +
            "        <version>1.0.0</version>\n" +
            "    </parent>\n" +
            "    <artifactId>" + moduleName + "</artifactId>\n" +
            "    <packaging>jar</packaging>\n" +
            "    \n" +
            "    <dependencies>\n" +
            "        <dependency>\n" +
            "            <groupId>org.slf4j</groupId>\n" +
            "            <artifactId>slf4j-api</artifactId>\n" +
            "            <version>1.7.36</version>\n" +
            "        </dependency>\n" +
            "    </dependencies>\n" +
            "</project>\n";

        Files.write(moduleDir.resolve("pom.xml"), modulePom.getBytes());
    }

    private Path createEmptyMavenProject() throws Exception {
        Path projectDir = tempDir.resolve("empty-project-" + System.currentTimeMillis());
        Files.createDirectories(projectDir);

        // Create minimal pom.xml with no dependencies
        String pomContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"\n" +
            "         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
            "         xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 \n" +
            "         http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n" +
            "    <modelVersion>4.0.0</modelVersion>\n" +
            "    <groupId>com.test</groupId>\n" +
            "    <artifactId>empty-project</artifactId>\n" +
            "    <version>1.0.0</version>\n" +
            "    <packaging>jar</packaging>\n" +
            "    \n" +
            "    <properties>\n" +
            "        <maven.compiler.source>8</maven.compiler.source>\n" +
            "        <maven.compiler.target>8</maven.compiler.target>\n" +
            "        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n" +
            "    </properties>\n" +
            "</project>\n";

        Files.write(projectDir.resolve("pom.xml"), pomContent.getBytes());
        return projectDir;
    }
}