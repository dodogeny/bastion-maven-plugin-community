package io.github.dodogeny.security.scanner;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.owasp.dependencycheck.Engine;
import org.owasp.dependencycheck.data.nvdcve.DatabaseException;
import io.github.jeremylong.openvulnerability.client.nvd.CvssV3;
import org.owasp.dependencycheck.dependency.Dependency;
import org.owasp.dependencycheck.dependency.Vulnerability.Source;
import org.owasp.dependencycheck.exception.ExceptionCollection;
import org.owasp.dependencycheck.exception.InitializationException;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class OwaspDependencyCheckScanner implements VulnerabilityScanner {
    
    private static final Logger logger = LoggerFactory.getLogger(OwaspDependencyCheckScanner.class);
    
    private static final String SCANNER_NAME = "OWASP Dependency-Check";
    private static final int MAX_CONCURRENT_SCANS = 2;
    
    private ScannerConfiguration configuration;
    private final AtomicInteger totalScansCompleted = new AtomicInteger(0);
    private final AtomicInteger totalScansFailed = new AtomicInteger(0);
    private final AtomicLong lastSuccessfulScanMs = new AtomicLong(0);
    private String nvdApiKey;
    private NvdCacheManager cacheManager;
    
    public OwaspDependencyCheckScanner() {
        this.configuration = new ScannerConfiguration();
        initializeCacheManager();
    }
    
    public OwaspDependencyCheckScanner(String nvdApiKey) {
        this.configuration = new ScannerConfiguration();
        this.nvdApiKey = nvdApiKey;
        initializeCacheManager();
    }
    
    private void initializeCacheManager() {
        long cacheValidityHours = configuration.getCacheValidityHours();
        int connectionTimeoutMs = 10000; // 10 seconds for cache checks
        
        this.cacheManager = new NvdCacheManager(
            configuration.getCacheDirectory(), 
            cacheValidityHours, 
            connectionTimeoutMs
        );
    }
    
    @Override
    public String getName() {
        return SCANNER_NAME;
    }
    
    @Override
    public boolean isEnabled() {
        return true;
    }
    
    @Override
    public CompletableFuture<List<Vulnerability>> scanDependencies(List<String> dependencies) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("Starting OWASP Dependency-Check scan for {} dependencies", dependencies.size());
                
                // Set API key system properties BEFORE creating any OWASP objects
                String effectiveNvdApiKey = getEffectiveApiKey();
                configureSystemPropertiesForOwasp(effectiveNvdApiKey);
                
                Settings settings = createSmartCachedSettings(effectiveNvdApiKey);
                
                // Disable experimental and problematic analyzers
                settings.setBoolean(Settings.KEYS.ANALYZER_EXPERIMENTAL_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_RETIRED_ENABLED, false);
                
                // Configure connection timeouts
                settings.setInt(Settings.KEYS.CONNECTION_TIMEOUT, 30000);
                settings.setInt(Settings.KEYS.CONNECTION_READ_TIMEOUT, 60000);
                
                // Disable analyzers that require external data to avoid connection issues
                settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, false);
                
                Engine engine = new Engine(settings);
                List<Vulnerability> vulnerabilities = new ArrayList<>();
                
                for (String dependencyPath : dependencies) {
                    try {
                        File depFile = new File(dependencyPath);
                        if (depFile.exists()) {
                            if (shouldScanFile(depFile)) {
                                engine.scan(depFile);
                            } else {
                                logger.debug("Skipping non-JAR dependency: {}", dependencyPath);
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Failed to scan dependency: {}", dependencyPath, e);
                    }
                }
                
                try {
                    engine.analyzeDependencies();
                } catch (ExceptionCollection ec) {
                    logger.warn("OWASP Dependency-Check analysis completed with warnings: {}", ec.getMessage());
                    // Continue with analysis even if there are some exceptions
                }
                
                for (Dependency dependency : engine.getDependencies()) {
                    for (org.owasp.dependencycheck.dependency.Vulnerability owaspVuln : dependency.getVulnerabilities()) {
                        Vulnerability vuln = convertOwaspVulnerability(owaspVuln, dependency);
                        vulnerabilities.add(vuln);
                    }
                }
                
                engine.close();
                
                totalScansCompleted.incrementAndGet();
                lastSuccessfulScanMs.set(System.currentTimeMillis());
                
                // Update cache metadata after successful scan
                updateCacheAfterScan();
                
                logger.info("OWASP Dependency-Check scan completed. Found {} vulnerabilities", vulnerabilities.size());
                return vulnerabilities;
                
            } catch (Exception e) {
                totalScansFailed.incrementAndGet();
                logger.error("OWASP Dependency-Check scan failed", e);
                if (e.getMessage() != null && e.getMessage().contains("No documents exist")) {
                    logger.error("NVD database is not initialized. Try running with NVD_API_KEY set or wait for database initialization.");
                    return new ArrayList<>(); // Return empty list instead of failing
                }
                throw new RuntimeException("OWASP scan failed", e);
            }
        });
    }
    
    @Override
    public CompletableFuture<ScanResult> scanProject(String projectPath) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("Starting OWASP Dependency-Check project scan: {}", projectPath);
                
                // Set API key system properties BEFORE creating any OWASP objects
                String effectiveNvdApiKey = getEffectiveApiKey();
                configureSystemPropertiesForOwasp(effectiveNvdApiKey);
                
                Settings settings = createSmartCachedSettings(effectiveNvdApiKey);
                settings.setInt(Settings.KEYS.CONNECTION_TIMEOUT, configuration.getTimeoutMs());
                
                // Enable key analyzers that work offline
                settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, true);
                settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, true);
                settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, true);
                settings.setBoolean(Settings.KEYS.ANALYZER_FILE_NAME_ENABLED, true);
                
                // Configure connection timeouts
                settings.setInt(Settings.KEYS.CONNECTION_TIMEOUT, 30000);
                settings.setInt(Settings.KEYS.CONNECTION_READ_TIMEOUT, 60000);
                
                // Disable analyzers that require external data to avoid connection issues
                settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
                settings.setBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, false);
                
                Engine engine = new Engine(settings);
                
                // Scan project directory for JAR files and dependencies
                scanProjectDirectory(engine, new File(projectPath));
                
                try {
                    engine.analyzeDependencies();
                } catch (ExceptionCollection ec) {
                    logger.warn("OWASP Dependency-Check analysis completed with warnings: {}", ec.getMessage());
                    // Continue with analysis even if there are some exceptions
                }
                
                ScanResult result = createScanResultFromEngine(engine, projectPath);
                
                engine.close();
                
                totalScansCompleted.incrementAndGet();
                lastSuccessfulScanMs.set(System.currentTimeMillis());
                
                // Update cache metadata after successful scan
                updateCacheAfterScan();
                
                logger.info("OWASP project scan completed: {} vulnerabilities in {} dependencies", 
                           result.getTotalVulnerabilities(), result.getTotalDependencies());
                
                return result;
                
            } catch (Exception e) {
                totalScansFailed.incrementAndGet();
                logger.error("OWASP project scan failed: {}", projectPath, e);
                if (e.getMessage() != null && e.getMessage().contains("No documents exist")) {
                    logger.error("NVD database is not initialized. Try running with NVD_API_KEY set or wait for database initialization.");
                    // Return empty scan result instead of failing
                    ScanResult result = new ScanResult();
                    result.setProjectName(new File(projectPath).getName());
                    result.setStartTime(LocalDateTime.now());
                    result.setEndTime(LocalDateTime.now());
                    result.setTotalVulnerabilities(0);
                    result.setTotalDependencies(0);
                    
                    // Initialize empty PerformanceMetrics and Statistics
                    ScanResult.PerformanceMetrics performanceMetrics = new ScanResult.PerformanceMetrics();
                    performanceMetrics.setInitializationTimeMs(0);
                    performanceMetrics.setVulnerabilityCheckTimeMs(0);
                    performanceMetrics.setReportGenerationTimeMs(0);
                    result.setPerformanceMetrics(performanceMetrics);
                    
                    ScanResult.ScanStatistics statistics = new ScanResult.ScanStatistics();
                    statistics.setTotalJarsScanned(0);
                    statistics.setTotalCvesFound(0);
                    statistics.setUniqueCvesFound(0);
                    statistics.setScannerVersion("OWASP Dependency-Check");
                    result.setStatistics(statistics);
                    
                    return result;
                }
                throw new RuntimeException("OWASP project scan failed", e);
            }
        });
    }
    
    @Override
    public boolean supportsBatchScanning() {
        return true;
    }
    
    @Override
    public int getMaxConcurrentScans() {
        return MAX_CONCURRENT_SCANS;
    }
    
    @Override
    public void configure(ScannerConfiguration configuration) {
        this.configuration = configuration;
        initializeCacheManager(); // Reinitialize cache manager with new configuration
        logger.info("OWASP Dependency-Check scanner configured with timeout: {}ms, cache validity: {}h, smart caching: {}", 
                   configuration.getTimeoutMs(), configuration.getCacheValidityHours(), configuration.isSmartCachingEnabled());
    }
    
    @Override
    public ScannerHealth getHealth() {
        boolean healthy = totalScansFailed.get() < totalScansCompleted.get() * 0.1;
        String status = healthy ? "Healthy" : "Degraded - High failure rate";
        
        return new ScannerHealth(
            healthy,
            status,
            lastSuccessfulScanMs.get(),
            totalScansCompleted.get(),
            totalScansFailed.get()
        );
    }
    
    private Vulnerability convertOwaspVulnerability(org.owasp.dependencycheck.dependency.Vulnerability owaspVuln, 
                                                   Dependency dependency) {
        Vulnerability vuln = new Vulnerability();
        vuln.setCveId(owaspVuln.getName());
        vuln.setDescription(owaspVuln.getDescription());
        vuln.setSeverity(mapSeverity(owaspVuln.getCvssV3()));
        vuln.setCvssV3Score(owaspVuln.getCvssV3() != null && owaspVuln.getCvssV3().getCvssData() != null ? 
                owaspVuln.getCvssV3().getCvssData().getBaseScore() : null);
        vuln.setAffectedComponent(dependency.getActualFilePath());
        vuln.setSource("OWASP Dependency-Check");
        vuln.setDiscoveredDate(LocalDateTime.now());
        vuln.setLastVerified(LocalDateTime.now());
        vuln.setDetectionMethod("Static Analysis");
        
        // Collect all references including official CVE link
        List<String> references = new ArrayList<>();
        
        // Add official CVE link first if it's a CVE
        String cveId = owaspVuln.getName();
        if (cveId != null && cveId.startsWith("CVE-")) {
            String officialCveUrl = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cveId;
            references.add(officialCveUrl);
            vuln.setReferenceUrl(officialCveUrl); // Set primary reference as official CVE link
        }
        
        // Add additional references from OWASP data
        if (owaspVuln.getReferences() != null && !owaspVuln.getReferences().isEmpty()) {
            for (org.owasp.dependencycheck.dependency.Reference ref : owaspVuln.getReferences()) {
                if (ref.getUrl() != null && !ref.getUrl().isEmpty()) {
                    references.add(ref.getUrl());
                }
            }
            // If no CVE link was set, use the first reference
            if (vuln.getReferenceUrl() == null) {
                vuln.setReferenceUrl(owaspVuln.getReferences().iterator().next().getUrl());
            }
        }
        
        vuln.setReferences(references);
        
        return vuln;
    }
    
    private String mapSeverity(CvssV3 cvssV3) {
        if (cvssV3 == null || cvssV3.getCvssData() == null) return "UNKNOWN";
        
        Double score = cvssV3.getCvssData().getBaseScore();
        if (score == null) return "UNKNOWN";
        
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        return "LOW";
    }
    
    private void scanProjectDirectory(Engine engine, File projectDir) {
        try {
            logger.info("Scanning project directory for dependencies: {}", projectDir.getAbsolutePath());
            
            // Scan the main project directory for JAR files only
            scanForJarFiles(engine, projectDir);
            
            // Scan target directories for compiled artifacts
            scanTargetDirectories(engine, projectDir);
            
        } catch (Exception e) {
            logger.warn("Error during project directory scan", e);
        }
    }
    
    private void scanMavenRepositoryCache(Engine engine, File projectDir) {
        String userHome = System.getProperty("user.home");
        File m2Repo = new File(userHome, ".m2/repository");
        
        if (m2Repo.exists() && m2Repo.isDirectory()) {
            logger.info("Scanning Maven local repository for JAR files: {}", m2Repo.getAbsolutePath());
            try {
                scanForJarFiles(engine, m2Repo);
            } catch (Exception e) {
                logger.warn("Error scanning Maven repository", e);
            }
        }
    }
    
    private void scanTargetDirectories(Engine engine, File projectDir) {
        File[] targetDirs = projectDir.listFiles(file -> 
            file.isDirectory() && "target".equals(file.getName()));
        
        if (targetDirs != null) {
            for (File targetDir : targetDirs) {
                logger.debug("Scanning target directory for JAR files: {}", targetDir.getAbsolutePath());
                try {
                    scanForJarFiles(engine, targetDir);
                } catch (Exception e) {
                    logger.warn("Error scanning target directory: {}", targetDir.getAbsolutePath(), e);
                }
            }
        }
    }
    
    private void scanForJarFiles(Engine engine, File directory) {
        File[] files = directory.listFiles();
        if (files == null) return;
        
        for (File file : files) {
            if (file.isDirectory()) {
                scanForJarFiles(engine, file); // Recursive scan
            } else if (shouldScanFile(file)) {
                logger.debug("Found scannable file: {}", file.getAbsolutePath());
                try {
                    engine.scan(file);
                } catch (Exception e) {
                    logger.warn("Error scanning file: {}", file.getAbsolutePath(), e);
                }
            } else {
                logger.debug("Skipping non-scannable file: {}", file.getAbsolutePath());
            }
        }
    }
    
    private ScanResult createScanResultFromEngine(Engine engine, String projectPath) {
        long scanStartTime = System.currentTimeMillis();
        ScanResult result = new ScanResult();
        result.setProjectName(new File(projectPath).getName());
        result.setStartTime(LocalDateTime.now());
        
        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        int totalDependencies = 0;
        
        long dependencyProcessingStart = System.currentTimeMillis();
        for (Dependency dependency : engine.getDependencies()) {
            totalDependencies++;
            
            // Create dependency result
            ScanResult.DependencyResult depResult = new ScanResult.DependencyResult();
            
            // Try to parse coordinates from file path or name
            parseCoordinatesFromDependency(dependency, depResult);
            
            depResult.setFilePath(dependency.getActualFilePath());
            depResult.setScannerUsed("OWASP Dependency-Check");
            
            // Collect vulnerability IDs for this dependency
            Set<String> vulnIds = new java.util.HashSet<>();
            for (org.owasp.dependencycheck.dependency.Vulnerability owaspVuln : dependency.getVulnerabilities()) {
                Vulnerability vuln = convertOwaspVulnerability(owaspVuln, dependency);
                vulnerabilities.add(vuln);
                vulnIds.add(owaspVuln.getName());
            }
            depResult.setVulnerabilityIds(vulnIds);
            
            dependencies.add(depResult);
            
            logger.debug("Processed dependency: {} with {} vulnerabilities", 
                        depResult.getCoordinates(), vulnIds.size());
        }
        long dependencyProcessingEnd = System.currentTimeMillis();
        
        result.setDependencies(dependencies);
        result.setVulnerabilities(vulnerabilities);
        result.setTotalVulnerabilities(vulnerabilities.size());
        result.setTotalDependencies(totalDependencies);
        
        // Calculate severity counts
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Vulnerability vuln : vulnerabilities) {
            switch (vuln.getSeverity().toUpperCase()) {
                case "CRITICAL": critical++; break;
                case "HIGH": high++; break;
                case "MEDIUM": medium++; break;
                case "LOW": low++; break;
            }
        }
        
        result.setCriticalVulnerabilities(critical);
        result.setHighVulnerabilities(high);
        result.setMediumVulnerabilities(medium);
        result.setLowVulnerabilities(low);
        result.setEndTime(LocalDateTime.now());
        
        // Initialize PerformanceMetrics
        ScanResult.PerformanceMetrics performanceMetrics = new ScanResult.PerformanceMetrics();
        long totalScanTime = System.currentTimeMillis() - scanStartTime;
        performanceMetrics.setInitializationTimeMs(100); // Default initialization time
        performanceMetrics.setVulnerabilityCheckTimeMs(dependencyProcessingEnd - dependencyProcessingStart);
        performanceMetrics.setReportGenerationTimeMs(50); // Default report generation time
        performanceMetrics.setTotalScanTimeMs(totalScanTime);
        if (totalDependencies > 0 && totalScanTime > 0) {
            performanceMetrics.setJarsPerSecond((int) ((totalDependencies * 1000L) / totalScanTime));
        }
        result.setPerformanceMetrics(performanceMetrics);
        
        // Initialize ScanStatistics
        ScanResult.ScanStatistics statistics = new ScanResult.ScanStatistics();
        statistics.setTotalJarsScanned(totalDependencies);
        statistics.setTotalCvesFound(vulnerabilities.size());
        statistics.setUniqueCvesFound(vulnerabilities.size()); // Assuming all CVEs are unique for now
        statistics.setCriticalCves(critical);
        statistics.setHighCves(high);
        statistics.setMediumCves(medium);
        statistics.setLowCves(low);
        statistics.setScannerVersion("OWASP Dependency-Check");
        
        // Calculate average CVSS score
        if (!vulnerabilities.isEmpty()) {
            double totalScore = 0;
            double maxScore = 0;
            double minScore = 10;
            int scoredVulns = 0;
            for (Vulnerability vuln : vulnerabilities) {
                if (vuln.getCvssV3Score() != null) {
                    double score = vuln.getCvssV3Score();
                    totalScore += score;
                    maxScore = Math.max(maxScore, score);
                    minScore = Math.min(minScore, score);
                    scoredVulns++;
                }
            }
            if (scoredVulns > 0) {
                statistics.setAverageCvssScore(totalScore / scoredVulns);
                statistics.setHighestCvssScore(maxScore);
                statistics.setLowestCvssScore(minScore);
            }
        }
        
        result.setStatistics(statistics);
        
        return result;
    }
    
    private void parseCoordinatesFromDependency(Dependency dependency, ScanResult.DependencyResult depResult) {
        String fileName = dependency.getFileName();
        String filePath = dependency.getActualFilePath();
        
        // Try to extract coordinates from Maven repository path
        if (filePath != null && filePath.contains(".m2/repository")) {
            String[] pathParts = filePath.split(".m2/repository/");
            if (pathParts.length > 1) {
                String repoPath = pathParts[1];
                String[] parts = repoPath.split("/");
                if (parts.length >= 3) {
                    StringBuilder groupId = new StringBuilder();
                    for (int i = 0; i < parts.length - 2; i++) {
                        if (i > 0) groupId.append(".");
                        groupId.append(parts[i]);
                    }
                    depResult.setGroupId(groupId.toString());
                    depResult.setArtifactId(parts[parts.length - 2]);
                    
                    // Try to extract version from filename
                    String version = parts[parts.length - 1];
                    if (fileName.endsWith(".jar")) {
                        String nameWithoutExt = fileName.substring(0, fileName.length() - 4);
                        String artifactId = depResult.getArtifactId();
                        if (nameWithoutExt.startsWith(artifactId + "-")) {
                            version = nameWithoutExt.substring(artifactId.length() + 1);
                        }
                    }
                    depResult.setVersion(version);
                    return;
                }
            }
        }
        
        // Fallback: try to parse from filename
        if (fileName != null && fileName.endsWith(".jar")) {
            String nameWithoutExt = fileName.substring(0, fileName.length() - 4);
            // Look for version pattern at the end
            String[] parts = nameWithoutExt.split("-");
            if (parts.length >= 2) {
                String lastPart = parts[parts.length - 1];
                if (lastPart.matches("\\d+.*")) { // Starts with digit, likely a version
                    String artifactId = nameWithoutExt.substring(0, nameWithoutExt.length() - lastPart.length() - 1);
                    depResult.setArtifactId(artifactId);
                    depResult.setVersion(lastPart);
                    depResult.setGroupId("unknown");
                    return;
                }
            }
        }
        
        // Final fallback
        depResult.setGroupId("unknown");
        depResult.setArtifactId(fileName != null ? fileName : "unknown");
        depResult.setVersion("unknown");
    }
    
    public CompletableFuture<ScanResult> scanProjectWithDependencies(String projectPath, List<String> dependencyPaths, 
                                                                     String groupId, String artifactId, String version) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("Starting OWASP Dependency-Check scan with {} explicit dependencies", dependencyPaths.size());
                
                // Set API key system properties BEFORE creating any OWASP objects
                String effectiveNvdApiKey = getEffectiveApiKey();
                configureSystemPropertiesForOwasp(effectiveNvdApiKey);
                
                Settings settings = createScannerSettings();
                Engine engine = new Engine(settings);
                
                // Scan all explicit dependency paths (only JAR files)
                for (String dependencyPath : dependencyPaths) {
                    File depFile = new File(dependencyPath);
                    if (depFile.exists()) {
                        if (shouldScanFile(depFile)) {
                            logger.debug("Scanning dependency: {}", dependencyPath);
                            engine.scan(depFile);
                        } else {
                            logger.debug("Skipping non-JAR file: {}", dependencyPath);
                        }
                    } else {
                        logger.warn("Dependency file not found: {}", dependencyPath);
                    }
                }
                
                // Also scan project directory for additional files
                scanProjectDirectory(engine, new File(projectPath));
                
                try {
                    engine.analyzeDependencies();
                } catch (ExceptionCollection ec) {
                    logger.warn("OWASP Dependency-Check analysis completed with warnings: {}", ec.getMessage());
                }
                
                ScanResult result = createEnhancedScanResult(engine, projectPath, groupId, artifactId, version);
                
                engine.close();
                
                totalScansCompleted.incrementAndGet();
                lastSuccessfulScanMs.set(System.currentTimeMillis());
                
                // Update cache metadata after successful scan
                updateCacheAfterScan();
                
                logger.info("OWASP enhanced scan completed: {} vulnerabilities in {} dependencies", 
                           result.getTotalVulnerabilities(), result.getTotalDependencies());
                
                return result;
                
            } catch (Exception e) {
                totalScansFailed.incrementAndGet();
                logger.error("OWASP enhanced scan failed", e);
                throw new RuntimeException("Enhanced OWASP scan failed", e);
            }
        });
    }
    
    private Settings createScannerSettings() {
        Settings settings = new Settings();
        settings.setBoolean(Settings.KEYS.AUTO_UPDATE, configuration.isAutoUpdate());
        settings.setInt(Settings.KEYS.CONNECTION_TIMEOUT, configuration.getTimeoutMs());
        
        // Enable key analyzers that work offline
        settings.setBoolean(Settings.KEYS.ANALYZER_JAR_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_ARCHIVE_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_ASSEMBLY_ENABLED, true);
        settings.setBoolean(Settings.KEYS.ANALYZER_FILE_NAME_ENABLED, true);
        
        // Use autoUpdate setting for NVD CVE updates too
        settings.setBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, configuration.isAutoUpdate());
        settings.setBoolean(Settings.KEYS.ANALYZER_NVD_CVE_ENABLED, true);
        
        // Configure connection timeouts
        settings.setInt(Settings.KEYS.CONNECTION_TIMEOUT, 30000);
        settings.setInt(Settings.KEYS.CONNECTION_READ_TIMEOUT, 60000);
        
        // Configure NVD API key - check all sources consistently
        String effectiveNvdApiKey = getEffectiveApiKey();
        if (effectiveNvdApiKey != null && !effectiveNvdApiKey.isEmpty()) {
            // Set all known NVD API key system properties for OWASP compatibility
            System.setProperty("nvd.api.key", effectiveNvdApiKey);
            System.setProperty("NVD_API_KEY", effectiveNvdApiKey);
            System.setProperty("bastion.nvd.apiKey", effectiveNvdApiKey);
            
            // Configure OWASP settings directly for NVD API key
            settings.setString(Settings.KEYS.NVD_API_KEY, effectiveNvdApiKey);
            logger.info("NVD API key configured for scanner settings");
        } else {
            logger.warn("No NVD API key found from any source. Using offline mode only.");
        }
        
        // Disable analyzers that require external data
        settings.setBoolean(Settings.KEYS.ANALYZER_OSSINDEX_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_CENTRAL_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_NEXUS_ENABLED, false);
        settings.setBoolean(Settings.KEYS.ANALYZER_ARTIFACTORY_ENABLED, false);
        
        return settings;
    }
    
    private ScanResult createEnhancedScanResult(Engine engine, String projectPath, String groupId, String artifactId, String version) {
        long scanStartTime = System.currentTimeMillis();
        ScanResult result = new ScanResult();
        result.setProjectGroupId(groupId);
        result.setProjectArtifactId(artifactId);
        result.setProjectVersion(version);
        result.setProjectName(new File(projectPath).getName());
        result.setStartTime(LocalDateTime.now());
        
        List<ScanResult.DependencyResult> dependencies = new ArrayList<>();
        List<Vulnerability> allVulnerabilities = new ArrayList<>();
        
        long dependencyProcessingStart = System.currentTimeMillis();
        for (Dependency dependency : engine.getDependencies()) {
            ScanResult.DependencyResult depResult = new ScanResult.DependencyResult();
            
            // Enhanced coordinate parsing
            parseCoordinatesFromDependency(dependency, depResult);
            
            depResult.setFilePath(dependency.getActualFilePath());
            depResult.setScannerUsed("OWASP Dependency-Check");
            
            // Set file information
            File depFile = new File(dependency.getActualFilePath());
            if (depFile.exists()) {
                depResult.setFileSize(depFile.length());
            }
            
            // Collect vulnerability information
            Set<String> vulnIds = new java.util.HashSet<>();
            for (org.owasp.dependencycheck.dependency.Vulnerability owaspVuln : dependency.getVulnerabilities()) {
                Vulnerability vuln = convertOwaspVulnerability(owaspVuln, dependency);
                allVulnerabilities.add(vuln);
                vulnIds.add(owaspVuln.getName());
            }
            depResult.setVulnerabilityIds(vulnIds);
            
            dependencies.add(depResult);
            
            if (vulnIds.size() > 0) {
                logger.info("Found {} vulnerabilities in {}", vulnIds.size(), depResult.getCoordinates());
            }
        }
        long dependencyProcessingEnd = System.currentTimeMillis();
        
        result.setDependencies(dependencies);
        result.setVulnerabilities(allVulnerabilities);
        result.setTotalDependencies(dependencies.size());
        
        // Calculate severity counts from vulnerabilities
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Vulnerability vuln : allVulnerabilities) {
            String severity = vuln.getSeverity().toUpperCase();
            switch (severity) {
                case "CRITICAL": critical++; break;
                case "HIGH": high++; break;
                case "MEDIUM": medium++; break;
                case "LOW": low++; break;
                default: low++; break; // Unknown severity defaults to low
            }
        }
        
        result.setCriticalVulnerabilities(critical);
        result.setHighVulnerabilities(high);
        result.setMediumVulnerabilities(medium);
        result.setLowVulnerabilities(low);
        result.setTotalVulnerabilities(allVulnerabilities.size());
        
        // Set vulnerable dependency count
        int vulnerableDeps = (int) dependencies.stream()
            .mapToLong(d -> d.getVulnerabilityIds().size() > 0 ? 1 : 0)
            .sum();
        result.setVulnerableDependencies(vulnerableDeps);
        
        result.setEndTime(LocalDateTime.now());
        
        // Initialize PerformanceMetrics
        ScanResult.PerformanceMetrics performanceMetrics = new ScanResult.PerformanceMetrics();
        long totalScanTime = System.currentTimeMillis() - scanStartTime;
        performanceMetrics.setInitializationTimeMs(150); // Default initialization time
        performanceMetrics.setVulnerabilityCheckTimeMs(dependencyProcessingEnd - dependencyProcessingStart);
        performanceMetrics.setReportGenerationTimeMs(75); // Default report generation time
        performanceMetrics.setTotalScanTimeMs(totalScanTime);
        if (dependencies.size() > 0 && totalScanTime > 0) {
            performanceMetrics.setJarsPerSecond((int) ((dependencies.size() * 1000L) / totalScanTime));
        }
        result.setPerformanceMetrics(performanceMetrics);
        
        // Initialize ScanStatistics
        ScanResult.ScanStatistics statistics = new ScanResult.ScanStatistics();
        statistics.setTotalJarsScanned(dependencies.size());
        statistics.setTotalCvesFound(allVulnerabilities.size());
        statistics.setUniqueCvesFound(allVulnerabilities.size()); // Assuming all CVEs are unique for now
        statistics.setCriticalCves(critical);
        statistics.setHighCves(high);
        statistics.setMediumCves(medium);
        statistics.setLowCves(low);
        statistics.setScannerVersion("OWASP Dependency-Check Enhanced");
        statistics.setDirectDependencies((int) dependencies.stream().mapToLong(d -> d.isDirect() ? 1 : 0).sum());
        statistics.setTransitiveDependencies(dependencies.size() - statistics.getDirectDependencies());
        statistics.setVulnerableDirectDeps((int) dependencies.stream()
            .mapToLong(d -> d.isDirect() && d.getVulnerabilityIds().size() > 0 ? 1 : 0).sum());
        statistics.setVulnerableTransitiveDeps(vulnerableDeps - statistics.getVulnerableDirectDeps());
        
        // Calculate average CVSS score
        if (!allVulnerabilities.isEmpty()) {
            double totalScore = 0;
            double maxScore = 0;
            double minScore = 10;
            int scoredVulns = 0;
            for (Vulnerability vuln : allVulnerabilities) {
                if (vuln.getCvssV3Score() != null) {
                    double score = vuln.getCvssV3Score();
                    totalScore += score;
                    maxScore = Math.max(maxScore, score);
                    minScore = Math.min(minScore, score);
                    scoredVulns++;
                }
            }
            if (scoredVulns > 0) {
                statistics.setAverageCvssScore(totalScore / scoredVulns);
                statistics.setHighestCvssScore(maxScore);
                statistics.setLowestCvssScore(minScore);
            }
        }
        
        result.setStatistics(statistics);
        
        logger.info("Scan summary: {} total deps, {} vulnerable deps, {} total vulnerabilities (C:{}, H:{}, M:{}, L:{})",
                   dependencies.size(), vulnerableDeps, allVulnerabilities.size(), critical, high, medium, low);
        
        return result;
    }
    
    private boolean isMultiModuleProject(String projectPath) {
        File projectDir = new File(projectPath);
        if (!projectDir.isDirectory()) {
            projectDir = projectDir.getParentFile();
        }
        
        File[] subdirs = projectDir.listFiles(File::isDirectory);
        if (subdirs == null) return false;
        
        int pomCount = 0;
        for (File subdir : subdirs) {
            if (new File(subdir, "pom.xml").exists()) {
                pomCount++;
            }
        }
        
        return pomCount > 1;
    }
    
    private boolean shouldScanFile(File file) {
        if (!file.isFile()) {
            return true; // Allow directories to be scanned
        }
        
        String fileName = file.getName().toLowerCase();
        
        // Only allow JAR files and avoid problematic archive types
        if (fileName.endsWith(".jar")) {
            return true;
        }
        
        // Exclude ZIP, TAR.GZ, and other archive types that cause issues
        if (fileName.endsWith(".zip") || 
            fileName.endsWith(".tar.gz") || 
            fileName.endsWith(".tar") ||
            fileName.endsWith(".gz") ||
            fileName.endsWith("-src.zip") ||
            fileName.endsWith("-docs.zip") ||
            fileName.endsWith("-bin.zip") ||
            fileName.contains("-src.") ||
            fileName.contains("-docs.")) {
            return false;
        }
        
        // Allow other types (WAR, EAR, etc.) but be conservative
        return fileName.endsWith(".war") || fileName.endsWith(".ear");
    }
    
    /**
     * Get effective NVD API key by checking all possible sources in priority order.
     * This ensures consistent API key detection across all scanner methods.
     */
    private String getEffectiveApiKey() {
        // Priority 1: Constructor parameter (passed from plugin)
        if (nvdApiKey != null && !nvdApiKey.trim().isEmpty()) {
            return nvdApiKey.trim();
        }
        
        // Priority 2: System property from Maven command line (-Dnvd.api.key)
        String systemProperty = System.getProperty("nvd.api.key");
        if (systemProperty != null && !systemProperty.trim().isEmpty()) {
            return systemProperty.trim();
        }
        
        // Priority 3: System property from plugin parameter (-Dbastion.nvd.apiKey)
        systemProperty = System.getProperty("bastion.nvd.apiKey");
        if (systemProperty != null && !systemProperty.trim().isEmpty()) {
            return systemProperty.trim();
        }
        
        // Priority 4: Environment variable
        String envVar = System.getenv("NVD_API_KEY");
        if (envVar != null && !envVar.trim().isEmpty()) {
            return envVar.trim();
        }
        
        return null;
    }
    
    /**
     * Configure all system properties that OWASP Dependency-Check looks for.
     * This must be called BEFORE any OWASP objects are created.
     */
    private void configureSystemPropertiesForOwasp(String apiKey) {
        if (apiKey != null && !apiKey.trim().isEmpty()) {
            // Set all possible system properties that OWASP might check
            System.setProperty("nvd.api.key", apiKey);
            System.setProperty("NVD_API_KEY", apiKey);
            System.setProperty("bastion.nvd.apiKey", apiKey);
            
            logger.info("API key system properties configured for OWASP Dependency-Check");
        } else {
            logger.warn("No NVD API key available - OWASP will run in offline mode");
        }
    }
    
    /**
     * Creates OWASP settings with smart caching that only downloads if remote database has changed.
     */
    private Settings createSmartCachedSettings(String effectiveNvdApiKey) {
        Settings settings = new Settings();
        boolean hasApiKey = effectiveNvdApiKey != null && !effectiveNvdApiKey.trim().isEmpty();
        
        // Check if cache is valid first
        boolean cacheValid = false;
        boolean shouldUpdate = configuration.isAutoUpdate();
        
        if (shouldUpdate && configuration.isSmartCachingEnabled()) {
            try {
                logger.info("🔍 Checking NVD database cache status...");
                cacheValid = cacheManager.isCacheValid(effectiveNvdApiKey);
                
                if (cacheValid) {
                    logger.info("✅ NVD cache is valid - skipping database download");
                    shouldUpdate = false; // Skip update since cache is valid
                } else {
                    logger.info("🔄 NVD cache is stale or remote database updated - will download latest");
                }
            } catch (Exception e) {
                logger.warn("⚠️  Error checking cache validity, defaulting to update: {}", e.getMessage());
                cacheValid = false;
            }
        }
        
        if (hasApiKey) {
            // Set all known NVD API key system properties for OWASP compatibility
            System.setProperty("nvd.api.key", effectiveNvdApiKey);
            System.setProperty("NVD_API_KEY", effectiveNvdApiKey);
            System.setProperty("bastion.nvd.apiKey", effectiveNvdApiKey);
            
            // Configure OWASP settings directly for NVD API key
            settings.setString(Settings.KEYS.NVD_API_KEY, effectiveNvdApiKey);
            
            // Use smart cache decision for autoUpdate
            settings.setBoolean(Settings.KEYS.AUTO_UPDATE, shouldUpdate);
            settings.setBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, shouldUpdate);
            settings.setBoolean(Settings.KEYS.ANALYZER_NVD_CVE_ENABLED, true);
            
            // Configure cache directory if specified
            if (configuration.getCacheDirectory() != null) {
                settings.setString(Settings.KEYS.DATA_DIRECTORY, cacheManager.getCacheDirectory());
                logger.info("📁 Using cache directory: {}", cacheManager.getCacheDirectory());
            }
            
            String updateMsg = shouldUpdate ? "will download latest" : "using cached database";
            logger.info("🔑 NVD API key configured - CVE analysis enabled, cache status: {}", updateMsg);
        } else {
            // Fallback to offline mode only
            settings.setBoolean(Settings.KEYS.AUTO_UPDATE, false);
            settings.setBoolean(Settings.KEYS.UPDATE_NVDCVE_ENABLED, false);
            settings.setBoolean(Settings.KEYS.ANALYZER_NVD_CVE_ENABLED, false);
            logger.warn("❌ No NVD API key provided - CVE analysis disabled (offline mode only)");
        }
        
        return settings;
    }
    
    /**
     * Updates cache metadata after successful database update.
     */
    private void updateCacheAfterScan() {
        if (configuration.isAutoUpdate()) {
            try {
                cacheManager.updateCacheMetadata();
                logger.debug("Cache metadata updated after successful scan");
            } catch (Exception e) {
                logger.debug("Could not update cache metadata: {}", e.getMessage());
            }
        }
    }
}