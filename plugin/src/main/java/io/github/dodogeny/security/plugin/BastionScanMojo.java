package io.github.dodogeny.security.plugin;

import io.github.dodogeny.security.database.VulnerabilityDatabase;
import io.github.dodogeny.security.database.InMemoryVulnerabilityDatabase;
import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.ScanResult.ScanStatistics;
import io.github.dodogeny.security.model.ScanResult.PerformanceMetrics;
import io.github.dodogeny.security.report.ReportGenerator;
import io.github.dodogeny.security.scanner.OwaspDependencyCheckScanner;
import io.github.dodogeny.security.scanner.VulnerabilityScanner;
import org.apache.commons.lang3.StringUtils;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.HashSet;
import java.util.Set;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

@Mojo(name = "scan", 
      defaultPhase = LifecyclePhase.VERIFY,
      requiresDependencyResolution = ResolutionScope.COMPILE_PLUS_RUNTIME,
      threadSafe = true)
public class BastionScanMojo extends AbstractMojo {
    
    private static final Logger logger = LoggerFactory.getLogger(BastionScanMojo.class);

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    private MavenSession session;

    @Parameter(property = "bastion.skip", defaultValue = "false")
    private boolean skip;

    @Parameter(property = "bastion.failOnError", defaultValue = "true")
    private boolean failOnError;

    @Parameter(property = "bastion.outputDirectory", defaultValue = "${project.build.directory}/bastion-reports")
    private File outputDirectory;

    @Parameter(property = "bastion.reportFormats", defaultValue = "HTML,JSON")
    private String reportFormats;

    @Parameter(property = "bastion.severityThreshold", defaultValue = "MEDIUM")
    private String severityThreshold;

    @Parameter(property = "bastion.database.url")
    private String databaseUrl;

    @Parameter(property = "bastion.database.username")
    private String databaseUsername;

    @Parameter(property = "bastion.database.password")
    private String databasePassword;


    @Parameter(property = "bastion.scanner.timeout", defaultValue = "300000")
    private int scannerTimeout;

    @Parameter(property = "bastion.enableMultiModule", defaultValue = "true")
    private boolean enableMultiModule;


    @Parameter(property = "bastion.purge.force", defaultValue = "false")
    private boolean force;

    @Parameter(property = "bastion.purge.confirm", defaultValue = "false")
    private boolean confirmPurge;

    @Parameter(property = "bastion.purge.projectOnly", defaultValue = "false")
    private boolean projectOnly;

    @Parameter(property = "bastion.purge.olderThanDays", defaultValue = "0")
    private int olderThanDays;

    @Parameter(property = "bastion.purge.dryRun", defaultValue = "false")
    private boolean dryRun;

    @Parameter(property = "bastion.purgeBeforeScan", defaultValue = "false")
    private boolean purgeBeforeScan;

    @Parameter(property = "bastion.storage.useJsonFile", defaultValue = "false")
    private boolean useJsonFileStorage;

    @Parameter(property = "bastion.storage.jsonFilePath", defaultValue = "${project.build.directory}/bastion-vulnerabilities.json")
    private String jsonFilePath;

    @Parameter(property = "bastion.nvd.apiKey")
    private String nvdApiKey;

    @Parameter(property = "bastion.community.storageMode", defaultValue = "IN_MEMORY")
    private String communityStorageMode;

    @Parameter(property = "bastion.useOwaspPlugin", defaultValue = "true")
    private boolean useOwaspPlugin;

    @Parameter(property = "bastion.owaspVersion", defaultValue = "12.1.3")
    private String owaspVersion;

    @Parameter(property = "bastion.owaspReportPath", defaultValue = "${project.build.directory}/dependency-check-report.json")
    private String owaspReportPath;

    private VulnerabilityDatabase database;
    private InMemoryVulnerabilityDatabase inMemoryDatabase;
    private VulnerabilityScanner scanner;
    private ReportGenerator reportGenerator;
    private ObjectMapper jsonMapper;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (skip) {
            getLog().info("Bastion scan skipped by configuration");
            return;
        }

        try {
            getLog().info("🛡️  Starting Bastion vulnerability scan (Community Edition)...");
            getLog().info("Project: " + project.getName());
            getLog().info("Multi-module enabled: " + enableMultiModule);
            getLog().info("📢 Running Community Edition - For additional features, upgrade to bastion-maven-plugin-enterprise");
            getLog().info("💾 Storage mode: " + communityStorageMode.toUpperCase().replace("_", " "));

            validateStorageConfiguration();
            initialize();
            
            if (purgeBeforeScan) {
                performPurgeBeforeScan();
            }
            
            ScanResult result = performScan();
            generateReports(result);
            storeResults(result);
            
            displayScanStatistics(result);
            handleScanResults(result);

        } catch (Exception e) {
            getLog().error("Bastion scan failed", e);
            if (failOnError) {
                throw new MojoExecutionException("Vulnerability scan failed", e);
            }
        } finally {
            cleanup();
        }
    }


    private void validateStorageConfiguration() throws MojoExecutionException {
        if (useJsonFileStorage) {
            getLog().info("📄 JSON file storage enabled - database options will be disabled");
            
            if (StringUtils.isNotBlank(databaseUrl)) {
                getLog().warn("⚠️  Database URL specified but JSON storage is enabled - database will be ignored");
            }
            
            if (StringUtils.isBlank(jsonFilePath)) {
                throw new MojoExecutionException("JSON file path must be specified when useJsonFileStorage is true");
            }
        } else {
            getLog().info("🗃️  Database storage enabled");
        }

        // Validate community edition storage mode
        if (!isValidCommunityStorageMode(communityStorageMode)) {
            throw new MojoExecutionException("Invalid community storage mode: " + communityStorageMode + 
                ". Valid options are: IN_MEMORY, JSON_FILE");
        }
    }

    private boolean isValidCommunityStorageMode(String mode) {
        return "IN_MEMORY".equalsIgnoreCase(mode) || "JSON_FILE".equalsIgnoreCase(mode);
    }

    private void initialize() throws MojoExecutionException {
        try {
            getLog().info("Initializing Bastion components...");

            // Handle storage initialization for community edition
            if (useJsonFileStorage) {
                initializeJsonMapper();
            } else {
                initializeCommunityStorage();
            }
            
            initializeScanner();
            initializeReportGenerator();

            if (!outputDirectory.exists()) {
                outputDirectory.mkdirs();
            }

        } catch (Exception e) {
            throw new MojoExecutionException("Failed to initialize Bastion components", e);
        }
    }

    private void initializeCommunityStorage() throws Exception {
        if ("JSON_FILE".equalsIgnoreCase(communityStorageMode)) {
            getLog().info("🆓 Community Edition: Using JSON file storage");
            initializeJsonMapper();
            // Force JSON file storage mode
            useJsonFileStorage = true;
        } else {
            getLog().info("🆓 Community Edition: Using in-memory database");
            initializeInMemoryDatabase();
        }
    }

    private void initializeJsonMapper() {
        jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new JavaTimeModule());
        jsonMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        jsonMapper.enable(SerializationFeature.INDENT_OUTPUT);
        getLog().info("JSON mapper initialized for file storage");
    }

    private void initializeInMemoryDatabase() throws Exception {
        getLog().info("🗃️  Initializing in-memory database for community edition");
        
        // Create the InMemoryVulnerabilityDatabase
        inMemoryDatabase = new InMemoryVulnerabilityDatabase(LoggerFactory.getLogger(InMemoryVulnerabilityDatabase.class));
        getLog().info("✅ In-memory database initialized successfully");
    }

    private void initializeDatabase() throws SQLException {
        VulnerabilityDatabase.DatabaseConfig config = new VulnerabilityDatabase.DatabaseConfig();
        
        if (StringUtils.isNotBlank(databaseUrl)) {
            getLog().info("Using external database: " + databaseUrl);
            if (databaseUrl.startsWith("jdbc:postgresql:")) {
                config.setType("postgresql");
                config.setUrl(databaseUrl);
                config.setUsername(databaseUsername);
                config.setPassword(databasePassword);
            } else if (databaseUrl.startsWith("jdbc:mysql:")) {
                config.setType("mysql");
                config.setUrl(databaseUrl);
                config.setUsername(databaseUsername);
                config.setPassword(databasePassword);
            } else if (databaseUrl.startsWith("jdbc:h2:")) {
                config.setType("h2");
                config.setPath(databaseUrl.substring("jdbc:h2:".length()));
            }
            database = new VulnerabilityDatabase(config, LoggerFactory.getLogger(VulnerabilityDatabase.class));
        } else {
            String h2Path = project.getBuild().getDirectory() + "/bastion-db/vulnerabilities";
            getLog().info("Using H2 database: " + h2Path);
            config.setType("h2");
            config.setPath(h2Path);
            database = new VulnerabilityDatabase(config, LoggerFactory.getLogger(VulnerabilityDatabase.class));
        }
    }

    private void initializeScanner() {
        // Check multiple sources for NVD API key
        String apiKey = nvdApiKey;
        String keySource = "plugin parameter";
        
        if (apiKey == null || apiKey.trim().isEmpty()) {
            // Try common system properties
            apiKey = System.getProperty("nvd.api.key");
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                keySource = "system property 'nvd.api.key'";
            }
        }
        
        if (apiKey == null || apiKey.trim().isEmpty()) {
            apiKey = System.getProperty("bastion.nvd.apiKey");
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                keySource = "system property 'bastion.nvd.apiKey'";
            }
        }
        
        if (apiKey == null || apiKey.trim().isEmpty()) {
            // Try environment variables
            apiKey = System.getenv("NVD_API_KEY");
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                keySource = "environment variable 'NVD_API_KEY'";
            }
        }
        
        if (apiKey != null && !apiKey.trim().isEmpty()) {
            scanner = new OwaspDependencyCheckScanner(apiKey.trim());
            getLog().info("NVD API key loaded from " + keySource);
        } else {
            scanner = new OwaspDependencyCheckScanner();
            getLog().info("No NVD API key found - using offline mode only");
        }
        
        VulnerabilityScanner.ScannerConfiguration config = new VulnerabilityScanner.ScannerConfiguration();
        config.setTimeoutMs(scannerTimeout);
        config.setSeverityThreshold(severityThreshold);
        config.setEnableCache(true);
        config.setAutoUpdate(true); // Always enable auto-update for latest NVD data

        scanner.configure(config);
        getLog().info("Scanner initialized: " + scanner.getName());
    }

    private void initializeReportGenerator() {
        reportGenerator = new ReportGenerator();
        getLog().info("Report generator initialized");
    }


    private ScanResult performScan() throws Exception {
        getLog().info("Scanning project dependencies...");

        // Check if hybrid mode is enabled (default: true)
        getLog().info("🔧 useOwaspPlugin parameter value: " + useOwaspPlugin);
        if (useOwaspPlugin) {
            getLog().info("🔀 Hybrid mode ENABLED - using official OWASP plugin for scanning");
            return performHybridScan();
        } else {
            getLog().info("🔀 Hybrid mode DISABLED - using direct OWASP Engine API");
            return performDirectScan();
        }
    }

    /**
     * Hybrid approach: Invoke OWASP plugin -> Parse JSON -> Convert to Bastion format
     */
    private ScanResult performHybridScan() throws Exception {
        // Pre-flight check: Ensure NVD database is initialized (first-time only)
        if (!isNvdDatabaseInitialized()) {
            getLog().info("🔧 First-time setup: Initializing NVD database...");
            initializeNvdDatabase();
        }

        // Step 1: Invoke OWASP plugin to generate JSON report
        // OWASP will automatically check for and download updates with autoUpdate=true
        File owaspReport = invokeOwaspPlugin();

        // Step 2: Parse OWASP JSON report
        Map<String, Object> owaspData = parseOwaspJsonReport(owaspReport);

        // Step 3: Convert OWASP data to Bastion format
        ScanResult result = convertOwaspToBastion(owaspData);

        getLog().info("✅ Hybrid scan completed successfully!");
        getLog().info("📊 Total vulnerabilities found: " + result.getTotalVulnerabilities());
        getLog().info("📦 Total dependencies scanned: " + result.getTotalDependencies());

        return result;
    }

    /**
     * Direct approach: Use OWASP Engine API directly (legacy mode)
     */
    private ScanResult performDirectScan() throws Exception {
        // Collect all dependency paths from Maven
        List<String> dependencyPaths = collectDependencyPaths();
        getLog().info("Found " + dependencyPaths.size() + " dependency paths to scan");

        CompletableFuture<ScanResult> scanFuture;

        if (enableMultiModule && isMultiModuleProject()) {
            getLog().info("Multi-module project detected");
            scanFuture = scanWithDependencies(session.getTopLevelProject().getBasedir().getAbsolutePath(), dependencyPaths);
        } else {
            scanFuture = scanWithDependencies(project.getBasedir().getAbsolutePath(), dependencyPaths);
        }

        ScanResult result = scanFuture.get();

        getLog().info("Scan completed successfully!");
        getLog().info("Total vulnerabilities found: " + result.getTotalVulnerabilities());
        getLog().info("Total dependencies scanned: " + result.getTotalDependencies());

        return result;
    }

    private void generateReports(ScanResult result) {
        getLog().info("Generating reports...");
        
        // Add trend data if available
        if (useJsonFileStorage) {
            addTrendDataFromJson(result);
        } else if (inMemoryDatabase != null) {
            addTrendDataFromInMemory(result);
        }
        
        List<String> formats = Arrays.asList(reportFormats.split(","));
        
        for (String format : formats) {
            try {
                String cleanFormat = format.trim().toUpperCase();
                ReportGenerator.ReportFormat reportFormat = ReportGenerator.ReportFormat.valueOf(cleanFormat);
                
                // Check if advanced formats require enterprise version
                if (isAdvancedReportFormat(reportFormat)) {
                    getLog().warn("⚠️  " + cleanFormat + " reports require bastion-maven-plugin-enterprise - skipping (Community Edition supports HTML/JSON only)");
                    continue;
                }
                
                String fileName = String.format("bastion-report-%s.%s", 
                    project.getArtifactId(), 
                    cleanFormat.toLowerCase());
                File reportFile = new File(outputDirectory, fileName);
                
                reportGenerator.generateReport(result, reportFormat, reportFile.getAbsolutePath());
                
                getLog().info("Generated " + cleanFormat + " report (Community): " + reportFile.getAbsolutePath());
                
            } catch (Exception e) {
                getLog().warn("Failed to generate " + format + " report", e);
            }
        }
        
        // Generate dedicated trend report
        generateTrendReport(result);
    }
    
    private void generateTrendReport(ScanResult result) {
        try {
            getLog().info("📈 Generating dedicated trend analysis report...");
            
            String fileName = String.format("bastion-trend-report-%s.html", project.getArtifactId());
            File trendReportFile = new File(outputDirectory, fileName);
            
            reportGenerator.generateTrendReport(result, trendReportFile.getAbsolutePath());
            
            getLog().info("Generated TREND report (Community): " + trendReportFile.getAbsolutePath());
            
        } catch (Exception e) {
            getLog().warn("Failed to generate trend analysis report", e);
        }
    }

    private void addTrendDataFromJson(ScanResult result) {
        try {
            Path jsonPath = Paths.get(jsonFilePath);
            
            if (!Files.exists(jsonPath)) {
                getLog().info("📊 No historical JSON data available for trend analysis");
                return;
            }
            
            JsonVulnerabilityStore store = loadExistingJsonData();
            List<JsonScanEntry> projectHistory = store.getScanHistory().stream()
                .filter(entry -> project.getGroupId().equals(entry.getProjectInfo().getGroupId()) && 
                               project.getArtifactId().equals(entry.getProjectInfo().getArtifactId()))
                .sorted((e1, e2) -> e1.getTimestamp().compareTo(e2.getTimestamp()))
                .collect(java.util.stream.Collectors.toList());
            
            if (projectHistory.size() < 2) {
                getLog().info("📊 Insufficient historical data for trend analysis (need at least 2 scans)");
                return;
            }
            
            getLog().info("📈 Generating trend analysis from " + projectHistory.size() + " historical scans");
            
            // Calculate trends
            JsonScanEntry previousScan = projectHistory.get(projectHistory.size() - 2);
            ScanResult previousResult = previousScan.getScanResult();
            
            int vulnerabilityTrend = result.getTotalVulnerabilities() - previousResult.getTotalVulnerabilities();
            int criticalTrend = result.getCriticalVulnerabilities() - previousResult.getCriticalVulnerabilities();
            int highTrend = result.getHighVulnerabilities() - previousResult.getHighVulnerabilities();
            int mediumTrend = result.getMediumVulnerabilities() - previousResult.getMediumVulnerabilities();
            int lowTrend = result.getLowVulnerabilities() - previousResult.getLowVulnerabilities();
            
            // Add trend metadata to result
            result.addTrendData("totalVulnerabilityTrend", vulnerabilityTrend);
            result.addTrendData("criticalTrend", criticalTrend);
            result.addTrendData("highTrend", highTrend);
            result.addTrendData("mediumTrend", mediumTrend);
            result.addTrendData("lowTrend", lowTrend);
            result.addTrendData("previousScanDate", previousScan.getTimestamp().toString());
            result.addTrendData("historicalScansCount", projectHistory.size());
            
            // Generate JAR analysis
            generateJarAnalysis(result, previousResult);
            
            // Display trend information
            displayTrendAnalysis(vulnerabilityTrend, criticalTrend, highTrend, mediumTrend, lowTrend, 
                               previousScan.getTimestamp(), projectHistory.size());
            
        } catch (Exception e) {
            getLog().warn("Failed to generate trend analysis from JSON data", e);
        }
    }

    private void addTrendDataFromInMemory(ScanResult result) {
        try {
            getLog().info("📊 Generating trend analysis from in-memory data...");
            
            // Get scan history from in-memory database
            List<InMemoryVulnerabilityDatabase.ScanSummary> scanHistory = inMemoryDatabase.getScanHistory(
                project.getGroupId(), project.getArtifactId(), 10);
            
            if (scanHistory.size() < 2) {
                getLog().info("📊 Insufficient historical data for trend analysis (need at least 2 scans)");
                return;
            }
            
            getLog().info("📈 Generating trend analysis from " + scanHistory.size() + " historical scans");
            
            // Get previous scan (second most recent, since scanHistory is sorted by most recent first)
            InMemoryVulnerabilityDatabase.ScanSummary previousScan = scanHistory.get(1);
            
            // Calculate trends compared to previous scan
            int vulnerabilityTrend = result.getTotalVulnerabilities() - previousScan.totalVulnerabilities;
            int criticalTrend = result.getCriticalVulnerabilities() - previousScan.criticalCount;
            int highTrend = result.getHighVulnerabilities() - previousScan.highCount;
            int mediumTrend = result.getMediumVulnerabilities() - previousScan.mediumCount;
            int lowTrend = result.getLowVulnerabilities() - previousScan.lowCount;
            
            // Add trend metadata to result
            result.addTrendData("totalVulnerabilityTrend", vulnerabilityTrend);
            result.addTrendData("criticalTrend", criticalTrend);
            result.addTrendData("highTrend", highTrend);
            result.addTrendData("mediumTrend", mediumTrend);
            result.addTrendData("lowTrend", lowTrend);
            result.addTrendData("previousScanDate", previousScan.startTime.toString());
            result.addTrendData("historicalScansCount", scanHistory.size());
            
            // Generate JAR analysis using in-memory data
            generateInMemoryJarAnalysis(result, previousScan);
            
            // Display trend information
            displayTrendAnalysis(vulnerabilityTrend, criticalTrend, highTrend, mediumTrend, lowTrend, 
                               previousScan.startTime, scanHistory.size());
            
        } catch (Exception e) {
            getLog().warn("Failed to generate trend analysis from in-memory data", e);
        }
    }

    private void generateInMemoryJarAnalysis(ScanResult currentResult, InMemoryVulnerabilityDatabase.ScanSummary previousScan) {
        try {
            getLog().info("📦 Generating JAR-level vulnerability analysis from in-memory data...");
            
            // Since the in-memory database doesn't store detailed JAR information per scan,
            // we'll do a simplified analysis based on overall vulnerability counts
            ScanResult.JarAnalysis jarAnalysis = new ScanResult.JarAnalysis();
            jarAnalysis.setTotalJarsAnalyzed(currentResult.getTotalDependencies());
            
            // For in-memory analysis, we'll estimate based on vulnerability changes
            // This is simplified since we don't have detailed JAR-level historical data
            int vulnerabilityChange = currentResult.getTotalVulnerabilities() - previousScan.totalVulnerabilities;
            int dependencyChange = currentResult.getTotalDependencies() - previousScan.totalDependencies;
            
            // Create simplified analysis
            List<ScanResult.VulnerableJar> newVulnerableJars = new ArrayList<>();
            List<ScanResult.VulnerableJar> resolvedJars = new ArrayList<>();
            List<ScanResult.VulnerableJar> pendingVulnerableJars = currentResult.getVulnerableJars();
            
            // Estimate new and resolved JARs based on trend data
            if (vulnerabilityChange > 0 && dependencyChange >= 0) {
                // More vulnerabilities, likely new vulnerable JARs
                getLog().info("📈 Trend indicates new vulnerable dependencies detected");
            } else if (vulnerabilityChange < 0) {
                // Fewer vulnerabilities, likely some JARs were fixed or removed
                getLog().info("📉 Trend indicates vulnerabilities were resolved");
            }
            
            jarAnalysis.setResolvedJars(resolvedJars);
            jarAnalysis.setNewVulnerableJars(newVulnerableJars);
            jarAnalysis.setPendingVulnerableJars(pendingVulnerableJars);
            
            currentResult.setJarAnalysis(jarAnalysis);
            
            // Log the analysis results
            getLog().info("📊 In-Memory JAR Analysis Results:");
            getLog().info("  📦 Total JARs analyzed: " + jarAnalysis.getTotalJarsAnalyzed());
            getLog().info("  📈 Vulnerability trend: " + (vulnerabilityChange >= 0 ? "+" : "") + vulnerabilityChange);
            getLog().info("  📦 Dependency count change: " + (dependencyChange >= 0 ? "+" : "") + dependencyChange);
            
        } catch (Exception e) {
            getLog().warn("Failed to generate in-memory JAR analysis", e);
        }
    }

    private void displayTrendAnalysis(int totalTrend, int criticalTrend, int highTrend, 
                                    int mediumTrend, int lowTrend, LocalDateTime previousScanTime, 
                                    int totalHistoricalScans) {
        getLog().info("");
        getLog().info("╭─────────────────────────────────────────────────────────────╮");
        getLog().info("│  📈 Vulnerability Trend Analysis (vs Previous Scan)        │");
        getLog().info("├─────────────────────────────────────────────────────────────┤");
        getLog().info(String.format("│  📅 Previous Scan: %-38s │", 
                     previousScanTime.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
        getLog().info(String.format("│  📊 Historical Scans: %-33d │", totalHistoricalScans));
        getLog().info("├─────────────────────────────────────────────────────────────┤");
        getLog().info(String.format("│  🔍 Total Vulnerabilities: %s%-26d │", 
                     getTrendIcon(totalTrend), totalTrend));
        getLog().info(String.format("│  🔴 Critical: %s%-38d │", 
                     getTrendIcon(criticalTrend), criticalTrend));
        getLog().info(String.format("│  🟠 High: %s%-42d │", 
                     getTrendIcon(highTrend), highTrend));
        getLog().info(String.format("│  🟡 Medium: %s%-40d │", 
                     getTrendIcon(mediumTrend), mediumTrend));
        getLog().info(String.format("│  🟢 Low: %s%-43d │", 
                     getTrendIcon(lowTrend), lowTrend));
        getLog().info("╰─────────────────────────────────────────────────────────────╯");
        getLog().info("");
    }

    private String getTrendIcon(int trend) {
        if (trend > 0) return "⬆️ +";
        if (trend < 0) return "⬇️ ";
        return "➡️ ";
    }
    
    private void generateJarAnalysis(ScanResult currentResult, ScanResult previousResult) {
        try {
            getLog().info("📦 Generating JAR-level vulnerability analysis...");
            
            // Get current and previous vulnerable JARs
            List<ScanResult.VulnerableJar> currentVulnerableJars = currentResult.getVulnerableJars();
            List<ScanResult.VulnerableJar> previousVulnerableJars = previousResult.getVulnerableJars();
            
            // Create JAR analysis
            ScanResult.JarAnalysis jarAnalysis = new ScanResult.JarAnalysis();
            jarAnalysis.setTotalJarsAnalyzed(currentResult.getTotalDependencies());
            
            // Create maps for easier comparison
            Map<String, ScanResult.VulnerableJar> currentJarMap = currentVulnerableJars.stream()
                .collect(java.util.stream.Collectors.toMap(jar -> jar.getName(), jar -> jar));
            Map<String, ScanResult.VulnerableJar> previousJarMap = previousVulnerableJars.stream()
                .collect(java.util.stream.Collectors.toMap(jar -> jar.getName(), jar -> jar));
            
            // Find resolved JARs (were vulnerable, now clean)
            List<ScanResult.VulnerableJar> resolvedJars = new ArrayList<>();
            for (ScanResult.VulnerableJar prevJar : previousVulnerableJars) {
                if (!currentJarMap.containsKey(prevJar.getName())) {
                    // This JAR was vulnerable before but is clean now
                    ScanResult.VulnerableJar resolvedJar = new ScanResult.VulnerableJar();
                    resolvedJar.setName(prevJar.getName());
                    resolvedJar.setVersion(prevJar.getVersion());
                    resolvedJar.setResolvedCveCount(prevJar.getVulnerabilities().size());
                    
                    // Convert vulnerabilities to resolved CVEs
                    List<ScanResult.ResolvedCve> resolvedCves = new ArrayList<>();
                    for (ScanResult.VulnerabilityInfo vuln : prevJar.getVulnerabilities()) {
                        ScanResult.ResolvedCve resolvedCve = new ScanResult.ResolvedCve();
                        resolvedCve.setId(vuln.getCveId());
                        resolvedCve.setSeverity(vuln.getSeverity());
                        resolvedCves.add(resolvedCve);
                    }
                    resolvedJar.setResolvedCves(resolvedCves);
                    resolvedJars.add(resolvedJar);
                }
            }
            
            // Find new vulnerable JARs (were clean, now vulnerable)
            List<ScanResult.VulnerableJar> newVulnerableJars = new ArrayList<>();
            for (ScanResult.VulnerableJar currentJar : currentVulnerableJars) {
                if (!previousJarMap.containsKey(currentJar.getName())) {
                    // This is a newly vulnerable JAR
                    newVulnerableJars.add(currentJar);
                }
            }
            
            // Find pending vulnerable JARs (were vulnerable, still vulnerable)
            List<ScanResult.VulnerableJar> pendingVulnerableJars = new ArrayList<>();
            for (ScanResult.VulnerableJar currentJar : currentVulnerableJars) {
                if (previousJarMap.containsKey(currentJar.getName())) {
                    // This JAR was vulnerable before and is still vulnerable
                    pendingVulnerableJars.add(currentJar);
                }
            }
            
            // Set the analysis data
            jarAnalysis.setResolvedJars(resolvedJars);
            jarAnalysis.setNewVulnerableJars(newVulnerableJars);
            jarAnalysis.setPendingVulnerableJars(pendingVulnerableJars);
            
            currentResult.setJarAnalysis(jarAnalysis);
            
            // Log the analysis results
            getLog().info("📊 JAR Analysis Results:");
            getLog().info("  ✅ Resolved JARs (CVEs fixed): " + resolvedJars.size());
            getLog().info("  🆕 New vulnerable JARs: " + newVulnerableJars.size());
            getLog().info("  ⏳ Pending vulnerable JARs: " + pendingVulnerableJars.size());
            getLog().info("  📦 Total JARs analyzed: " + jarAnalysis.getTotalJarsAnalyzed());
            
        } catch (Exception e) {
            getLog().warn("Failed to generate JAR analysis", e);
        }
    }

    
    private boolean isAdvancedReportFormat(ReportGenerator.ReportFormat format) {
        return format == ReportGenerator.ReportFormat.PDF || 
               format == ReportGenerator.ReportFormat.SARIF;
    }

    private void storeResults(ScanResult result) {
        if (useJsonFileStorage) {
            storeResultsInJsonFile(result);
        } else if (inMemoryDatabase != null) {
            try {
                getLog().info("Storing scan results in in-memory database...");
                inMemoryDatabase.storeScanResult(result);
                getLog().info("Scan results stored successfully in in-memory database");
            } catch (Exception e) {
                getLog().warn("Failed to store scan results in in-memory database", e);
            }
        } else if (database != null) {
            try {
                getLog().info("Storing scan results in database...");
                database.storeScanResultBatch(result);
                getLog().info("Scan results stored successfully");
            } catch (Exception e) {
                getLog().warn("Failed to store scan results in database", e);
            }
        }
    }

    private void storeResultsInJsonFile(ScanResult result) {
        try {
            getLog().info("Storing scan results in JSON file...");
            
            Path jsonPath = Paths.get(jsonFilePath);
            Files.createDirectories(jsonPath.getParent());
            
            JsonVulnerabilityStore existingStore = loadExistingJsonData();
            
            JsonScanEntry newEntry = new JsonScanEntry();
            newEntry.setTimestamp(LocalDateTime.now());
            newEntry.setScanResult(result);
            newEntry.setProjectInfo(new JsonProjectInfo(
                project.getGroupId(),
                project.getArtifactId(),
                project.getVersion()
            ));
            
            existingStore.getScanHistory().add(newEntry);
            
            try (FileWriter writer = new FileWriter(jsonPath.toFile())) {
                jsonMapper.writeValue(writer, existingStore);
            }
            
            getLog().info("✅ Scan results stored in JSON file: " + jsonFilePath);
            getLog().info("📊 Total scan history entries: " + existingStore.getScanHistory().size());
            
        } catch (Exception e) {
            getLog().warn("Failed to store scan results in JSON file", e);
        }
    }

    private JsonVulnerabilityStore loadExistingJsonData() {
        try {
            Path jsonPath = Paths.get(jsonFilePath);
            
            if (Files.exists(jsonPath)) {
                getLog().info("📖 Loading existing vulnerability data from JSON file");
                JsonVulnerabilityStore store = jsonMapper.readValue(jsonPath.toFile(), JsonVulnerabilityStore.class);
                getLog().info("📊 Found " + store.getScanHistory().size() + " existing scan entries");
                return store;
            } else {
                getLog().info("📄 Creating new vulnerability data JSON file");
                JsonVulnerabilityStore newStore = new JsonVulnerabilityStore();
                newStore.setCreated(LocalDateTime.now());
                newStore.setLastUpdated(LocalDateTime.now());
                return newStore;
            }
        } catch (Exception e) {
            getLog().warn("Failed to load existing JSON data, creating new store: " + e.getMessage());
            JsonVulnerabilityStore newStore = new JsonVulnerabilityStore();
            newStore.setCreated(LocalDateTime.now());
            newStore.setLastUpdated(LocalDateTime.now());
            return newStore;
        }
    }

    private static class JsonVulnerabilityStore {
        private LocalDateTime created;
        private LocalDateTime lastUpdated;
        private List<JsonScanEntry> scanHistory = new java.util.ArrayList<>();

        public LocalDateTime getCreated() { return created; }
        public void setCreated(LocalDateTime created) { this.created = created; }
        public LocalDateTime getLastUpdated() { return lastUpdated; }
        public void setLastUpdated(LocalDateTime lastUpdated) { this.lastUpdated = lastUpdated; }
        public List<JsonScanEntry> getScanHistory() { return scanHistory; }
        public void setScanHistory(List<JsonScanEntry> scanHistory) { this.scanHistory = scanHistory; }
    }

    private static class JsonScanEntry {
        private LocalDateTime timestamp;
        private ScanResult scanResult;
        private JsonProjectInfo projectInfo;

        public LocalDateTime getTimestamp() { return timestamp; }
        public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
        public ScanResult getScanResult() { return scanResult; }
        public void setScanResult(ScanResult scanResult) { this.scanResult = scanResult; }
        public JsonProjectInfo getProjectInfo() { return projectInfo; }
        public void setProjectInfo(JsonProjectInfo projectInfo) { this.projectInfo = projectInfo; }
    }

    private static class JsonProjectInfo {
        private String groupId;
        private String artifactId;
        private String version;

        public JsonProjectInfo() {}

        public JsonProjectInfo(String groupId, String artifactId, String version) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.version = version;
        }

        public String getGroupId() { return groupId; }
        public void setGroupId(String groupId) { this.groupId = groupId; }
        public String getArtifactId() { return artifactId; }
        public void setArtifactId(String artifactId) { this.artifactId = artifactId; }
        public String getVersion() { return version; }
        public void setVersion(String version) { this.version = version; }
    }


    private void handleScanResults(ScanResult result) throws MojoFailureException {
        int criticalCount = result.getCriticalVulnerabilities();
        int highCount = result.getHighVulnerabilities();
        
        boolean shouldFail = false;
        StringBuilder message = new StringBuilder();
        
        switch (severityThreshold.toUpperCase()) {
            case "CRITICAL":
                if (criticalCount > 0) {
                    shouldFail = true;
                    message.append(criticalCount).append(" critical vulnerabilities found");
                }
                break;
            case "HIGH":
                if (criticalCount > 0 || highCount > 0) {
                    shouldFail = true;
                    message.append(criticalCount + highCount).append(" high+ severity vulnerabilities found");
                }
                break;
            case "MEDIUM":
                if (result.getTotalVulnerabilities() > 0) {
                    shouldFail = true;
                    message.append(result.getTotalVulnerabilities()).append(" vulnerabilities found");
                }
                break;
        }
        
        if (shouldFail && failOnError) {
            throw new MojoFailureException("Build failed due to security vulnerabilities: " + message);
        } else if (result.getTotalVulnerabilities() > 0) {
            getLog().warn("⚠️  Security vulnerabilities detected: " + message);
        } else {
            getLog().info("✅ No security vulnerabilities found!");
        }
    }

    private boolean isMultiModuleProject() {
        return session.getTopLevelProject() != project && 
               session.getTopLevelProject().getModules() != null && 
               !session.getTopLevelProject().getModules().isEmpty();
    }
    
    private void displayScanStatistics(ScanResult result) {
        try {
            getLog().info("");
            getLog().info("╭─────────────────────────────────────────────────────────────╮");
            getLog().info("│  📊 Bastion Scan Statistics & Performance Metrics          │");
            getLog().info("├─────────────────────────────────────────────────────────────┤");
            
            // Basic scan metrics
            getLog().info(String.format("│  📦 JARs Scanned: %-40d │", result.getTotalDependencies()));
            getLog().info(String.format("│  🔍 CVEs Found: %-42d │", result.getTotalVulnerabilities()));
            getLog().info(String.format("│  ⏱️  Scan Duration: %-38s │", formatDuration(result.getScanDurationMs())));
            getLog().info(String.format("│  🚀 Processing Speed: %-33d deps/sec │", result.getDependenciesProcessedPerSecond()));
            
            // Enhanced statistics if available
            ScanStatistics stats = result.getStatistics();
            if (stats != null) {
                getLog().info("├─────────────────────────────────────────────────────────────┤");
                getLog().info("│  📈 Detailed Analysis:                                     │");
                getLog().info(String.format("│    • Direct Dependencies: %-29d │", stats.getDirectDependencies()));
                getLog().info(String.format("│    • Transitive Dependencies: %-25d │", stats.getTransitiveDependencies()));
                getLog().info(String.format("│    • Total JAR Size: %-34s │", stats.getTotalJarsSizeFormatted()));
                getLog().info(String.format("│    • Unique Group IDs: %-31d │", stats.getUniqueGroupIds()));
                getLog().info(String.format("│    • Duplicate JARs: %-33d │", stats.getDuplicateJars()));
                
                getLog().info("├─────────────────────────────────────────────────────────────┤");
                getLog().info("│  🎯 CVE Analysis:                                          │");
                getLog().info(String.format("│    • Unique CVEs: %-35d │", stats.getUniqueCvesFound()));
                getLog().info(String.format("│    • CVEs with Exploits: %-28d │", stats.getCvesWithExploits()));
                getLog().info(String.format("│    • Actively Exploited: %-27d │", stats.getCvesActivelyExploited()));
                getLog().info(String.format("│    • Average CVSS Score: %-27.1f │", stats.getAverageCvssScore()));
                getLog().info(String.format("│    • Highest CVSS Score: %-27.1f │", stats.getHighestCvssScore()));
                
                if (stats.getMostVulnerableComponent() != null) {
                    getLog().info(String.format("│    • Most Vulnerable: %-30s │", 
                                 truncateString(stats.getMostVulnerableComponent(), 30)));
                    getLog().info(String.format("│      (%-2d CVEs)                                       │", 
                                 stats.getMostVulnerableComponentCveCount()));
                }
            }
            
            // Performance metrics if available
            PerformanceMetrics perf = result.getPerformanceMetrics();
            if (perf != null) {
                getLog().info("├─────────────────────────────────────────────────────────────┤");
                getLog().info("│  ⚡ Performance Breakdown:                                  │");
                getLog().info(String.format("│    • Initialization: %-32s │", formatDuration(perf.getInitializationTimeMs())));
                getLog().info(String.format("│    • Dependency Resolution: %-24s │", formatDuration(perf.getDependencyResolutionTimeMs())));
                getLog().info(String.format("│    • Vulnerability Checks: %-25s │", formatDuration(perf.getVulnerabilityCheckTimeMs())));
                getLog().info(String.format("│    • Report Generation: %-28s │", formatDuration(perf.getReportGenerationTimeMs())));
                getLog().info(String.format("│    • Database Write: %-31s │", formatDuration(perf.getDatabaseWriteTimeMs())));
                
                if (perf.getPeakMemoryUsageMB() > 0) {
                    getLog().info("├─────────────────────────────────────────────────────────────┤");
                    getLog().info("│  💾 Resource Usage:                                        │");
                    getLog().info(String.format("│    • Peak Memory: %-33d MB │", perf.getPeakMemoryUsageMB()));
                    getLog().info(String.format("│    • Average Memory: %-30d MB │", perf.getAvgMemoryUsageMB()));
                    getLog().info(String.format("│    • Max Threads Used: %-29d │", perf.getMaxThreadsUsed()));
                    getLog().info(String.format("│    • Average CPU Usage: %-26d%% │", perf.getAvgCpuUsagePercent()));
                }
                
                if (perf.getCacheHits() > 0 || perf.getCacheMisses() > 0) {
                    getLog().info("├─────────────────────────────────────────────────────────────┤");
                    getLog().info("│  📂 Cache Performance:                                     │");
                    getLog().info(String.format("│    • Cache Hits: %-34d │", perf.getCacheHits()));
                    getLog().info(String.format("│    • Cache Misses: %-32d │", perf.getCacheMisses()));
                    getLog().info(String.format("│    • Hit Ratio: %-35.1f%% │", perf.getCacheHitRatio() * 100));
                }
                
                if (perf.getSlowestPhase() != null) {
                    getLog().info("├─────────────────────────────────────────────────────────────┤");
                    getLog().info("│  🐌 Bottleneck Analysis:                                   │");
                    getLog().info(String.format("│    • Slowest Phase: %-31s │", perf.getSlowestPhase()));
                    getLog().info(String.format("│    • Phase Duration: %-30s │", formatDuration(perf.getSlowestPhaseTimeMs())));
                    
                    if (perf.getRecommendedOptimization() != null) {
                        getLog().info(String.format("│    • Recommendation: %-30s │", 
                                     truncateString(perf.getRecommendedOptimization(), 30)));
                    }
                }
            }
            
            // Severity breakdown
            getLog().info("├─────────────────────────────────────────────────────────────┤");
            getLog().info("│  🚨 Severity Breakdown:                                    │");
            int criticalCount = result.getCriticalVulnerabilities();
            int highCount = result.getHighVulnerabilities();
            int mediumCount = result.getMediumVulnerabilities();
            int lowCount = result.getLowVulnerabilities();
            
            getLog().info(String.format("│    🔴 Critical: %-35d │", criticalCount));
            getLog().info(String.format("│    🟠 High: %-39d │", highCount));
            getLog().info(String.format("│    🟡 Medium: %-37d │", mediumCount));
            getLog().info(String.format("│    🟢 Low: %-40d │", lowCount));
            
            getLog().info("╰─────────────────────────────────────────────────────────────╯");
            getLog().info("");
            
        } catch (Exception e) {
            getLog().warn("Failed to display scan statistics", e);
        }
    }
    
    private String formatDuration(long milliseconds) {
        if (milliseconds < 1000) {
            return milliseconds + "ms";
        } else if (milliseconds < 60000) {
            return String.format("%.1fs", milliseconds / 1000.0);
        } else {
            return String.format("%dm %02ds", milliseconds / 60000, (milliseconds % 60000) / 1000);
        }
    }
    
    private String truncateString(String text, int maxLength) {
        if (text == null) return "";
        return text.length() > maxLength ? text.substring(0, maxLength - 3) + "..." : text;
    }

    private void performPurgeBeforeScan() throws Exception {
        getLog().info("🗑️  Performing database purge before scan");
        getLog().info("=====================================");
        
        determinePurgeScope();
        
        if (!force && !confirmPurge && !confirmPurgeOperation()) {
            getLog().info("Purge operation cancelled by user - continuing with scan");
            return;
        }
        
        performPurge();
    }

    private void determinePurgeScope() {
        getLog().info("");
        getLog().info("📊 Purge Scope Configuration:");
        
        if (projectOnly) {
            getLog().info("  • Scope: Current project only (" + project.getArtifactId() + ")");
        } else {
            getLog().info("  • Scope: ALL projects in database");
        }
        
        if (olderThanDays > 0) {
            getLog().info("  • Age Filter: Records older than " + olderThanDays + " days");
        } else {
            getLog().info("  • Age Filter: ALL records (no age restriction)");
        }
        
        if (dryRun) {
            getLog().info("  • Mode: DRY RUN (no actual deletion)");
        } else {
            getLog().info("  • Mode: DESTRUCTIVE (will permanently delete data)");
        }
        getLog().info("");
    }

    private boolean confirmPurgeOperation() throws SQLException {
        try {
            getLog().warn("⚠️  WARNING: This operation will PERMANENTLY DELETE vulnerability data!");
            getLog().warn("⚠️  This action CANNOT be undone!");
            getLog().info("");
            
            showPurgeImpact();
            
            getLog().info("To proceed without confirmation, use:");
            getLog().info("  mvn bastion:scan -Dbastion.purge.confirm=true");
            getLog().info("  mvn bastion:scan -Dbastion.purge.force=true");
            getLog().info("");
            
            System.out.print("Are you sure you want to continue? Type 'DELETE' to confirm: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String input = reader.readLine();
            
            return "DELETE".equals(input);
            
        } catch (IOException e) {
            getLog().error("Failed to read user confirmation", e);
            return false;
        }
    }

    private void showPurgeImpact() throws SQLException {
        getLog().info("📊 Impact Analysis:");
        
        if (useJsonFileStorage) {
            showJsonPurgeImpact();
        } else {
            showDatabasePurgeImpact();
        }
        
        getLog().info("");
    }

    private void showJsonPurgeImpact() {
        try {
            Path jsonPath = Paths.get(jsonFilePath);
            
            if (Files.exists(jsonPath)) {
                JsonVulnerabilityStore store = loadExistingJsonData();
                
                if (projectOnly) {
                    long projectEntries = store.getScanHistory().stream()
                        .filter(entry -> project.getGroupId().equals(entry.getProjectInfo().getGroupId()) && 
                                       project.getArtifactId().equals(entry.getProjectInfo().getArtifactId()))
                        .count();
                    getLog().info("  • JSON entries for this project: " + projectEntries);
                } else {
                    getLog().info("  • Total JSON scan entries: " + store.getScanHistory().size());
                    getLog().info("  • JSON file path: " + jsonFilePath);
                    
                    if (olderThanDays == 0) {
                        getLog().info("  • Action: Complete JSON file deletion");
                    }
                }
                
                if (olderThanDays > 0) {
                    LocalDateTime cutoff = LocalDateTime.now().minusDays(olderThanDays);
                    long oldEntries = store.getScanHistory().stream()
                        .filter(entry -> entry.getTimestamp().isBefore(cutoff))
                        .count();
                    getLog().info("  • Entries older than " + olderThanDays + " days: " + oldEntries);
                }
            } else {
                getLog().info("  • JSON file does not exist - nothing to purge");
            }
        } catch (Exception e) {
            getLog().warn("  • Could not analyze JSON file: " + e.getMessage());
        }
    }

    private void showDatabasePurgeImpact() throws SQLException {
        if (projectOnly) {
            int projectRecords = database.countScanResultsForProject(
                project.getGroupId(), project.getArtifactId());
            getLog().info("  • Scan results for this project: " + projectRecords);
            
            int projectVulns = database.countVulnerabilitiesForProject(
                project.getGroupId(), project.getArtifactId());
            getLog().info("  • Vulnerabilities for this project: " + projectVulns);
        } else {
            int totalScans = database.countAllScanResults();
            getLog().info("  • Total scan results: " + totalScans);
            
            int totalVulns = database.countAllVulnerabilities();
            getLog().info("  • Total vulnerabilities: " + totalVulns);
            
            int totalProjects = database.countDistinctProjects();
            getLog().info("  • Affected projects: " + totalProjects);
        }
        
        if (olderThanDays > 0) {
            int oldRecords = database.countScanResultsOlderThan(olderThanDays);
            getLog().info("  • Records older than " + olderThanDays + " days: " + oldRecords);
        }
    }

    private void performPurge() throws SQLException {
        if (dryRun) {
            getLog().info("🔍 DRY RUN - No actual data will be deleted");
            performDryRunPurge();
        } else {
            if (useJsonFileStorage) {
                getLog().info("🗑️  Performing JSON file purge...");
                performJsonPurge();
            } else {
                getLog().info("🗑️  Performing actual database purge...");
                performActualPurge();
            }
        }
    }

    private void performDryRunPurge() throws SQLException {
        getLog().info("");
        getLog().info("DRY RUN RESULTS:");
        getLog().info("================");
        
        if (useJsonFileStorage) {
            performJsonDryRunPurge();
        } else {
            performDatabaseDryRunPurge();
        }
        
        getLog().info("");
        getLog().info("✅ DRY RUN completed - no data was actually deleted");
    }

    private void performJsonPurge() {
        try {
            long startTime = System.currentTimeMillis();
            Path jsonPath = Paths.get(jsonFilePath);
            
            if (!Files.exists(jsonPath)) {
                getLog().info("✅ JSON file does not exist - nothing to purge");
                return;
            }
            
            JsonVulnerabilityStore store = loadExistingJsonData();
            int originalSize = store.getScanHistory().size();
            int deletedEntries = 0;
            
            if (projectOnly) {
                int sizeBefore = store.getScanHistory().size();
                store.getScanHistory().removeIf(entry -> 
                    project.getGroupId().equals(entry.getProjectInfo().getGroupId()) && 
                    project.getArtifactId().equals(entry.getProjectInfo().getArtifactId()));
                deletedEntries = sizeBefore - store.getScanHistory().size();
                
                getLog().info("Deleted " + deletedEntries + " entries for project: " + project.getArtifactId());
                
                try (FileWriter writer = new FileWriter(jsonPath.toFile())) {
                    jsonMapper.writeValue(writer, store);
                }
                
            } else {
                if (olderThanDays > 0) {
                    LocalDateTime cutoff = LocalDateTime.now().minusDays(olderThanDays);
                    int sizeBefore = store.getScanHistory().size();
                    store.getScanHistory().removeIf(entry -> 
                        entry.getTimestamp().isBefore(cutoff));
                    deletedEntries = sizeBefore - store.getScanHistory().size();
                    
                    getLog().info("Deleted " + deletedEntries + " entries older than " + olderThanDays + " days");
                    
                    try (FileWriter writer = new FileWriter(jsonPath.toFile())) {
                        jsonMapper.writeValue(writer, store);
                    }
                } else {
                    deletedEntries = originalSize;
                    Files.delete(jsonPath);
                    getLog().info("✅ Complete JSON file deleted: " + jsonFilePath);
                }
            }
            
            long duration = System.currentTimeMillis() - startTime;
            
            getLog().info("");
            getLog().info("🎉 JSON purge operation completed successfully!");
            getLog().info("📊 Summary:");
            getLog().info("  • Entries deleted: " + deletedEntries);
            getLog().info("  • Remaining entries: " + (originalSize - deletedEntries));
            getLog().info("  • Operation duration: " + duration + "ms");
            
        } catch (Exception e) {
            getLog().error("Failed to purge JSON file", e);
        }
    }

    private void performJsonDryRunPurge() {
        try {
            Path jsonPath = Paths.get(jsonFilePath);
            
            if (!Files.exists(jsonPath)) {
                getLog().info("Would delete: Nothing (JSON file doesn't exist)");
                return;
            }
            
            JsonVulnerabilityStore store = loadExistingJsonData();
            
            if (projectOnly) {
                long projectEntries = store.getScanHistory().stream()
                    .filter(entry -> project.getGroupId().equals(entry.getProjectInfo().getGroupId()) && 
                                   project.getArtifactId().equals(entry.getProjectInfo().getArtifactId()))
                    .count();
                
                getLog().info("Would delete:");
                getLog().info("  • " + projectEntries + " JSON entries for project " + project.getArtifactId());
                
            } else {
                if (olderThanDays > 0) {
                    LocalDateTime cutoff = LocalDateTime.now().minusDays(olderThanDays);
                    long oldEntries = store.getScanHistory().stream()
                        .filter(entry -> entry.getTimestamp().isBefore(cutoff))
                        .count();
                    
                    getLog().info("Would delete (older than " + olderThanDays + " days):");
                    getLog().info("  • " + oldEntries + " JSON scan entries");
                } else {
                    getLog().info("Would delete ALL JSON data:");
                    getLog().info("  • Complete JSON file: " + jsonFilePath);
                    getLog().info("  • " + store.getScanHistory().size() + " scan entries");
                    getLog().info("  • All historical trend data");
                }
            }
        } catch (Exception e) {
            getLog().warn("Could not analyze JSON file for dry run: " + e.getMessage());
        }
    }

    private void performDatabaseDryRunPurge() throws SQLException {
        if (projectOnly) {
            int scanResults = database.countScanResultsForProject(
                project.getGroupId(), project.getArtifactId());
            int vulnerabilities = database.countVulnerabilitiesForProject(
                project.getGroupId(), project.getArtifactId());
            
            getLog().info("Would delete:");
            getLog().info("  • " + scanResults + " scan results for project " + project.getArtifactId());
            getLog().info("  • " + vulnerabilities + " associated vulnerabilities");
            
        } else {
            if (olderThanDays > 0) {
                int oldScans = database.countScanResultsOlderThan(olderThanDays);
                int oldVulns = database.countVulnerabilitiesOlderThan(olderThanDays);
                
                getLog().info("Would delete (older than " + olderThanDays + " days):");
                getLog().info("  • " + oldScans + " scan results");
                getLog().info("  • " + oldVulns + " vulnerabilities");
            } else {
                int allScans = database.countAllScanResults();
                int allVulns = database.countAllVulnerabilities();
                
                getLog().info("Would delete ALL data:");
                getLog().info("  • " + allScans + " scan results");
                getLog().info("  • " + allVulns + " vulnerabilities");
                getLog().info("  • All historical trend data");
                getLog().info("  • All performance metrics");
            }
        }
    }

    private void performActualPurge() throws SQLException {
        long startTime = System.currentTimeMillis();
        int deletedScans = 0;
        int deletedVulns = 0;
        
        getLog().info("");
        
        if (projectOnly) {
            getLog().info("Deleting data for project: " + project.getArtifactId());
            
            deletedVulns = database.deleteVulnerabilitiesForProject(
                project.getGroupId(), project.getArtifactId());
            getLog().info("  ✅ Deleted " + deletedVulns + " vulnerability records");
            
            deletedScans = database.deleteScanResultsForProject(
                project.getGroupId(), project.getArtifactId());
            getLog().info("  ✅ Deleted " + deletedScans + " scan result records");
            
        } else {
            if (olderThanDays > 0) {
                getLog().info("Deleting records older than " + olderThanDays + " days");
                
                deletedVulns = database.deleteVulnerabilitiesOlderThan(olderThanDays);
                getLog().info("  ✅ Deleted " + deletedVulns + " old vulnerability records");
                
                deletedScans = database.deleteScanResultsOlderThan(olderThanDays);
                getLog().info("  ✅ Deleted " + deletedScans + " old scan result records");
                
            } else {
                getLog().info("Deleting ALL vulnerability data from database");
                
                deletedVulns = database.deleteAllVulnerabilities();
                getLog().info("  ✅ Deleted " + deletedVulns + " vulnerability records");
                
                deletedScans = database.deleteAllScanResults();
                getLog().info("  ✅ Deleted " + deletedScans + " scan result records");
                
                int deletedStats = database.deleteAllStatistics();
                getLog().info("  ✅ Deleted " + deletedStats + " statistics records");
                
                int deletedMetrics = database.deleteAllPerformanceMetrics();
                getLog().info("  ✅ Deleted " + deletedMetrics + " performance metrics");
                
                database.optimizeDatabase();
                getLog().info("  ✅ Database optimized");
            }
        }
        
        long duration = System.currentTimeMillis() - startTime;
        
        getLog().info("");
        getLog().info("🎉 Purge operation completed successfully!");
        getLog().info("📊 Summary:");
        getLog().info("  • Scan results deleted: " + deletedScans);
        getLog().info("  • Vulnerabilities deleted: " + deletedVulns);
        getLog().info("  • Operation duration: " + duration + "ms");
        
        if (!projectOnly && olderThanDays == 0) {
            getLog().info("");
            getLog().info("💡 Database has been completely reset");
            getLog().info("💡 Next scan will start fresh with no historical data");
        }
    }

    private List<String> collectDependencyPaths() {
        List<String> dependencyPaths = new ArrayList<>();
        
        try {
            getLog().info("Collecting Maven dependency artifacts...");
            
            // Get all project artifacts including transitive dependencies
            Set<org.apache.maven.artifact.Artifact> artifacts = project.getArtifacts();
            
            for (org.apache.maven.artifact.Artifact artifact : artifacts) {
                if (artifact.getFile() != null && artifact.getFile().exists()) {
                    dependencyPaths.add(artifact.getFile().getAbsolutePath());
                    getLog().info("Added dependency: " + artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion() + " -> " + artifact.getFile().getAbsolutePath());
                } else {
                    getLog().warn("Dependency file not found for: " + artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion());
                }
            }
            
            // Also scan the project's own artifact if it exists
            File projectArtifact = new File(project.getBuild().getDirectory(), 
                project.getBuild().getFinalName() + ".jar");
            if (projectArtifact.exists()) {
                dependencyPaths.add(projectArtifact.getAbsolutePath());
                getLog().debug("Added project artifact: " + projectArtifact.getAbsolutePath());
            }
            
            getLog().info("Collected " + dependencyPaths.size() + " dependency paths for scanning");
            
        } catch (Exception e) {
            getLog().warn("Error collecting dependency paths, falling back to directory scan", e);
        }
        
        return dependencyPaths;
    }
    
    private CompletableFuture<ScanResult> scanWithDependencies(String projectPath, List<String> dependencyPaths) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // Create enhanced scanner that can handle both project path and dependency list
                if (scanner instanceof OwaspDependencyCheckScanner) {
                    OwaspDependencyCheckScanner owaspScanner = (OwaspDependencyCheckScanner) scanner;
                    return owaspScanner.scanProjectWithDependencies(projectPath, dependencyPaths, 
                                                                  project.getGroupId(), 
                                                                  project.getArtifactId(), 
                                                                  project.getVersion()).get();
                } else {
                    // Fallback to regular project scan
                    return scanner.scanProject(projectPath).get();
                }
            } catch (Exception e) {
                throw new RuntimeException("Scan failed", e);
            }
        });
    }
    
    /**
     * Invoke official OWASP Dependency-Check plugin to generate JSON report
     */
    /**
     * Get the NVD database file path if it exists
     * @return Path to database file, or null if not found
     */
    private Path getNvdDatabasePath() {
        String userHome = System.getProperty("user.home");

        // Check common NVD database locations
        List<Path> possiblePaths = Arrays.asList(
            // H2 database file in Maven repository (OWASP 12.x format)
            Paths.get(userHome, ".m2", "repository", "org", "owasp", "dependency-check-utils", owaspVersion, "data", "11.0", "odc.mv.db"),
            // Alternative H2 database location
            Paths.get(userHome, ".m2", "repository", "org", "owasp", "dependency-check-data", "odc.mv.db"),
            // Legacy location
            Paths.get(userHome, ".owasp-dependency-check", "data", "odc.mv.db")
        );

        for (Path path : possiblePaths) {
            if (Files.exists(path)) {
                getLog().debug("Found NVD database at: " + path);
                return path;
            }
        }

        // Check for any version pattern in utils directory
        Path utilsDir = Paths.get(userHome, ".m2", "repository", "org", "owasp", "dependency-check-utils");
        if (Files.exists(utilsDir)) {
            try {
                return Files.walk(utilsDir, 5)
                    .filter(p -> p.toString().endsWith("odc.mv.db"))
                    .findFirst()
                    .orElse(null);
            } catch (IOException e) {
                getLog().debug("Error checking dependency-check-utils directory: " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Check if NVD database has been initialized
     * @return true if database exists, false otherwise
     */
    private boolean isNvdDatabaseInitialized() {
        getLog().debug("Checking if NVD database is initialized...");
        Path dbPath = getNvdDatabasePath();

        if (dbPath == null) {
            getLog().info("📥 NVD database not found - initialization required");
            return false;
        }

        try {
            long lastModifiedMs = Files.getLastModifiedTime(dbPath).toMillis();
            long currentMs = System.currentTimeMillis();
            long ageInDays = (currentMs - lastModifiedMs) / (1000 * 60 * 60 * 24);

            getLog().info("✅ NVD database found (age: " + ageInDays + " days) - OWASP will check for updates automatically");
            return true;
        } catch (IOException e) {
            getLog().debug("Could not read database timestamp: " + e.getMessage());
            return true; // Database exists, just can't read timestamp
        }
    }

    /**
     * Initialize NVD database by running update-only goal (first-time setup)
     * @throws MojoExecutionException if initialization fails
     */
    private void initializeNvdDatabase() throws MojoExecutionException {
        getLog().info("════════════════════════════════════════════════════════════════");
        getLog().info("📥 First-Time Setup: Downloading NVD Database");
        getLog().info("════════════════════════════════════════════════════════════════");
        getLog().info("⏱️  This will take 20-30 minutes (one-time only)");
        getLog().info("🔄 Future scans will automatically check for incremental updates");

        if (nvdApiKey != null && !nvdApiKey.isEmpty()) {
            getLog().info("🔑 Using NVD API key for faster downloads");
        } else {
            getLog().warn("⚠️  No NVD API key - download will be slower");
            getLog().warn("💡 Get a free API key: https://nvd.nist.gov/developers/request-an-api-key");
        }

        getLog().info("════════════════════════════════════════════════════════════════");

        try {
            // Build Maven command for update-only
            List<String> command = new ArrayList<>();
            command.add("mvn");
            command.add("org.owasp:dependency-check-maven:" + owaspVersion + ":update-only");

            // Pass through NVD API key if available
            if (nvdApiKey != null && !nvdApiKey.isEmpty()) {
                command.add("-Dnvd.api.key=" + nvdApiKey);
            }

            getLog().debug("Executing: " + String.join(" ", command));

            // Execute Maven command
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(project.getBasedir());
            pb.redirectErrorStream(true);

            // Pass MAVEN_OPTS to subprocess to prevent OOM during database download
            Map<String, String> env = pb.environment();
            String mavenOpts = env.get("MAVEN_OPTS");
            if (mavenOpts == null || !mavenOpts.contains("-Xmx")) {
                // Set reasonable heap size for database initialization
                env.put("MAVEN_OPTS", "-Xmx3g");
                getLog().info("💾 Setting MAVEN_OPTS=-Xmx3g for database initialization");
            } else {
                getLog().info("💾 Using existing MAVEN_OPTS: " + mavenOpts);
            }

            Process process = pb.start();

            // Capture and display output
            StringBuilder output = new StringBuilder();
            int lineCount = 0;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    lineCount++;

                    // Log important progress lines
                    if (line.contains("Processing") || line.contains("Downloaded") ||
                        line.contains("ERROR") || line.contains("WARNING") ||
                        line.contains("CVE") || lineCount % 50 == 0) {
                        getLog().info("  " + line);
                    }
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                getLog().error("NVD database initialization failed with exit code " + exitCode);
                getLog().debug("Full output:\n" + output);
                throw new MojoExecutionException(
                    "Failed to initialize NVD database. Exit code: " + exitCode + "\n" +
                    "Please run manually: mvn org.owasp:dependency-check-maven:" + owaspVersion + ":update-only" +
                    (nvdApiKey != null && !nvdApiKey.isEmpty() ? " -Dnvd.api.key=" + nvdApiKey : "")
                );
            }

            getLog().info("✅ NVD database initialized successfully!");

        } catch (IOException | InterruptedException e) {
            throw new MojoExecutionException("Failed to initialize NVD database", e);
        }
    }

    private File invokeOwaspPlugin() throws MojoExecutionException {
        getLog().info("🔄 Invoking official OWASP Dependency-Check plugin v" + owaspVersion + "...");
        getLog().info("📋 Hybrid mode: OWASP for scanning + Bastion for enhanced reporting");
        getLog().info("🔄 Auto-update enabled: OWASP will check for latest NVD data");

        try {
            // Build Maven command
            List<String> command = new ArrayList<>();
            command.add("mvn");
            command.add("org.owasp:dependency-check-maven:" + owaspVersion + ":check");
            command.add("-DautoUpdate=true"); // Always enable auto-update for latest NVD data
            command.add("-Dformat=JSON");
            command.add("-Dformat=HTML"); // Keep HTML for OWASP native report

            // Pass through NVD API key if available
            if (nvdApiKey != null && !nvdApiKey.isEmpty()) {
                command.add("-DnvdApiKey=" + nvdApiKey);
                getLog().info("🔑 Using NVD API key for faster updates");
            } else {
                getLog().warn("⚠️  No NVD API key provided - updates may be slower");
                getLog().warn("💡 Get a free API key: https://nvd.nist.gov/developers/request-an-api-key");
            }

            getLog().debug("Executing: " + String.join(" ", command));

            // Execute Maven command
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(project.getBasedir());
            pb.redirectErrorStream(true);

            // Pass MAVEN_OPTS to subprocess to prevent OOM
            Map<String, String> env = pb.environment();
            String mavenOpts = env.get("MAVEN_OPTS");
            if (mavenOpts == null || !mavenOpts.contains("-Xmx")) {
                // If MAVEN_OPTS not set or doesn't specify heap, set a reasonable default
                env.put("MAVEN_OPTS", "-Xmx2g");
                getLog().info("💾 Setting MAVEN_OPTS=-Xmx2g for OWASP subprocess");
            } else {
                getLog().info("💾 Using existing MAVEN_OPTS: " + mavenOpts);
            }

            Process process = pb.start();

            // Capture output
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                    // Log important lines
                    if (line.contains("ERROR") || line.contains("WARNING") || line.contains("vulnerabilities found")) {
                        getLog().info("  " + line);
                    }
                }
            }

            int exitCode = process.waitFor();

            if (exitCode != 0) {
                getLog().warn("OWASP plugin exited with code " + exitCode);
                getLog().debug("OWASP plugin output:\n" + output);
            } else {
                getLog().info("✅ OWASP scan completed successfully");
            }

            // Check if report was generated
            File reportFile = new File(project.getBuild().getDirectory(), "dependency-check-report.json");
            if (!reportFile.exists()) {
                throw new MojoExecutionException("OWASP report not generated at: " + reportFile.getAbsolutePath());
            }

            getLog().info("📄 OWASP JSON report: " + reportFile.getAbsolutePath() + " (" + (reportFile.length() / 1024) + " KB)");
            return reportFile;

        } catch (IOException | InterruptedException e) {
            throw new MojoExecutionException("Failed to invoke OWASP plugin", e);
        }
    }

    /**
     * Parse OWASP JSON report
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseOwaspJsonReport(File reportFile) throws MojoExecutionException {
        getLog().info("📖 Parsing OWASP JSON report...");

        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> report = mapper.readValue(reportFile, Map.class);

            // Validate report structure
            if (!report.containsKey("dependencies")) {
                throw new MojoExecutionException("Invalid OWASP report format: missing 'dependencies' field");
            }

            List<Map<String, Object>> dependencies = (List<Map<String, Object>>) report.get("dependencies");
            getLog().info("✅ Parsed " + dependencies.size() + " dependencies from OWASP report");

            return report;

        } catch (IOException e) {
            throw new MojoExecutionException("Failed to parse OWASP JSON report", e);
        }
    }

    /**
     * Convert OWASP report data to Bastion ScanResult format
     */
    @SuppressWarnings("unchecked")
    private ScanResult convertOwaspToBastion(Map<String, Object> owaspReport) throws MojoExecutionException {
        getLog().info("🔄 Converting OWASP data to Bastion format...");

        try {
            List<Map<String, Object>> owaspDependencies = (List<Map<String, Object>>) owaspReport.get("dependencies");

            // Create Bastion ScanResult
            ScanResult result = new ScanResult();
            result.setProjectName(project.getName());
            result.setProjectGroupId(project.getGroupId());
            result.setProjectArtifactId(project.getArtifactId());
            result.setProjectVersion(project.getVersion());
            result.setStartTime(LocalDateTime.now());

            // Statistics
            int totalVulnerabilities = 0;
            int criticalCount = 0;
            int highCount = 0;
            int mediumCount = 0;
            int lowCount = 0;
            int vulnerableDependenciesCount = 0;

            // Convert each dependency
            List<ScanResult.DependencyResult> bastionDependencies = new ArrayList<>();
            List<io.github.dodogeny.security.model.Vulnerability> allVulnerabilities = new ArrayList<>();

            for (Map<String, Object> owaspDep : owaspDependencies) {
                String fileName = (String) owaspDep.get("fileName");
                String filePath = (String) owaspDep.get("filePath");

                // Extract identifiers from PURL format: pkg:maven/groupId/artifactId@version
                List<Map<String, Object>> packages = (List<Map<String, Object>>) owaspDep.get("packages");
                String groupId = "unknown";
                String artifactId = fileName;
                String version = "unknown";

                if (packages != null && !packages.isEmpty()) {
                    Map<String, Object> pkg = packages.get(0);
                    String id = (String) pkg.get("id");
                    if (id != null && id.startsWith("pkg:maven/")) {
                        // Remove "pkg:maven/" prefix
                        String mavenCoords = id.substring("pkg:maven/".length());

                        // Split by @ to separate coordinates from version
                        String[] coordsAndVersion = mavenCoords.split("@");
                        if (coordsAndVersion.length == 2) {
                            version = coordsAndVersion[1];

                            // Split coordinates by / to get groupId and artifactId
                            String[] coords = coordsAndVersion[0].split("/");
                            if (coords.length == 2) {
                                groupId = coords[0];
                                artifactId = coords[1];
                            }
                        }
                    }
                }

                // Create DependencyResult
                ScanResult.DependencyResult bastionDep = new ScanResult.DependencyResult();
                bastionDep.setGroupId(groupId);
                bastionDep.setArtifactId(artifactId);
                bastionDep.setVersion(version);
                bastionDep.setFilePath(filePath);

                List<Map<String, Object>> vulnerabilities = (List<Map<String, Object>>) owaspDep.get("vulnerabilities");

                if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
                    vulnerableDependenciesCount++;

                    // Collect vulnerability IDs for this dependency
                    Set<String> vulnerabilityIds = new HashSet<>();

                    // Convert vulnerabilities
                    for (Map<String, Object> owaspVuln : vulnerabilities) {
                        String cveId = (String) owaspVuln.get("name");
                        String description = (String) owaspVuln.get("description");
                        String severity = (String) owaspVuln.get("severity");

                        // Create Vulnerability object
                        io.github.dodogeny.security.model.Vulnerability bastionVuln =
                            new io.github.dodogeny.security.model.Vulnerability(cveId, severity, description);

                        // Extract CVSS score
                        Map<String, Object> cvssv3 = (Map<String, Object>) owaspVuln.get("cvssv3");
                        if (cvssv3 != null && cvssv3.containsKey("baseScore")) {
                            Object baseScoreObj = cvssv3.get("baseScore");
                            if (baseScoreObj instanceof Number) {
                                bastionVuln.setCvssV3Score(((Number) baseScoreObj).doubleValue());
                            }
                        }

                        // Count by severity
                        if (severity != null) {
                            switch (severity.toUpperCase()) {
                                case "CRITICAL":
                                    criticalCount++;
                                    break;
                                case "HIGH":
                                    highCount++;
                                    break;
                                case "MEDIUM":
                                    mediumCount++;
                                    break;
                                case "LOW":
                                    lowCount++;
                                    break;
                            }
                        }

                        allVulnerabilities.add(bastionVuln);
                        vulnerabilityIds.add(cveId);
                        totalVulnerabilities++;
                    }

                    bastionDep.setVulnerabilityIds(vulnerabilityIds);
                }

                bastionDependencies.add(bastionDep);
            }

            result.setDependencies(bastionDependencies);
            result.setVulnerabilities(allVulnerabilities);

            // Set summary statistics
            result.setTotalDependencies(owaspDependencies.size());
            result.setVulnerableDependencies(vulnerableDependenciesCount);
            result.setTotalVulnerabilities(totalVulnerabilities);
            result.setCriticalVulnerabilities(criticalCount);
            result.setHighVulnerabilities(highCount);
            result.setMediumVulnerabilities(mediumCount);
            result.setLowVulnerabilities(lowCount);

            // Set enhanced statistics
            ScanStatistics stats = new ScanStatistics();
            stats.setTotalJarsScanned(owaspDependencies.size());
            stats.setTotalCvesFound(totalVulnerabilities);
            stats.setUniqueCvesFound(allVulnerabilities.size());
            stats.setCriticalCves(criticalCount);
            stats.setHighCves(highCount);
            stats.setMediumCves(mediumCount);
            stats.setLowCves(lowCount);
            result.setStatistics(stats);

            getLog().info("✅ Converted to Bastion format:");
            getLog().info("   📦 Total dependencies: " + owaspDependencies.size());
            getLog().info("   ⚠️  Vulnerable dependencies: " + vulnerableDependenciesCount);
            getLog().info("   🔴 Total vulnerabilities: " + totalVulnerabilities);
            getLog().info("   🔴 Critical: " + criticalCount + " | High: " + highCount + " | Medium: " + mediumCount + " | Low: " + lowCount);

            return result;

        } catch (Exception e) {
            throw new MojoExecutionException("Failed to convert OWASP data to Bastion format", e);
        }
    }

    private void cleanup() {
        try {
            if (database != null) {
                database.close();
            }
            // Note: InMemoryVulnerabilityDatabase doesn't need explicit cleanup
            // as it's designed for session-based storage with automatic cleanup
            if (inMemoryDatabase != null) {
                getLog().debug("In-memory database cleanup completed");
            }
        } catch (Exception e) {
            getLog().warn("Error during cleanup", e);
        }
    }
}