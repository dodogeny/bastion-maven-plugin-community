package io.github.dodogeny.security.plugin;

import io.github.dodogeny.security.database.VulnerabilityDatabase;
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

    @Parameter(property = "bastion.autoUpdate", defaultValue = "false")
    private boolean autoUpdate;

    @Parameter(property = "bastion.community.storageMode", defaultValue = "IN_MEMORY")
    private String communityStorageMode;

    private VulnerabilityDatabase database;
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
        
        // Create in-memory database configuration
        VulnerabilityDatabase.DatabaseConfig config = new VulnerabilityDatabase.DatabaseConfig();
        config.setType("h2");
        config.setPath("mem:bastion");
        
        database = new VulnerabilityDatabase(config, LoggerFactory.getLogger(VulnerabilityDatabase.class));
        database.initialize(); // Initialize the database schema
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
        config.setAutoUpdate(autoUpdate);
        
        scanner.configure(config);
        getLog().info("Scanner initialized: " + scanner.getName());
    }

    private void initializeReportGenerator() {
        reportGenerator = new ReportGenerator();
        getLog().info("Report generator initialized");
    }


    private ScanResult performScan() throws Exception {
        getLog().info("Scanning project dependencies...");
        
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
        } else if (database != null) {
            try {
                String storageType = "IN_MEMORY".equalsIgnoreCase(communityStorageMode) ? 
                    "in-memory database" : "database";
                getLog().info("Storing scan results in " + storageType + "...");
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
                    getLog().debug("Added dependency: " + artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion() + " -> " + artifact.getFile().getAbsolutePath());
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
    
    private void cleanup() {
        try {
            if (database != null) {
                database.close();
            }
        } catch (Exception e) {
            getLog().warn("Error during cleanup", e);
        }
    }
}