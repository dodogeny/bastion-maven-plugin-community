package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Custom NVD client that directly accesses the local H2 NVD database to handle CVSSv4 parsing issues
 * that cause problems with OWASP Dependency-Check 10.0.4.
 * 
 * This client queries the existing local database and provides enhanced error handling for 
 * CVSSv4 data that cannot be properly parsed by OWASP Dependency-Check.
 */
public class CustomNvdClient {
    private static final Logger logger = LoggerFactory.getLogger(CustomNvdClient.class);
    
    private final String databasePath;
    private Connection connection;
    
    public CustomNvdClient(String databasePath) {
        this.databasePath = databasePath;
        logger.info("🔗 Initializing CustomNvdClient with local database: {}", databasePath);
    }
    
    /**
     * Connects to the local H2 database
     */
    private void connect() throws SQLException {
        if (connection == null || connection.isClosed()) {
            // Ensure H2 driver is loaded
            try {
                Class.forName("org.h2.Driver");
            } catch (ClassNotFoundException e) {
                throw new SQLException("H2 driver not found", e);
            }
            
            // Try multiple connection approaches for different OWASP Dependency-Check versions
            String baseJdbcUrl = "jdbc:h2:" + databasePath;
            String[] connectionVariants = {
                // Standard OWASP connection (most common)
                baseJdbcUrl + ";CACHE_SIZE=8192;IFEXISTS=TRUE",
                // Read-only mode
                baseJdbcUrl + ";ACCESS_MODE_DATA=r;CACHE_SIZE=8192;IFEXISTS=TRUE", 
                // Minimal connection
                baseJdbcUrl + ";IFEXISTS=TRUE",
                // Default H2 settings
                baseJdbcUrl
            };
            
            String[][] credentialVariants = {
                {"", ""},           // Empty credentials (most common for OWASP)
                {"sa", ""},         // H2 default admin
                {"dc", ""},         // OWASP specific user
                {"user", ""},       // Generic user
                {"owasp", ""}       // OWASP branded
            };
            
            SQLException lastException = null;
            boolean connected = false;
            
            for (String url : connectionVariants) {
                if (connected) break;
                
                logger.debug("Trying connection URL: {}", url);
                
                for (String[] credentials : credentialVariants) {
                    try {
                        connection = DriverManager.getConnection(url, credentials[0], credentials[1]);
                        logger.debug("✅ Connected successfully with user: '{}', URL: {}", credentials[0], url);
                        connected = true;
                        break;
                    } catch (SQLException e) {
                        lastException = e;
                        logger.debug("Failed connection attempt - user: '{}', error: {}", credentials[0], e.getMessage());
                    }
                }
            }
            
            if (!connected && lastException != null) {
                throw lastException;
            }
            logger.info("✅ Connected to local NVD database successfully");
        }
    }
    
    /**
     * Closes the database connection
     */
    public void close() {
        if (connection != null) {
            try {
                connection.close();
                logger.debug("Database connection closed");
            } catch (SQLException e) {
                logger.warn("Error closing database connection: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Queries the local database for vulnerability records that might have CVSSv4 data
     */
    public List<io.github.dodogeny.security.model.Vulnerability> queryLocalVulnerabilities(int limit) throws SQLException {
        connect();
        
        List<io.github.dodogeny.security.model.Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Query the VULNERABILITY table for CVE records
        String sql = "SELECT CVE, DESCRIPTION, CVSSV3_BASE_SCORE, CVSSV3_SEVERITY FROM VULNERABILITY WHERE CVE IS NOT NULL LIMIT ?";
        
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, limit);
            
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    io.github.dodogeny.security.model.Vulnerability vuln = new io.github.dodogeny.security.model.Vulnerability();
                    
                    String cveId = rs.getString("CVE");
                    String description = rs.getString("DESCRIPTION");
                    Double cvssScore = rs.getDouble("CVSSV3_BASE_SCORE");
                    if (rs.wasNull()) {
                        cvssScore = null;
                    }
                    String severity = rs.getString("CVSSV3_SEVERITY");
                    
                    vuln.setCveId(cveId);
                    vuln.setDescription(description);
                    vuln.setCvssV3Score(cvssScore);
                    vuln.setSeverity(severity != null ? severity : "UNKNOWN");
                    
                    // Set metadata
                    vuln.setSource("Local NVD Database");
                    vuln.setDiscoveredDate(LocalDateTime.now());
                    vuln.setLastVerified(LocalDateTime.now());
                    vuln.setDetectionMethod("H2 Database Query");
                    
                    vulnerabilities.add(vuln);
                }
            }
        }
        
        logger.info("📊 Queried {} vulnerabilities from local NVD database", vulnerabilities.size());
        return vulnerabilities;
    }
    
    /**
     * Gets total vulnerability count from local database
     */
    public long getTotalVulnerabilityCount() throws SQLException {
        connect();
        
        String sql = "SELECT COUNT(*) FROM VULNERABILITY WHERE CVE IS NOT NULL";
        try (PreparedStatement stmt = connection.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            if (rs.next()) {
                return rs.getLong(1);
            }
        }
        return 0;
    }
    
    /**
     * Static method to find the local NVD database path
     */
    public static String findLocalNvdDatabase() {
        // Dynamically discover OWASP Dependency Check NVD database locations
        List<String> possiblePaths = new ArrayList<>();
        String userHome = System.getProperty("user.home");
        String m2RepoPath = System.getProperty("maven.repo.local", userHome + "/.m2/repository");

        // Add common OWASP paths with version detection
        File owaspUtilsDir = new File(m2RepoPath, "org/owasp/dependency-check-utils");
        if (owaspUtilsDir.exists()) {
            File[] versions = owaspUtilsDir.listFiles(File::isDirectory);
            if (versions != null) {
                Arrays.sort(versions, (a, b) -> b.getName().compareTo(a.getName())); // Sort descending by version
                for (File versionDir : versions) {
                    File dataDir = new File(versionDir, "data");
                    if (dataDir.exists()) {
                        File[] dataDirs = dataDir.listFiles(File::isDirectory);
                        if (dataDirs != null) {
                            for (File nvdDataDir : dataDirs) {
                                possiblePaths.add(nvdDataDir.getAbsolutePath() + "/odc");
                            }
                        }
                    }
                }
            }
        }

        // Add fallback paths
        possiblePaths.add(userHome + "/.bastion/nvd-cache/odc");

        for (String path : possiblePaths) {
            File dbFile = new File(path + ".mv.db");
            if (dbFile.exists() && dbFile.length() > 50_000_000) { // Should be >50MB for complete database
                logger.info("🎯 Found local NVD database: {}", dbFile.getAbsolutePath());
                return path; // Return path without .mv.db extension for H2 connection
            }
        }
        
        logger.warn("❌ Could not find local NVD database in standard locations");
        return null;
    }
}