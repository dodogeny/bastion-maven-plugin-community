package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Manages NVD database caching with smart remote change detection.
 * Only downloads the database if there are actual changes on the NVD server.
 */
public class NvdCacheManager {
    
    private static final Logger logger = LoggerFactory.getLogger(NvdCacheManager.class);
    
    // NVD API endpoints for checking updates
    private static final String NVD_CVE_META_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta";
    private static final String NVD_CVE_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta";
    private static final String NVD_API_2_0_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final Pattern TOTAL_RESULTS_PATTERN = Pattern.compile("\"totalResults\"\\s*:\\s*(\\d+)");
    
    private static final String CACHE_METADATA_FILE = "nvd-cache.properties";
    private static final String LAST_UPDATE_CHECK_KEY = "last.update.check";
    private static final String LAST_REMOTE_MODIFIED_KEY = "last.remote.modified";
    private static final String CACHE_VERSION_KEY = "cache.version";
    private static final String LAST_RECORD_COUNT_KEY = "last.record.count";
    private static final String UPDATE_THRESHOLD_KEY = "update.threshold.percent";
    private static final String CURRENT_CACHE_VERSION = "2.0"; // Bumped for new features
    
    private final String cacheDirectory;
    private final long cacheValidityHours;
    private final int connectionTimeoutMs;
    private final double updateThresholdPercent;
    
    public NvdCacheManager(String cacheDirectory, long cacheValidityHours, int connectionTimeoutMs) {
        this(cacheDirectory, cacheValidityHours, connectionTimeoutMs, 5.0); // Default 5% threshold
    }
    
    public NvdCacheManager(String cacheDirectory, long cacheValidityHours, int connectionTimeoutMs, double updateThresholdPercent) {
        this.cacheDirectory = cacheDirectory != null ? cacheDirectory : getDefaultCacheDirectory();
        this.cacheValidityHours = cacheValidityHours;
        this.connectionTimeoutMs = connectionTimeoutMs;
        this.updateThresholdPercent = updateThresholdPercent;
        
        ensureCacheDirectoryExists();
        logger.info("NVD Cache Manager initialized with cache directory: {}, validity: {} hours, update threshold: {}%", 
                   this.cacheDirectory, cacheValidityHours, updateThresholdPercent);
    }
    
    /**
     * Checks if the NVD database cache is valid and up to date.
     * Returns true if cache can be used, false if update is needed.
     */
    public boolean isCacheValid(String apiKey) {
        try {
            File metadataFile = new File(cacheDirectory, CACHE_METADATA_FILE);
            if (!metadataFile.exists()) {
                logger.info("No cache metadata found - cache update required");
                return false;
            }
            
            Properties metadata = loadCacheMetadata();
            
            // Check cache version compatibility
            String cacheVersion = metadata.getProperty(CACHE_VERSION_KEY);
            if (!CURRENT_CACHE_VERSION.equals(cacheVersion)) {
                logger.info("Cache version mismatch (expected: {}, found: {}) - cache update required", 
                           CURRENT_CACHE_VERSION, cacheVersion);
                return false;
            }
            
            // Check if enough time has passed since last check
            String lastCheckStr = metadata.getProperty(LAST_UPDATE_CHECK_KEY);
            if (lastCheckStr != null) {
                long lastCheck = Long.parseLong(lastCheckStr);
                long hoursSinceLastCheck = (System.currentTimeMillis() - lastCheck) / (1000 * 60 * 60);
                
                if (hoursSinceLastCheck >= cacheValidityHours) {
                    logger.info("Cache expired - {} hours since last check (validity: {} hours) - cache update required", 
                                hoursSinceLastCheck, cacheValidityHours);
                    return false;
                }
                
                logger.debug("Cache is still valid - {} hours since last check (validity: {} hours)", 
                            hoursSinceLastCheck, cacheValidityHours);
            }
            
            // Cache is within validity period, now check if remote NVD database has been modified or record count changed significantly
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                return checkRemoteChangesWithApi(metadata, apiKey.trim());
            } else {
                return checkRemoteChangesWithoutApi(metadata);
            }
            
        } catch (Exception e) {
            logger.warn("Error checking cache validity - forcing update: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Updates the cache metadata after a successful database update.
     */
    public void updateCacheMetadata() {
        updateCacheMetadata(-1); // Use -1 to indicate no record count available
    }
    
    /**
     * Updates the cache metadata with record count information.
     */
    public void updateCacheMetadata(long recordCount) {
        try {
            Properties metadata = new Properties();
            metadata.setProperty(LAST_UPDATE_CHECK_KEY, String.valueOf(System.currentTimeMillis()));
            metadata.setProperty(CACHE_VERSION_KEY, CURRENT_CACHE_VERSION);
            metadata.setProperty(UPDATE_THRESHOLD_KEY, String.valueOf(updateThresholdPercent));
            
            if (recordCount > 0) {
                metadata.setProperty(LAST_RECORD_COUNT_KEY, String.valueOf(recordCount));
                logger.debug("Stored record count: {}", recordCount);
            }
            
            // Try to get current remote modification time
            try {
                long remoteModified = getRemoteLastModified(NVD_CVE_RECENT_URL);
                if (remoteModified > 0) {
                    metadata.setProperty(LAST_REMOTE_MODIFIED_KEY, String.valueOf(remoteModified));
                }
            } catch (Exception e) {
                logger.debug("Could not get remote modification time: {}", e.getMessage());
            }
            
            saveCacheMetadata(metadata);
            logger.info("Cache metadata updated successfully" + (recordCount > 0 ? " with " + recordCount + " records" : ""));
            
        } catch (Exception e) {
            logger.warn("Failed to update cache metadata: {}", e.getMessage());
        }
    }
    
    /**
     * Gets the configured cache directory path.
     */
    public String getCacheDirectory() {
        return cacheDirectory;
    }
    
    /**
     * Clears the entire cache directory and metadata.
     */
    public void clearCache() {
        try {
            Path cachePath = Paths.get(cacheDirectory);
            if (Files.exists(cachePath)) {
                Files.walk(cachePath)
                    .filter(Files::isRegularFile)
                    .forEach(file -> {
                        try {
                            Files.delete(file);
                        } catch (IOException e) {
                            logger.warn("Could not delete cache file: {}", file);
                        }
                    });
                logger.info("Cache cleared successfully");
            }
        } catch (Exception e) {
            logger.warn("Error clearing cache: {}", e.getMessage());
        }
    }
    
    private boolean checkRemoteChangesWithApi(Properties metadata, String apiKey) {
        logger.debug("Checking remote NVD database changes with API key (optimized check)");
        
        try {
            // Quick exit: Check if we're within minimum check interval (e.g., 1 hour)
            String lastCheckStr = metadata.getProperty(LAST_UPDATE_CHECK_KEY);
            if (lastCheckStr != null) {
                long lastCheck = Long.parseLong(lastCheckStr);
                long minutesSinceLastCheck = (System.currentTimeMillis() - lastCheck) / (1000 * 60);
                
                // If checked within last hour, skip remote checks entirely
                if (minutesSinceLastCheck < 60) {
                    logger.debug("Skipping remote check - last check was {} minutes ago (minimum interval: 60 min)", minutesSinceLastCheck);
                    return true; // Cache is valid, no need for expensive network calls
                }
            }
            
            // First check timestamp-based changes (lighter check)
            long remoteModified = getRemoteLastModified(NVD_CVE_RECENT_URL);
            String lastRemoteModifiedStr = metadata.getProperty(LAST_REMOTE_MODIFIED_KEY);
            
            // Early exit if timestamp hasn't changed - avoid expensive API call
            if (lastRemoteModifiedStr != null) {
                long lastRemoteModified = Long.parseLong(lastRemoteModifiedStr);
                if (remoteModified <= lastRemoteModified) {
                    logger.debug("Timestamp unchanged - skipping record count check");
                    return true; // Cache is valid
                }
            }
            
            // Only check record count if timestamp changed
            Long remoteRecordCount = getRemoteRecordCount(apiKey);
            String lastRecordCountStr = metadata.getProperty(LAST_RECORD_COUNT_KEY);
            
            boolean timestampChanged = false;
            boolean significantRecordChange = false;
            
            // Timestamp analysis
            if (lastRemoteModifiedStr != null && remoteModified > 0) {
                long lastRemoteModified = Long.parseLong(lastRemoteModifiedStr);
                timestampChanged = remoteModified > lastRemoteModified;
                
                if (!timestampChanged) {
                    logger.debug("Timestamp unchanged - remote: {}, cached: {}", 
                               formatTimestamp(remoteModified), formatTimestamp(lastRemoteModified));
                }
            }
            
            // Record count analysis  
            if (remoteRecordCount != null && lastRecordCountStr != null) {
                try {
                    long lastRecordCount = Long.parseLong(lastRecordCountStr);
                    double changePercent = Math.abs((remoteRecordCount - lastRecordCount) * 100.0 / lastRecordCount);
                    significantRecordChange = changePercent >= updateThresholdPercent;
                    
                    logger.debug("Record count analysis - remote: {}, cached: {}, change: {:.2f}% (threshold: {}%)", 
                               remoteRecordCount, lastRecordCount, changePercent, updateThresholdPercent);
                } catch (NumberFormatException e) {
                    logger.debug("Invalid cached record count format: {}", lastRecordCountStr);
                }
            }
            
            // Decision logic: update if timestamp changed OR significant record count change
            if (!timestampChanged && !significantRecordChange) {
                if (remoteRecordCount != null && lastRecordCountStr != null) {
                    logger.info("🎯 Smart cache hit - NVD database unchanged (records: {}, change < {}%)", 
                               remoteRecordCount, updateThresholdPercent);
                } else {
                    logger.info("📅 Timestamp-based cache hit - NVD database unchanged");
                }
                updateLastCheckTime();
                return true;
            } else {
                if (timestampChanged && significantRecordChange) {
                    logger.info("🔄 Cache refresh needed - both timestamp and record count changed significantly");
                } else if (timestampChanged) {
                    logger.info("🔄 Cache refresh needed - timestamp updated (remote: {}, cached: {})", 
                               formatTimestamp(remoteModified), formatTimestamp(Long.parseLong(lastRemoteModifiedStr)));
                } else {
                    logger.info("🔄 Cache refresh needed - record count changed significantly by {:.1f}%", 
                               Math.abs((remoteRecordCount - Long.parseLong(lastRecordCountStr)) * 100.0 / Long.parseLong(lastRecordCountStr)));
                }
                return false;
            }
            
        } catch (Exception e) {
            logger.debug("Error checking remote changes with API: {}", e.getMessage());
            return checkRemoteChangesWithoutApi(metadata);
        }
    }
    
    private boolean checkRemoteChangesWithoutApi(Properties metadata) {
        logger.debug("Checking remote NVD database changes without API key");
        
        // Without API key, be more conservative and check less frequently
        try {
            // Check the modified metadata URL
            long remoteModified = getRemoteLastModified(NVD_CVE_MODIFIED_META_URL);
            String lastRemoteModifiedStr = metadata.getProperty(LAST_REMOTE_MODIFIED_KEY);
            
            if (lastRemoteModifiedStr != null && remoteModified > 0) {
                long lastRemoteModified = Long.parseLong(lastRemoteModifiedStr);
                
                // Without API key, be more conservative with updates
                long timeDifference = remoteModified - lastRemoteModified;
                long hoursDifference = timeDifference / (1000 * 60 * 60);
                
                if (hoursDifference < 1) { // Less than 1 hour difference
                    logger.info("NVD database appears unchanged - using cache");
                    updateLastCheckTime();
                    return true;
                } else {
                    logger.info("NVD database may have updates - cache refresh needed");
                    return false;
                }
            }
            
            // If we can't determine, default to updating every 24 hours without API key
            String lastCheckStr = metadata.getProperty(LAST_UPDATE_CHECK_KEY);
            if (lastCheckStr != null) {
                long lastCheck = Long.parseLong(lastCheckStr);
                long hoursSinceLastCheck = (System.currentTimeMillis() - lastCheck) / (1000 * 60 * 60);
                
                if (hoursSinceLastCheck < 24) {
                    logger.info("No API key - using 24-hour cache policy ({} hours since last update)", hoursSinceLastCheck);
                    return true;
                }
            }
            
            logger.info("No API key - 24+ hours elapsed, forcing cache update");
            return false;
            
        } catch (Exception e) {
            logger.debug("Error checking remote modification without API: {}", e.getMessage());
            // If all else fails, use time-based caching
            return isTimeBasedCacheValid(metadata);
        }
    }
    
    private boolean isTimeBasedCacheValid(Properties metadata) {
        String lastCheckStr = metadata.getProperty(LAST_UPDATE_CHECK_KEY);
        if (lastCheckStr != null) {
            long lastCheck = Long.parseLong(lastCheckStr);
            long hoursSinceLastCheck = (System.currentTimeMillis() - lastCheck) / (1000 * 60 * 60);
            
            boolean valid = hoursSinceLastCheck < cacheValidityHours;
            logger.info("Time-based cache check: {} hours elapsed (validity: {} hours) - cache {}",
                       hoursSinceLastCheck, cacheValidityHours, valid ? "valid" : "expired");
            return valid;
        }
        return false;
    }
    
    /**
     * Gets the total number of CVE records from NVD API 2.0
     */
    private Long getRemoteRecordCount(String apiKey) {
        HttpURLConnection connection = null;
        BufferedReader reader = null;
        
        try {
            String urlString = NVD_API_2_0_BASE_URL + "?resultsPerPage=1"; // Only need count, not actual records
            URL url = new URL(urlString);
            
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectionTimeoutMs);
            connection.setReadTimeout(connectionTimeoutMs);
            connection.setRequestProperty("User-Agent", "Bastion-Security-Scanner/2.0");
            
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                connection.setRequestProperty("apiKey", apiKey.trim());
            }
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                StringBuilder response = new StringBuilder();
                
                // Read only first few lines to find totalResults
                int lineCount = 0;
                while ((line = reader.readLine()) != null && lineCount < 10) {
                    response.append(line);
                    lineCount++;
                    
                    // Look for totalResults in the current accumulated response
                    Matcher matcher = TOTAL_RESULTS_PATTERN.matcher(response.toString());
                    if (matcher.find()) {
                        long totalResults = Long.parseLong(matcher.group(1));
                        logger.debug("Found totalResults from NVD API 2.0: {}", totalResults);
                        return totalResults;
                    }
                }
                
                logger.debug("Could not find totalResults in NVD API response");
                return null;
                
            } else {
                logger.debug("HTTP {} when checking NVD API 2.0 record count", responseCode);
                return null;
            }
            
        } catch (Exception e) {
            logger.debug("Error getting remote record count: {}", e.getMessage());
            return null;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.debug("Error closing reader: {}", e.getMessage());
                }
            }
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    private long getRemoteLastModified(String url) throws IOException {
        HttpURLConnection connection = null;
        try {
            URL nvdUrl = new URL(url);
            connection = (HttpURLConnection) nvdUrl.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(connectionTimeoutMs);
            connection.setReadTimeout(connectionTimeoutMs);
            connection.setRequestProperty("User-Agent", "Bastion-Security-Scanner/1.0");
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return connection.getLastModified();
            } else {
                logger.debug("HTTP {} when checking {}", responseCode, url);
                return 0;
            }
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    private void updateLastCheckTime() {
        try {
            Properties metadata = loadCacheMetadata();
            metadata.setProperty(LAST_UPDATE_CHECK_KEY, String.valueOf(System.currentTimeMillis()));
            saveCacheMetadata(metadata);
        } catch (Exception e) {
            logger.debug("Could not update last check time: {}", e.getMessage());
        }
    }
    
    private Properties loadCacheMetadata() throws IOException {
        Properties properties = new Properties();
        File metadataFile = new File(cacheDirectory, CACHE_METADATA_FILE);
        
        if (metadataFile.exists()) {
            try (FileInputStream fis = new FileInputStream(metadataFile)) {
                properties.load(fis);
            }
        }
        return properties;
    }
    
    private void saveCacheMetadata(Properties properties) throws IOException {
        File metadataFile = new File(cacheDirectory, CACHE_METADATA_FILE);
        try (FileOutputStream fos = new FileOutputStream(metadataFile)) {
            properties.store(fos, "NVD Cache Metadata - Generated by Bastion Security Scanner");
        }
    }
    
    private void ensureCacheDirectoryExists() {
        try {
            Path cachePath = Paths.get(cacheDirectory);
            if (!Files.exists(cachePath)) {
                Files.createDirectories(cachePath);
                logger.info("Created cache directory: {}", cacheDirectory);
            }
        } catch (IOException e) {
            logger.warn("Could not create cache directory: {} - {}", cacheDirectory, e.getMessage());
        }
    }
    
    private String getDefaultCacheDirectory() {
        String userHome = System.getProperty("user.home");
        return Paths.get(userHome, ".bastion", "nvd-cache").toString();
    }
    
    private String formatTimestamp(long timestamp) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), ZoneId.systemDefault()).toString();
    }
    
    // Correct URL for NVD CVE modified metadata
    private static final String NVD_CVE_MODIFIED_META_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta";
}