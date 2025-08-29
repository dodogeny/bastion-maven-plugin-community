package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Properties;

/**
 * Manages NVD database caching with smart remote change detection.
 * Only downloads the database if there are actual changes on the NVD server.
 */
public class NvdCacheManager {
    
    private static final Logger logger = LoggerFactory.getLogger(NvdCacheManager.class);
    
    // NVD API endpoints for checking updates
    private static final String NVD_CVE_META_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta";
    private static final String NVD_CVE_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta";
    
    private static final String CACHE_METADATA_FILE = "nvd-cache.properties";
    private static final String LAST_UPDATE_CHECK_KEY = "last.update.check";
    private static final String LAST_REMOTE_MODIFIED_KEY = "last.remote.modified";
    private static final String CACHE_VERSION_KEY = "cache.version";
    private static final String CURRENT_CACHE_VERSION = "1.0";
    
    private final String cacheDirectory;
    private final long cacheValidityHours;
    private final int connectionTimeoutMs;
    
    public NvdCacheManager(String cacheDirectory, long cacheValidityHours, int connectionTimeoutMs) {
        this.cacheDirectory = cacheDirectory != null ? cacheDirectory : getDefaultCacheDirectory();
        this.cacheValidityHours = cacheValidityHours;
        this.connectionTimeoutMs = connectionTimeoutMs;
        
        ensureCacheDirectoryExists();
        logger.info("NVD Cache Manager initialized with cache directory: {} and validity: {} hours", 
                   this.cacheDirectory, cacheValidityHours);
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
                
                if (hoursSinceLastCheck < cacheValidityHours) {
                    logger.debug("Cache is still valid - {} hours since last check (validity: {} hours)", 
                                hoursSinceLastCheck, cacheValidityHours);
                    return true;
                }
            }
            
            // Check if remote NVD database has been modified
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                return checkRemoteModificationWithApi(metadata, apiKey.trim());
            } else {
                return checkRemoteModificationWithoutApi(metadata);
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
        try {
            Properties metadata = new Properties();
            metadata.setProperty(LAST_UPDATE_CHECK_KEY, String.valueOf(System.currentTimeMillis()));
            metadata.setProperty(CACHE_VERSION_KEY, CURRENT_CACHE_VERSION);
            
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
            logger.info("Cache metadata updated successfully");
            
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
    
    private boolean checkRemoteModificationWithApi(Properties metadata, String apiKey) {
        logger.debug("Checking remote NVD database changes with API key");
        
        // With API key, we can check more frequently and get better information
        try {
            long remoteModified = getRemoteLastModified(NVD_CVE_RECENT_URL);
            String lastRemoteModifiedStr = metadata.getProperty(LAST_REMOTE_MODIFIED_KEY);
            
            if (lastRemoteModifiedStr != null && remoteModified > 0) {
                long lastRemoteModified = Long.parseLong(lastRemoteModifiedStr);
                
                if (remoteModified <= lastRemoteModified) {
                    logger.info("NVD database unchanged - using cache (remote modified: {}, cached: {})", 
                               formatTimestamp(remoteModified), formatTimestamp(lastRemoteModified));
                    updateLastCheckTime();
                    return true;
                } else {
                    logger.info("NVD database updated - cache refresh needed (remote: {}, cached: {})", 
                               formatTimestamp(remoteModified), formatTimestamp(lastRemoteModified));
                    return false;
                }
            }
            
            // If we can't determine modification times, be conservative
            logger.info("Cannot determine remote modification time - forcing cache update");
            return false;
            
        } catch (Exception e) {
            logger.debug("Error checking remote modification with API: {}", e.getMessage());
            // Fallback to without API method
            return checkRemoteModificationWithoutApi(metadata);
        }
    }
    
    private boolean checkRemoteModificationWithoutApi(Properties metadata) {
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