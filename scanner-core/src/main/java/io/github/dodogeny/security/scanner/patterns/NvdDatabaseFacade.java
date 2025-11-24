package io.github.dodogeny.security.scanner.patterns;

/**
 * Facade Pattern: Unified interface for NVD database operations.
 * Simplifies access to cache management, initialization, and updates.
 */
public interface NvdDatabaseFacade {

    /**
     * Checks if this is a first-time setup requiring database initialization.
     */
    boolean isFirstTimeSetup();

    /**
     * Checks if the local cache is valid (no network calls).
     */
    boolean isLocalCacheValid();

    /**
     * Checks if the cache is valid including remote checks.
     */
    boolean isCacheValid(String apiKey);

    /**
     * Checks if a valid database exists.
     */
    boolean hasValidDatabase();

    /**
     * Initializes the database for first-time users.
     * @return true if initialization was successful
     */
    boolean initializeDatabase();

    /**
     * Validates database after download and stores integrity information.
     * @return true if validation passed
     */
    boolean validateAfterDownload();

    /**
     * Updates cache metadata after successful operations.
     */
    void updateCacheMetadata();

    /**
     * Updates cache metadata with record count.
     */
    void updateCacheMetadata(long recordCount);

    /**
     * Clears the entire cache.
     */
    void clearCache();

    /**
     * Gets the cache directory path.
     */
    String getCacheDirectory();

    /**
     * Gets statistics about the database.
     */
    DatabaseStats getDatabaseStats();

    /**
     * Shuts down the facade and releases resources.
     */
    void shutdown();

    /**
     * Statistics about the NVD database.
     */
    class DatabaseStats {
        private long totalRecords;
        private long databaseSizeBytes;
        private String checksum;
        private long lastUpdateTime;
        private boolean valid;

        public long getTotalRecords() { return totalRecords; }
        public void setTotalRecords(long totalRecords) { this.totalRecords = totalRecords; }
        public long getDatabaseSizeBytes() { return databaseSizeBytes; }
        public void setDatabaseSizeBytes(long databaseSizeBytes) { this.databaseSizeBytes = databaseSizeBytes; }
        public String getChecksum() { return checksum; }
        public void setChecksum(String checksum) { this.checksum = checksum; }
        public long getLastUpdateTime() { return lastUpdateTime; }
        public void setLastUpdateTime(long lastUpdateTime) { this.lastUpdateTime = lastUpdateTime; }
        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
    }
}
