package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.scanner.NvdCacheManager;
import io.github.dodogeny.security.scanner.NvdDatabaseInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of NvdDatabaseFacade.
 * Delegates to existing NvdCacheManager and NvdDatabaseInitializer
 * without modifying their business logic.
 */
public class DefaultNvdDatabaseFacade implements NvdDatabaseFacade {

    private static final Logger logger = LoggerFactory.getLogger(DefaultNvdDatabaseFacade.class);

    private final NvdCacheManager cacheManager;
    private final NvdDatabaseInitializer databaseInitializer;
    private final String apiKey;

    public DefaultNvdDatabaseFacade(String cacheDirectory, long cacheValidityHours,
                                     int connectionTimeoutMs, String apiKey) {
        this.apiKey = apiKey;
        this.cacheManager = new NvdCacheManager(cacheDirectory, cacheValidityHours, connectionTimeoutMs);
        this.databaseInitializer = new NvdDatabaseInitializer(cacheDirectory, apiKey);
    }

    public DefaultNvdDatabaseFacade(NvdCacheManager cacheManager,
                                     NvdDatabaseInitializer databaseInitializer,
                                     String apiKey) {
        this.cacheManager = cacheManager;
        this.databaseInitializer = databaseInitializer;
        this.apiKey = apiKey;
    }

    @Override
    public boolean isFirstTimeSetup() {
        return databaseInitializer.isFirstTimeSetup();
    }

    @Override
    public boolean isLocalCacheValid() {
        return cacheManager.isLocalCacheValid();
    }

    @Override
    public boolean isCacheValid(String apiKey) {
        return cacheManager.isCacheValid(apiKey != null ? apiKey : this.apiKey);
    }

    @Override
    public boolean hasValidDatabase() {
        return databaseInitializer.hasValidDatabase();
    }

    @Override
    public boolean initializeDatabase() {
        NvdDatabaseInitializer.InitializationResult result = databaseInitializer.initializeDatabase();
        return result.isSuccess();
    }

    @Override
    public boolean validateAfterDownload() {
        NvdDatabaseInitializer.ValidationResult result = databaseInitializer.validateAfterDownload();
        return result.isValid();
    }

    @Override
    public void updateCacheMetadata() {
        cacheManager.updateCacheMetadata();
    }

    @Override
    public void updateCacheMetadata(long recordCount) {
        cacheManager.updateCacheMetadata(recordCount);
    }

    @Override
    public void clearCache() {
        cacheManager.clearCache();
    }

    @Override
    public String getCacheDirectory() {
        return cacheManager.getCacheDirectory();
    }

    @Override
    public DatabaseStats getDatabaseStats() {
        DatabaseStats stats = new DatabaseStats();

        NvdDatabaseInitializer.ValidationResult validation = databaseInitializer.validateAfterDownload();
        stats.setDatabaseSizeBytes(validation.getDatabaseSizeBytes());
        stats.setChecksum(validation.getChecksum());
        stats.setValid(validation.isValid());
        stats.setLastUpdateTime(System.currentTimeMillis());

        return stats;
    }

    @Override
    public void shutdown() {
        if (cacheManager != null) {
            cacheManager.shutdown();
        }
        logger.debug("NVD Database Facade shutdown completed");
    }

    /**
     * Gets the underlying cache manager for advanced operations.
     */
    public NvdCacheManager getCacheManager() {
        return cacheManager;
    }

    /**
     * Gets the underlying database initializer for advanced operations.
     */
    public NvdDatabaseInitializer getDatabaseInitializer() {
        return databaseInitializer;
    }
}
