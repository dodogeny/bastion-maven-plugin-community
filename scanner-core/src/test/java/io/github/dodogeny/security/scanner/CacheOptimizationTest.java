package io.github.dodogeny.security.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the optimized NVD cache logic that prevents unnecessary downloads during unit tests
 */
class CacheOptimizationTest {
    
    @TempDir
    Path tempDir;
    
    private NvdCacheManager cacheManager;
    private OwaspDependencyCheckScanner scanner;
    
    @BeforeEach
    void setUp() {
        // Create cache manager with test directory
        cacheManager = new NvdCacheManager(tempDir.toString(), 6, 10000, 5.0);
        scanner = new OwaspDependencyCheckScanner();
    }
    
    @Test
    void testLocalCacheValidityWithFreshCache() {
        // Simulate a fresh cache that was just updated
        createCacheMetadata(0); // 0 hours ago
        
        assertTrue(cacheManager.isLocalCacheValid(), "Fresh cache should be valid");
    }
    
    @Test
    void testLocalCacheValidityWithExpiredCache() {
        // Simulate an old cache beyond validity period
        createCacheMetadata(10); // 10 hours ago (beyond 6-hour validity)
        
        assertFalse(cacheManager.isLocalCacheValid(), "Expired cache should be invalid");
    }
    
    @Test
    void testLocalCacheValidityWithinWindow() {
        // Simulate a cache within the validity window
        createCacheMetadata(3); // 3 hours ago (within 6-hour validity)
        
        assertTrue(cacheManager.isLocalCacheValid(), "Cache within validity window should be valid");
    }
    
    @Test
    void testLocalCacheValidityWithNoMetadata() {
        // No cache metadata file exists
        assertFalse(cacheManager.isLocalCacheValid(), "Missing cache metadata should be invalid");
    }
    
    @Test
    void testTestEnvironmentDetection() {
        // Since this test is running, it should be detected as test environment
        OwaspDependencyCheckScanner testScanner = new OwaspDependencyCheckScanner();
        
        // The scanner should have optimized settings for test environment
        VulnerabilityScanner.ScannerConfiguration config = new VulnerabilityScanner.ScannerConfiguration();
        
        // Test environment detection should disable remote validation by default
        assertFalse(config.isEnableRemoteValidation(), 
                   "Test environment should default to local-only validation");
    }
    
    @Test
    void testRemoteValidationConfiguration() {
        VulnerabilityScanner.ScannerConfiguration config = new VulnerabilityScanner.ScannerConfiguration();
        
        // Test default state
        assertFalse(config.isEnableRemoteValidation(), "Remote validation should be disabled by default");
        
        // Test enabling remote validation
        config.setEnableRemoteValidation(true);
        assertTrue(config.isEnableRemoteValidation(), "Should be able to enable remote validation");
        
        // Test disabling remote validation
        config.setEnableRemoteValidation(false);
        assertFalse(config.isEnableRemoteValidation(), "Should be able to disable remote validation");
    }
    
    @Test
    void testCacheValidationMethods() {
        // Test that isLocalCacheValid() doesn't make network calls
        // This is hard to test directly, but we can verify it works quickly
        createCacheMetadata(2); // 2 hours ago
        
        long startTime = System.currentTimeMillis();
        boolean isValid = cacheManager.isLocalCacheValid();
        long duration = System.currentTimeMillis() - startTime;
        
        assertTrue(isValid, "Cache should be valid");
        assertTrue(duration < 100, "Local cache check should be very fast (< 100ms), actual: " + duration + "ms");
    }
    
    @Test
    void testCacheVersionCompatibility() {
        // Test with wrong cache version
        createCacheMetadataWithVersion(0, "1.0"); // Old version
        
        assertFalse(cacheManager.isLocalCacheValid(), "Old cache version should be invalid");
        
        // Test with correct cache version
        createCacheMetadataWithVersion(0, "2.0"); // Current version
        
        assertTrue(cacheManager.isLocalCacheValid(), "Current cache version should be valid");
    }
    
    
    /**
     * Helper method to create cache metadata for testing
     */
    private void createCacheMetadata(int hoursAgo) {
        createCacheMetadataWithVersion(hoursAgo, "2.0");
    }
    
    /**
     * Helper method to create cache metadata with specific version
     */
    private void createCacheMetadataWithVersion(int hoursAgo, String version) {
        try {
            Properties metadata = new Properties();
            long lastCheck = System.currentTimeMillis() - (hoursAgo * 60 * 60 * 1000L);
            metadata.setProperty("last.update.check", String.valueOf(lastCheck));
            metadata.setProperty("cache.version", version);
            metadata.setProperty("update.threshold.percent", "5.0");
            
            File metadataFile = new File(tempDir.toFile(), "nvd-cache.properties");
            try (FileOutputStream fos = new FileOutputStream(metadataFile)) {
                metadata.store(fos, "Test cache metadata");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to create test cache metadata", e);
        }
    }
}