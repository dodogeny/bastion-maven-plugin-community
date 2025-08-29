package io.github.dodogeny.security.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for NVD Cache Manager functionality.
 */
class NvdCacheManagerTest {
    
    @TempDir
    Path tempDir;
    
    private NvdCacheManager cacheManager;
    private String cacheDirectory;
    
    @BeforeEach
    void setUp() {
        cacheDirectory = tempDir.resolve("nvd-cache").toString();
        cacheManager = new NvdCacheManager(cacheDirectory, 6, 5000);
    }
    
    @Test
    @DisplayName("Should create cache directory if it doesn't exist")
    void shouldCreateCacheDirectory() {
        assertDoesNotThrow(() -> {
            new NvdCacheManager(tempDir.resolve("new-cache").toString(), 6, 5000);
        });
        
        assertTrue(tempDir.resolve("new-cache").toFile().exists());
    }
    
    @Test
    @DisplayName("Should return false for cache validity when no metadata exists")
    void shouldReturnFalseWhenNoMetadata() {
        boolean isValid = cacheManager.isCacheValid("test-api-key");
        assertFalse(isValid, "Cache should be invalid when no metadata exists");
    }
    
    @Test
    @DisplayName("Should return false for cache validity when cache version mismatch")
    void shouldReturnFalseWhenVersionMismatch() throws IOException {
        // Create metadata with wrong version
        Properties metadata = new Properties();
        metadata.setProperty("cache.version", "0.5");
        metadata.setProperty("last.update.check", String.valueOf(System.currentTimeMillis()));
        
        File metadataFile = new File(cacheDirectory, "nvd-cache.properties");
        metadataFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(metadataFile)) {
            metadata.store(fos, "Test metadata");
        }
        
        boolean isValid = cacheManager.isCacheValid("test-api-key");
        assertFalse(isValid, "Cache should be invalid when version mismatches");
    }
    
    @Test
    @DisplayName("Should return true for cache validity when recently checked and valid")
    void shouldReturnTrueWhenRecentlyValid() throws IOException {
        // Create recent valid metadata
        Properties metadata = new Properties();
        metadata.setProperty("cache.version", "1.0");
        metadata.setProperty("last.update.check", String.valueOf(System.currentTimeMillis() - (2 * 60 * 60 * 1000))); // 2 hours ago
        
        File metadataFile = new File(cacheDirectory, "nvd-cache.properties");
        metadataFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(metadataFile)) {
            metadata.store(fos, "Test metadata");
        }
        
        boolean isValid = cacheManager.isCacheValid("test-api-key");
        assertTrue(isValid, "Cache should be valid when recently checked (within validity period)");
    }
    
    @Test
    @DisplayName("Should return false for cache validity when expired")
    void shouldReturnFalseWhenExpired() throws IOException {
        // Create expired metadata (more than 6 hours old)
        Properties metadata = new Properties();
        metadata.setProperty("cache.version", "1.0");
        metadata.setProperty("last.update.check", String.valueOf(System.currentTimeMillis() - (8 * 60 * 60 * 1000))); // 8 hours ago
        
        File metadataFile = new File(cacheDirectory, "nvd-cache.properties");
        metadataFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(metadataFile)) {
            metadata.store(fos, "Test metadata");
        }
        
        boolean isValid = cacheManager.isCacheValid("test-api-key");
        assertFalse(isValid, "Cache should be invalid when expired");
    }
    
    @Test
    @DisplayName("Should update cache metadata successfully")
    void shouldUpdateCacheMetadata() {
        assertDoesNotThrow(() -> cacheManager.updateCacheMetadata());
        
        File metadataFile = new File(cacheDirectory, "nvd-cache.properties");
        assertTrue(metadataFile.exists(), "Metadata file should be created");
        assertTrue(metadataFile.length() > 0, "Metadata file should not be empty");
    }
    
    @Test
    @DisplayName("Should clear cache successfully")
    void shouldClearCache() throws IOException {
        // Create some cache files
        new File(cacheDirectory).mkdirs();
        File testFile = new File(cacheDirectory, "test.cache");
        assertTrue(testFile.createNewFile());
        
        cacheManager.clearCache();
        
        assertFalse(testFile.exists(), "Cache files should be deleted");
    }
    
    @Test
    @DisplayName("Should handle invalid cache directory gracefully")
    void shouldHandleInvalidCacheDirectory() {
        // Test with a path that can't be created (like a file path instead of directory)
        String invalidPath = tempDir.resolve("invalid-path.txt").toString();
        
        assertDoesNotThrow(() -> {
            NvdCacheManager invalidCacheManager = new NvdCacheManager(invalidPath, 6, 5000);
            invalidCacheManager.isCacheValid("test-key");
        }, "Should handle invalid cache directory gracefully");
    }
    
    @Test
    @DisplayName("Should use default cache directory when null provided")
    void shouldUseDefaultCacheDirectory() {
        NvdCacheManager defaultCacheManager = new NvdCacheManager(null, 6, 5000);
        
        String cacheDir = defaultCacheManager.getCacheDirectory();
        assertNotNull(cacheDir, "Cache directory should not be null");
        assertTrue(cacheDir.contains(".bastion"), "Should use default bastion cache directory");
        assertTrue(cacheDir.contains("nvd-cache"), "Should use nvd-cache subdirectory");
    }
    
    @Test
    @DisplayName("Should return correct cache directory")
    void shouldReturnCorrectCacheDirectory() {
        assertEquals(cacheDirectory, cacheManager.getCacheDirectory());
    }
}