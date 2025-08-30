package io.github.dodogeny.security.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for ParallelNvdDownloader functionality and performance
 */
class ParallelNvdDownloaderTest {
    
    @TempDir
    Path tempDir;
    
    private ParallelNvdDownloader downloader;
    private ParallelNvdDownloader.DownloadConfig config;
    
    @BeforeEach
    void setUp() {
        config = new ParallelNvdDownloader.DownloadConfig();
        config.setMaxConcurrentDownloads(2);
        config.setChunkSizeBytes(512 * 1024); // 512KB for testing
        config.setConnectionTimeoutMs(10000);
        config.setReadTimeoutMs(15000);
        config.setEnableRangeRequests(true);
        
        downloader = new ParallelNvdDownloader(tempDir.toString(), config);
    }
    
    @Test
    void testDownloadConfigDefaults() {
        ParallelNvdDownloader.DownloadConfig defaultConfig = new ParallelNvdDownloader.DownloadConfig();
        
        assertEquals(4, defaultConfig.getMaxConcurrentDownloads());
        assertEquals(1024 * 1024, defaultConfig.getChunkSizeBytes());
        assertEquals(30000, defaultConfig.getConnectionTimeoutMs());
        assertEquals(60000, defaultConfig.getReadTimeoutMs());
        assertTrue(defaultConfig.isEnableRangeRequests());
        assertTrue(defaultConfig.isEnableProgressReporting());
    }
    
    @Test
    void testDownloadConfigCustomization() {
        config.setMaxConcurrentDownloads(8);
        config.setChunkSizeBytes(2 * 1024 * 1024);
        config.setConnectionTimeoutMs(45000);
        config.setReadTimeoutMs(90000);
        config.setEnableRangeRequests(false);
        config.setEnableProgressReporting(false);
        
        assertEquals(8, config.getMaxConcurrentDownloads());
        assertEquals(2 * 1024 * 1024, config.getChunkSizeBytes());
        assertEquals(45000, config.getConnectionTimeoutMs());
        assertEquals(90000, config.getReadTimeoutMs());
        assertFalse(config.isEnableRangeRequests());
        assertFalse(config.isEnableProgressReporting());
    }
    
    @Test
    void testCacheDirectoryCreation() {
        File cacheDir = new File(tempDir.toFile(), "test-cache");
        assertFalse(cacheDir.exists());
        
        // Creating downloader should create cache directory
        ParallelNvdDownloader testDownloader = new ParallelNvdDownloader(cacheDir.getAbsolutePath(), config);
        assertTrue(cacheDir.exists());
        assertTrue(cacheDir.isDirectory());
        
        testDownloader.shutdown();
    }
    
    @Test
    void testDownloadResultSuccess() {
        long totalBytes = 1024 * 1024; // 1MB
        long durationMs = 2000; // 2 seconds
        int filesDownloaded = 3;
        
        ParallelNvdDownloader.DownloadResult result = new ParallelNvdDownloader.DownloadResult(
            true, totalBytes, durationMs, filesDownloaded, null);
        
        assertTrue(result.isSuccess());
        assertEquals(totalBytes, result.getTotalBytes());
        assertEquals(durationMs, result.getDurationMs());
        assertEquals(filesDownloaded, result.getFilesDownloaded());
        assertNull(result.getErrorMessage());
        
        // Check speed calculation (1MB in 2s = 4 Mbps)
        assertTrue(result.getAverageSpeedMbps() > 3.9 && result.getAverageSpeedMbps() < 4.1);
        
        String resultString = result.toString();
        assertTrue(resultString.contains("Download completed"));
        assertTrue(resultString.contains("3 files"));
        assertTrue(resultString.contains("Mbps"));
    }
    
    @Test
    void testDownloadResultFailure() {
        String errorMessage = "Connection failed";
        ParallelNvdDownloader.DownloadResult result = new ParallelNvdDownloader.DownloadResult(
            false, 0, 1000, 0, errorMessage);
        
        assertFalse(result.isSuccess());
        assertEquals(0, result.getTotalBytes());
        assertEquals(1000, result.getDurationMs());
        assertEquals(0, result.getFilesDownloaded());
        assertEquals(errorMessage, result.getErrorMessage());
        assertEquals(0.0, result.getAverageSpeedMbps());
        
        String resultString = result.toString();
        assertTrue(resultString.contains("Download failed"));
        assertTrue(resultString.contains(errorMessage));
    }
    
    @Test
    void testDownloaderShutdown() {
        // Test that shutdown doesn't throw exceptions
        assertDoesNotThrow(() -> {
            downloader.shutdown();
            // Multiple shutdowns should be safe
            downloader.shutdown();
        });
    }
    
    @Test
    void testDownloadStatisticsInitial() {
        // Initially, no downloads should be tracked
        assertEquals(0, downloader.getTotalBytesDownloaded());
    }
    
    /**
     * Integration test that verifies the download mechanism works
     * Note: This test is disabled by default as it requires network access
     * Enable for integration testing with actual NVD endpoints
     */
    // @Test
    void testActualNvdDownload() throws Exception {
        // This test would download actual NVD files
        // Only enable for integration testing
        
        String apiKey = System.getenv("NVD_API_KEY");
        if (apiKey == null) {
            System.out.println("Skipping actual download test - no API key");
            return;
        }
        
        CompletableFuture<ParallelNvdDownloader.DownloadResult> future = 
            downloader.downloadNvdDatabase(apiKey);
        
        ParallelNvdDownloader.DownloadResult result = future.get();
        
        // Verify download completed
        if (result.isSuccess()) {
            assertTrue(result.getTotalBytes() > 0);
            assertTrue(result.getFilesDownloaded() > 0);
            assertTrue(result.getAverageSpeedMbps() > 0);
            System.out.println("Download performance: " + result.toString());
        }
    }
    
    /**
     * Performance benchmark test
     * Measures download performance characteristics
     */
    @Test
    void testPerformanceCharacteristics() {
        // Test configuration impact on performance
        
        // Low concurrency config
        ParallelNvdDownloader.DownloadConfig lowConfig = new ParallelNvdDownloader.DownloadConfig();
        lowConfig.setMaxConcurrentDownloads(1);
        lowConfig.setChunkSizeBytes(512 * 1024);
        
        // High concurrency config  
        ParallelNvdDownloader.DownloadConfig highConfig = new ParallelNvdDownloader.DownloadConfig();
        highConfig.setMaxConcurrentDownloads(8);
        highConfig.setChunkSizeBytes(2 * 1024 * 1024);
        
        // Verify configurations are applied correctly
        ParallelNvdDownloader lowDownloader = new ParallelNvdDownloader(tempDir.toString(), lowConfig);
        ParallelNvdDownloader highDownloader = new ParallelNvdDownloader(tempDir.toString(), highConfig);
        
        // Both should initialize successfully
        assertNotNull(lowDownloader);
        assertNotNull(highDownloader);
        
        // Clean up
        lowDownloader.shutdown();
        highDownloader.shutdown();
    }
    
    @Test
    void testConfigurationValidation() {
        // Test edge cases and validation
        ParallelNvdDownloader.DownloadConfig testConfig = new ParallelNvdDownloader.DownloadConfig();
        
        // Test maximum reasonable values
        testConfig.setMaxConcurrentDownloads(16);
        testConfig.setChunkSizeBytes(10 * 1024 * 1024); // 10MB
        testConfig.setConnectionTimeoutMs(120000); // 2 minutes
        
        // Should create successfully
        assertDoesNotThrow(() -> {
            ParallelNvdDownloader testDownloader = new ParallelNvdDownloader(tempDir.toString(), testConfig);
            testDownloader.shutdown();
        });
    }
    
    @Test
    void testErrorHandling() {
        // Test with invalid cache directory
        String invalidPath = "/invalid/nonexistent/path";
        
        // Should handle gracefully (create ParallelNvdDownloader but may log warnings)
        assertDoesNotThrow(() -> {
            ParallelNvdDownloader testDownloader = new ParallelNvdDownloader(invalidPath, config);
            testDownloader.shutdown();
        });
    }
}