package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-performance parallel NVD database downloader with chunked downloads and connection pooling.
 * Provides significant performance improvements over single-threaded downloads.
 */
public class ParallelNvdDownloader {
    
    private static final Logger logger = LoggerFactory.getLogger(ParallelNvdDownloader.class);
    
    // NVD Data Feed URLs
    private static final String NVD_DATA_FEEDS_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1/";
    private static final String[] NVD_FEED_FILES = {
        "nvdcve-1.1-modified.json.gz",
        "nvdcve-1.1-recent.json.gz",
        "nvdcve-1.1-2024.json.gz",
        "nvdcve-1.1-2023.json.gz",
        "nvdcve-1.1-2022.json.gz"
    };
    
    private final int maxConcurrentDownloads;
    private final int chunkSizeBytes;
    private final int connectionTimeoutMs;
    private final int readTimeoutMs;
    private final String cacheDirectory;
    private final ExecutorService downloadExecutor;
    private final AtomicLong totalBytesDownloaded = new AtomicLong(0);
    
    /**
     * Configuration for parallel NVD downloader
     */
    public static class DownloadConfig {
        private int maxConcurrentDownloads = 4;
        private int chunkSizeBytes = 1024 * 1024; // 1MB chunks
        private int connectionTimeoutMs = 30000;
        private int readTimeoutMs = 60000;
        private boolean enableRangeRequests = true;
        private boolean enableProgressReporting = true;
        
        public int getMaxConcurrentDownloads() { return maxConcurrentDownloads; }
        public void setMaxConcurrentDownloads(int maxConcurrentDownloads) { this.maxConcurrentDownloads = maxConcurrentDownloads; }
        
        public int getChunkSizeBytes() { return chunkSizeBytes; }
        public void setChunkSizeBytes(int chunkSizeBytes) { this.chunkSizeBytes = chunkSizeBytes; }
        
        public int getConnectionTimeoutMs() { return connectionTimeoutMs; }
        public void setConnectionTimeoutMs(int connectionTimeoutMs) { this.connectionTimeoutMs = connectionTimeoutMs; }
        
        public int getReadTimeoutMs() { return readTimeoutMs; }
        public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }
        
        public boolean isEnableRangeRequests() { return enableRangeRequests; }
        public void setEnableRangeRequests(boolean enableRangeRequests) { this.enableRangeRequests = enableRangeRequests; }
        
        public boolean isEnableProgressReporting() { return enableProgressReporting; }
        public void setEnableProgressReporting(boolean enableProgressReporting) { this.enableProgressReporting = enableProgressReporting; }
    }
    
    /**
     * Download result with performance metrics
     */
    public static class DownloadResult {
        private final boolean success;
        private final long totalBytes;
        private final long durationMs;
        private final double averageSpeedMbps;
        private final int filesDownloaded;
        private final String errorMessage;
        
        public DownloadResult(boolean success, long totalBytes, long durationMs, int filesDownloaded, String errorMessage) {
            this.success = success;
            this.totalBytes = totalBytes;
            this.durationMs = durationMs;
            this.filesDownloaded = filesDownloaded;
            this.errorMessage = errorMessage;
            this.averageSpeedMbps = durationMs > 0 ? (totalBytes * 8.0 / 1024 / 1024) / (durationMs / 1000.0) : 0;
        }
        
        public boolean isSuccess() { return success; }
        public long getTotalBytes() { return totalBytes; }
        public long getDurationMs() { return durationMs; }
        public double getAverageSpeedMbps() { return averageSpeedMbps; }
        public int getFilesDownloaded() { return filesDownloaded; }
        public String getErrorMessage() { return errorMessage; }
        
        @Override
        public String toString() {
            if (success) {
                return String.format("Download completed: %d files, %.1f MB in %.1fs (%.1f Mbps)", 
                    filesDownloaded, totalBytes / 1024.0 / 1024.0, durationMs / 1000.0, averageSpeedMbps);
            } else {
                return String.format("Download failed: %s", errorMessage);
            }
        }
    }
    
    public ParallelNvdDownloader(String cacheDirectory, DownloadConfig config) {
        this.cacheDirectory = cacheDirectory;
        this.maxConcurrentDownloads = config.getMaxConcurrentDownloads();
        this.chunkSizeBytes = config.getChunkSizeBytes();
        this.connectionTimeoutMs = config.getConnectionTimeoutMs();
        this.readTimeoutMs = config.getReadTimeoutMs();
        this.downloadExecutor = Executors.newFixedThreadPool(maxConcurrentDownloads);
        
        ensureCacheDirectoryExists();
        
        logger.info("Parallel NVD Downloader initialized: {} threads, {} KB chunks, cache: {}", 
                   maxConcurrentDownloads, chunkSizeBytes / 1024, cacheDirectory);
    }
    
    /**
     * Downloads NVD database files in parallel with chunked downloads
     */
    public CompletableFuture<DownloadResult> downloadNvdDatabase(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            Instant startTime = Instant.now();
            logger.info("🚀 Starting parallel NVD database download...");
            
            try {
                // Create list of download tasks
                List<CompletableFuture<FileDownloadResult>> downloadTasks = new ArrayList<>();
                
                for (String fileName : NVD_FEED_FILES) {
                    String fileUrl = NVD_DATA_FEEDS_BASE + fileName;
                    File targetFile = new File(cacheDirectory, fileName);
                    
                    // Skip if file exists and is recent (less than 1 hour old)
                    if (targetFile.exists() && isFileRecent(targetFile, Duration.ofHours(1))) {
                        logger.debug("⏭️ Skipping recent file: {}", fileName);
                        continue;
                    }
                    
                    CompletableFuture<FileDownloadResult> downloadTask = 
                        downloadFileParallel(fileUrl, targetFile, apiKey);
                    downloadTasks.add(downloadTask);
                }
                
                if (downloadTasks.isEmpty()) {
                    logger.info("✅ All NVD files are up to date - no downloads needed");
                    return new DownloadResult(true, 0, 0, 0, null);
                }
                
                // Wait for all downloads to complete
                CompletableFuture<Void> allDownloads = CompletableFuture.allOf(
                    downloadTasks.toArray(new CompletableFuture[0]));
                
                allDownloads.get(); // Block until all complete
                
                // Collect results
                long totalBytes = 0;
                int successCount = 0;
                StringBuilder errors = new StringBuilder();
                
                for (CompletableFuture<FileDownloadResult> task : downloadTasks) {
                    FileDownloadResult result = task.get();
                    if (result.success) {
                        totalBytes += result.bytesDownloaded;
                        successCount++;
                    } else {
                        errors.append(result.fileName).append(": ").append(result.errorMessage).append("; ");
                    }
                }
                
                long durationMs = Duration.between(startTime, Instant.now()).toMillis();
                
                if (successCount == downloadTasks.size()) {
                    logger.info("✅ Parallel NVD download completed successfully!");
                    return new DownloadResult(true, totalBytes, durationMs, successCount, null);
                } else {
                    logger.warn("⚠️ Partial download success: {}/{} files", successCount, downloadTasks.size());
                    return new DownloadResult(false, totalBytes, durationMs, successCount, errors.toString());
                }
                
            } catch (Exception e) {
                long durationMs = Duration.between(startTime, Instant.now()).toMillis();
                logger.error("❌ Parallel NVD download failed", e);
                return new DownloadResult(false, 0, durationMs, 0, e.getMessage());
            }
        }, downloadExecutor);
    }
    
    /**
     * Downloads a single file using parallel chunked downloads
     */
    private CompletableFuture<FileDownloadResult> downloadFileParallel(String fileUrl, File targetFile, String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.info("📥 Downloading: {}", targetFile.getName());
                
                // First, get file size to determine if we can use range requests
                long fileSize = getFileSize(fileUrl, apiKey);
                
                if (fileSize <= 0 || fileSize < chunkSizeBytes * 2) {
                    // File too small for chunking, download normally
                    return downloadFileSingle(fileUrl, targetFile, apiKey);
                }
                
                // Calculate optimal number of chunks
                int numChunks = Math.min(maxConcurrentDownloads, (int) Math.ceil((double) fileSize / chunkSizeBytes));
                long chunkSize = fileSize / numChunks;
                
                logger.debug("📊 File size: {} MB, chunks: {}, chunk size: {} KB", 
                            fileSize / 1024 / 1024, numChunks, chunkSize / 1024);
                
                // Create temporary files for chunks
                List<CompletableFuture<ChunkDownloadResult>> chunkTasks = new ArrayList<>();
                List<File> chunkFiles = new ArrayList<>();
                
                for (int i = 0; i < numChunks; i++) {
                    long startByte = i * chunkSize;
                    long endByte = (i == numChunks - 1) ? fileSize - 1 : (startByte + chunkSize - 1);
                    
                    File chunkFile = new File(targetFile.getParent(), targetFile.getName() + ".chunk." + i);
                    chunkFiles.add(chunkFile);
                    
                    CompletableFuture<ChunkDownloadResult> chunkTask = 
                        downloadChunk(fileUrl, chunkFile, startByte, endByte, apiKey, i);
                    chunkTasks.add(chunkTask);
                }
                
                // Wait for all chunks to download
                CompletableFuture.allOf(chunkTasks.toArray(new CompletableFuture[0])).get();
                
                // Verify all chunks downloaded successfully
                for (CompletableFuture<ChunkDownloadResult> task : chunkTasks) {
                    ChunkDownloadResult result = task.get();
                    if (!result.success) {
                        // Cleanup chunk files on failure
                        cleanupChunkFiles(chunkFiles);
                        return new FileDownloadResult(false, targetFile.getName(), 0, result.errorMessage);
                    }
                }
                
                // Merge chunks into final file
                boolean mergeSuccess = mergeChunkFiles(chunkFiles, targetFile);
                cleanupChunkFiles(chunkFiles);
                
                if (mergeSuccess) {
                    long downloadedBytes = targetFile.length();
                    totalBytesDownloaded.addAndGet(downloadedBytes);
                    logger.info("✅ Successfully downloaded: {} ({} MB)", 
                               targetFile.getName(), downloadedBytes / 1024 / 1024);
                    return new FileDownloadResult(true, targetFile.getName(), downloadedBytes, null);
                } else {
                    return new FileDownloadResult(false, targetFile.getName(), 0, "Failed to merge chunks");
                }
                
            } catch (Exception e) {
                logger.error("❌ Failed to download {}: {}", targetFile.getName(), e.getMessage());
                return new FileDownloadResult(false, targetFile.getName(), 0, e.getMessage());
            }
        }, downloadExecutor);
    }
    
    /**
     * Downloads a single chunk of a file
     */
    private CompletableFuture<ChunkDownloadResult> downloadChunk(String fileUrl, File chunkFile, 
                                                               long startByte, long endByte, 
                                                               String apiKey, int chunkIndex) {
        return CompletableFuture.supplyAsync(() -> {
            HttpURLConnection connection = null;
            try {
                URL url = new URL(fileUrl);
                connection = (HttpURLConnection) url.openConnection();
                
                // Configure connection
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(connectionTimeoutMs);
                connection.setReadTimeout(readTimeoutMs);
                connection.setRequestProperty("User-Agent", "Bastion-Security-Scanner/2.0-Parallel");
                connection.setRequestProperty("Range", "bytes=" + startByte + "-" + endByte);
                
                if (apiKey != null && !apiKey.trim().isEmpty()) {
                    connection.setRequestProperty("apiKey", apiKey.trim());
                }
                
                int responseCode = connection.getResponseCode();
                if (responseCode != HttpURLConnection.HTTP_PARTIAL && responseCode != HttpURLConnection.HTTP_OK) {
                    return new ChunkDownloadResult(false, chunkIndex, 0, "HTTP " + responseCode);
                }
                
                // Download chunk
                try (InputStream inputStream = connection.getInputStream();
                     FileOutputStream outputStream = new FileOutputStream(chunkFile)) {
                    
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    long totalBytesRead = 0;
                    
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                    }
                    
                    logger.debug("✅ Chunk {} downloaded: {} KB", chunkIndex, totalBytesRead / 1024);
                    return new ChunkDownloadResult(true, chunkIndex, totalBytesRead, null);
                }
                
            } catch (Exception e) {
                logger.debug("❌ Chunk {} failed: {}", chunkIndex, e.getMessage());
                return new ChunkDownloadResult(false, chunkIndex, 0, e.getMessage());
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }, downloadExecutor);
    }
    
    /**
     * Downloads a file using traditional single-connection method
     */
    private FileDownloadResult downloadFileSingle(String fileUrl, File targetFile, String apiKey) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(fileUrl);
            connection = (HttpURLConnection) url.openConnection();
            
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(connectionTimeoutMs);
            connection.setReadTimeout(readTimeoutMs);
            connection.setRequestProperty("User-Agent", "Bastion-Security-Scanner/2.0");
            
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                connection.setRequestProperty("apiKey", apiKey.trim());
            }
            
            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                return new FileDownloadResult(false, targetFile.getName(), 0, "HTTP " + responseCode);
            }
            
            try (InputStream inputStream = connection.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(targetFile)) {
                
                byte[] buffer = new byte[8192];
                int bytesRead;
                long totalBytesRead = 0;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                }
                
                totalBytesDownloaded.addAndGet(totalBytesRead);
                logger.info("✅ Downloaded: {} ({} MB)", targetFile.getName(), totalBytesRead / 1024 / 1024);
                return new FileDownloadResult(true, targetFile.getName(), totalBytesRead, null);
            }
            
        } catch (Exception e) {
            logger.error("❌ Failed to download {}: {}", targetFile.getName(), e.getMessage());
            return new FileDownloadResult(false, targetFile.getName(), 0, e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    /**
     * Gets the size of a remote file
     */
    private long getFileSize(String fileUrl, String apiKey) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(fileUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(connectionTimeoutMs);
            connection.setReadTimeout(readTimeoutMs);
            connection.setRequestProperty("User-Agent", "Bastion-Security-Scanner/2.0");
            
            if (apiKey != null && !apiKey.trim().isEmpty()) {
                connection.setRequestProperty("apiKey", apiKey.trim());
            }
            
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                return connection.getContentLengthLong();
            }
            
        } catch (Exception e) {
            logger.debug("Could not get file size for {}: {}", fileUrl, e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        return -1;
    }
    
    /**
     * Merges chunk files into the final target file
     */
    private boolean mergeChunkFiles(List<File> chunkFiles, File targetFile) {
        try (FileOutputStream output = new FileOutputStream(targetFile)) {
            for (File chunkFile : chunkFiles) {
                if (!chunkFile.exists()) {
                    logger.error("Missing chunk file: {}", chunkFile.getName());
                    return false;
                }
                
                Files.copy(chunkFile.toPath(), output);
            }
            return true;
        } catch (Exception e) {
            logger.error("Failed to merge chunks for {}: {}", targetFile.getName(), e.getMessage());
            return false;
        }
    }
    
    /**
     * Cleans up temporary chunk files
     */
    private void cleanupChunkFiles(List<File> chunkFiles) {
        for (File chunkFile : chunkFiles) {
            if (chunkFile.exists()) {
                try {
                    Files.delete(chunkFile.toPath());
                } catch (Exception e) {
                    logger.debug("Could not delete chunk file {}: {}", chunkFile.getName(), e.getMessage());
                }
            }
        }
    }
    
    /**
     * Checks if a file was modified within the specified duration
     */
    private boolean isFileRecent(File file, Duration maxAge) {
        if (!file.exists()) return false;
        
        long fileAge = System.currentTimeMillis() - file.lastModified();
        return fileAge < maxAge.toMillis();
    }
    
    /**
     * Ensures the cache directory exists
     */
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
    
    /**
     * Shuts down the download executor
     */
    public void shutdown() {
        if (downloadExecutor != null && !downloadExecutor.isShutdown()) {
            downloadExecutor.shutdown();
            logger.debug("Parallel downloader executor shutdown");
        }
    }
    
    /**
     * Gets current download progress statistics
     */
    public long getTotalBytesDownloaded() {
        return totalBytesDownloaded.get();
    }
    
    // Inner classes for results
    private static class FileDownloadResult {
        final boolean success;
        final String fileName;
        final long bytesDownloaded;
        final String errorMessage;
        
        FileDownloadResult(boolean success, String fileName, long bytesDownloaded, String errorMessage) {
            this.success = success;
            this.fileName = fileName;
            this.bytesDownloaded = bytesDownloaded;
            this.errorMessage = errorMessage;
        }
    }
    
    private static class ChunkDownloadResult {
        final boolean success;
        final int chunkIndex;
        final long bytesDownloaded;
        final String errorMessage;
        
        ChunkDownloadResult(boolean success, int chunkIndex, long bytesDownloaded, String errorMessage) {
            this.success = success;
            this.chunkIndex = chunkIndex;
            this.bytesDownloaded = bytesDownloaded;
            this.errorMessage = errorMessage;
        }
    }
}