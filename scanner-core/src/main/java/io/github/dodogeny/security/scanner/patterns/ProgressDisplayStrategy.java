package io.github.dodogeny.security.scanner.patterns;

import java.time.Instant;

/**
 * Strategy Pattern: Defines different ways to display progress.
 * Allows switching between single-line (Linux-style) and multi-line progress display.
 */
public interface ProgressDisplayStrategy {

    /**
     * Display record-based progress (e.g., downloading CVEs).
     */
    void displayRecordProgress(long current, long total, Instant startTime, String operation);

    /**
     * Display byte-based progress (e.g., file downloads).
     */
    void displayDownloadProgress(long bytesDownloaded, long totalBytes, Instant startTime, String filename);

    /**
     * Display a success message.
     */
    void displaySuccess(String message);

    /**
     * Display a warning message.
     */
    void displayWarning(String message);

    /**
     * Display an error message.
     */
    void displayError(String message);

    /**
     * Display an info message.
     */
    void displayInfo(String message);

    /**
     * Clear any active progress display.
     */
    void clearProgress();

    /**
     * Finalize the progress display (show completion).
     */
    void finalize();
}
