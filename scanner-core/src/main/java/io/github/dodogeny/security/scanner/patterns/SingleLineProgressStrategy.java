package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.scanner.ConsoleLogger;
import java.time.Instant;

/**
 * Strategy implementation: Single-line progress display (Linux-style).
 * Updates progress on the same line using carriage return.
 */
public class SingleLineProgressStrategy implements ProgressDisplayStrategy {

    private Instant startTime;
    private boolean progressActive = false;

    @Override
    public void displayRecordProgress(long current, long total, Instant startTime, String operation) {
        if (!progressActive) {
            progressActive = true;
            ConsoleLogger.startProgress();
        }
        this.startTime = startTime;
        ConsoleLogger.printRecordProgress(current, total, startTime, operation);
    }

    @Override
    public void displayDownloadProgress(long bytesDownloaded, long totalBytes, Instant startTime, String filename) {
        if (!progressActive) {
            progressActive = true;
            ConsoleLogger.startProgress();
        }
        this.startTime = startTime;
        ConsoleLogger.printDownloadProgress(bytesDownloaded, totalBytes, startTime, filename);
    }

    @Override
    public void displaySuccess(String message) {
        if (progressActive) {
            ConsoleLogger.clearProgressLine();
        }
        ConsoleLogger.success(message);
    }

    @Override
    public void displayWarning(String message) {
        if (progressActive) {
            ConsoleLogger.clearProgressLine();
        }
        ConsoleLogger.warning(message);
    }

    @Override
    public void displayError(String message) {
        if (progressActive) {
            ConsoleLogger.clearProgressLine();
        }
        ConsoleLogger.error(message);
    }

    @Override
    public void displayInfo(String message) {
        if (progressActive) {
            ConsoleLogger.clearProgressLine();
        }
        ConsoleLogger.info(message);
    }

    @Override
    public void clearProgress() {
        if (progressActive) {
            ConsoleLogger.clearProgressLine();
            progressActive = false;
        }
    }

    @Override
    public void finalize() {
        progressActive = false;
    }
}
