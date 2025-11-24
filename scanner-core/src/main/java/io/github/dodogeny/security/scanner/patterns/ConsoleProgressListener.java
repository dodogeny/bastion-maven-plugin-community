package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import io.github.dodogeny.security.scanner.ConsoleLogger;

import java.time.Duration;
import java.time.Instant;

/**
 * Observer implementation: Console-based progress listener.
 * Uses Strategy pattern for configurable progress display.
 */
public class ConsoleProgressListener implements ScanEventListener {

    private final ProgressDisplayStrategy displayStrategy;
    private Instant scanStartTime;
    private Instant updateStartTime;
    private int vulnerabilityCount = 0;

    public ConsoleProgressListener() {
        this(new SingleLineProgressStrategy());
    }

    public ConsoleProgressListener(ProgressDisplayStrategy displayStrategy) {
        this.displayStrategy = displayStrategy;
    }

    @Override
    public void onScanStarted(String projectName, int totalDependencies) {
        scanStartTime = Instant.now();
        vulnerabilityCount = 0;

        ConsoleLogger.printSubHeader("SECURITY SCAN");
        ConsoleLogger.printKeyValue("Project", projectName);
        ConsoleLogger.printKeyValue("Dependencies", String.valueOf(totalDependencies));
    }

    @Override
    public void onScanProgress(int scannedCount, int totalCount, String currentDependency) {
        displayStrategy.displayRecordProgress(scannedCount, totalCount, scanStartTime, "Scanning");
    }

    @Override
    public void onVulnerabilityFound(Vulnerability vulnerability) {
        vulnerabilityCount++;

        // Don't clear progress for vulnerability notifications
        // Just count them for the summary
    }

    @Override
    public void onDatabaseUpdateStarted(long totalRecords) {
        updateStartTime = Instant.now();
        ConsoleLogger.info("Starting NVD database update ({} records)",
            ConsoleLogger.formatNumber(totalRecords));
    }

    @Override
    public void onDatabaseUpdateProgress(long current, long total) {
        displayStrategy.displayRecordProgress(current, total, updateStartTime, "Downloading NVD");
    }

    @Override
    public void onDatabaseUpdateCompleted(long durationMs) {
        displayStrategy.clearProgress();
        ConsoleLogger.success("NVD database update completed in {}",
            ConsoleLogger.formatDuration(durationMs));
    }

    @Override
    public void onScanCompleted(ScanResult result) {
        displayStrategy.clearProgress();

        Duration duration = scanStartTime != null ?
            Duration.between(scanStartTime, Instant.now()) : Duration.ZERO;

        int vulnCount = result.getVulnerabilities() != null ?
            result.getVulnerabilities().size() : vulnerabilityCount;

        ConsoleLogger.printCompletionSummary(
            true,
            duration,
            vulnCount,
            result.getDependencies() != null ? result.getDependencies().size() : 0
        );
    }

    @Override
    public void onScanFailed(String errorMessage, Exception exception) {
        displayStrategy.clearProgress();
        displayStrategy.displayError("Scan failed: " + errorMessage);

        if (exception != null) {
            ConsoleLogger.bullet("Exception: " + exception.getClass().getSimpleName());
            if (exception.getMessage() != null) {
                ConsoleLogger.bullet("Details: " + exception.getMessage());
            }
        }
    }

    @Override
    public void onInfo(String message) {
        displayStrategy.displayInfo(message);
    }

    @Override
    public void onWarning(String message) {
        displayStrategy.displayWarning(message);
    }

    @Override
    public void onError(String message) {
        displayStrategy.displayError(message);
    }
}
