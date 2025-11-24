package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;

import java.util.List;

/**
 * Observer Pattern: Interface for listening to scan events.
 * Allows decoupling of scan logic from UI/logging/notification concerns.
 */
public interface ScanEventListener {

    /**
     * Called when a scan starts.
     */
    default void onScanStarted(String projectName, int totalDependencies) {}

    /**
     * Called to report scan progress.
     */
    default void onScanProgress(int scannedCount, int totalCount, String currentDependency) {}

    /**
     * Called when a vulnerability is found.
     */
    default void onVulnerabilityFound(Vulnerability vulnerability) {}

    /**
     * Called when database update starts.
     */
    default void onDatabaseUpdateStarted(long totalRecords) {}

    /**
     * Called to report database update progress.
     */
    default void onDatabaseUpdateProgress(long current, long total) {}

    /**
     * Called when database update completes.
     */
    default void onDatabaseUpdateCompleted(long durationMs) {}

    /**
     * Called when scan completes successfully.
     */
    default void onScanCompleted(ScanResult result) {}

    /**
     * Called when scan fails.
     */
    default void onScanFailed(String errorMessage, Exception exception) {}

    /**
     * Called for informational messages.
     */
    default void onInfo(String message) {}

    /**
     * Called for warning messages.
     */
    default void onWarning(String message) {}

    /**
     * Called for error messages.
     */
    default void onError(String message) {}
}
