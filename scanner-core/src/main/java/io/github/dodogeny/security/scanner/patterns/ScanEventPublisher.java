package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Observer Pattern: Publisher that manages scan event listeners.
 * Thread-safe implementation for concurrent scan operations.
 */
public class ScanEventPublisher {

    private static final ScanEventPublisher INSTANCE = new ScanEventPublisher();

    private final List<ScanEventListener> listeners = new CopyOnWriteArrayList<>();

    private ScanEventPublisher() {}

    /**
     * Gets the singleton instance.
     */
    public static ScanEventPublisher getInstance() {
        return INSTANCE;
    }

    /**
     * Registers a listener for scan events.
     */
    public void addListener(ScanEventListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * Removes a listener.
     */
    public void removeListener(ScanEventListener listener) {
        listeners.remove(listener);
    }

    /**
     * Clears all listeners.
     */
    public void clearListeners() {
        listeners.clear();
    }

    /**
     * Gets the number of registered listeners.
     */
    public int getListenerCount() {
        return listeners.size();
    }

    // Event publishing methods

    public void publishScanStarted(String projectName, int totalDependencies) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onScanStarted(projectName, totalDependencies);
            } catch (Exception e) {
                // Log but don't fail - listeners shouldn't break the scan
            }
        }
    }

    public void publishScanProgress(int scannedCount, int totalCount, String currentDependency) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onScanProgress(scannedCount, totalCount, currentDependency);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishVulnerabilityFound(Vulnerability vulnerability) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onVulnerabilityFound(vulnerability);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishDatabaseUpdateStarted(long totalRecords) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onDatabaseUpdateStarted(totalRecords);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishDatabaseUpdateProgress(long current, long total) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onDatabaseUpdateProgress(current, total);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishDatabaseUpdateCompleted(long durationMs) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onDatabaseUpdateCompleted(durationMs);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishScanCompleted(ScanResult result) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onScanCompleted(result);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishScanFailed(String errorMessage, Exception exception) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onScanFailed(errorMessage, exception);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishInfo(String message) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onInfo(message);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishWarning(String message) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onWarning(message);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }

    public void publishError(String message) {
        for (ScanEventListener listener : listeners) {
            try {
                listener.onError(message);
            } catch (Exception e) {
                // Ignore listener errors
            }
        }
    }
}
