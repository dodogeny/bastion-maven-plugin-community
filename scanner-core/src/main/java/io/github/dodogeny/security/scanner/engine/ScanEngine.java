package io.github.dodogeny.security.scanner.engine;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import io.github.dodogeny.security.scanner.VulnerabilityScanner;
import io.github.dodogeny.security.scanner.patterns.ProcessorChain;
import io.github.dodogeny.security.scanner.patterns.ScanEventListener;
import io.github.dodogeny.security.scanner.patterns.ScanEventPublisher;
import io.github.dodogeny.security.scanner.patterns.VulnerabilityProcessor;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * ScanEngine: Central orchestrator for all scanning operations.
 *
 * This engine encapsulates all scanning business logic and provides:
 * - Unified scanning API
 * - Event-driven architecture via Observer pattern
 * - Extensible vulnerability processing pipeline
 * - Support for multiple scanner implementations
 * - Async and sync scanning modes
 */
public interface ScanEngine {

    /**
     * Scans a project synchronously.
     *
     * @param projectPath Path to the project to scan
     * @return The scan result
     */
    ScanResult scan(String projectPath);

    /**
     * Scans a project asynchronously.
     *
     * @param projectPath Path to the project to scan
     * @return CompletableFuture with the scan result
     */
    CompletableFuture<ScanResult> scanAsync(String projectPath);

    /**
     * Scans specific dependencies.
     *
     * @param projectPath Path to the project
     * @param dependencies List of dependencies to scan
     * @return The scan result
     */
    ScanResult scanDependencies(String projectPath, List<String> dependencies);

    /**
     * Adds a vulnerability processor to the processing pipeline.
     *
     * @param processor The processor to add
     * @return This engine for chaining
     */
    ScanEngine addProcessor(VulnerabilityProcessor processor);

    /**
     * Removes a processor from the pipeline.
     *
     * @param processor The processor to remove
     * @return This engine for chaining
     */
    ScanEngine removeProcessor(VulnerabilityProcessor processor);

    /**
     * Registers an event listener.
     *
     * @param listener The listener to register
     * @return This engine for chaining
     */
    ScanEngine addEventListener(ScanEventListener listener);

    /**
     * Removes an event listener.
     *
     * @param listener The listener to remove
     * @return This engine for chaining
     */
    ScanEngine removeEventListener(ScanEventListener listener);

    /**
     * Configures the scanner.
     *
     * @param configuration The scanner configuration
     * @return This engine for chaining
     */
    ScanEngine configure(VulnerabilityScanner.ScannerConfiguration configuration);

    /**
     * Gets the current configuration.
     *
     * @return The current configuration
     */
    VulnerabilityScanner.ScannerConfiguration getConfiguration();

    /**
     * Gets the processor chain.
     *
     * @return The processor chain
     */
    ProcessorChain getProcessorChain();

    /**
     * Gets the event publisher.
     *
     * @return The event publisher
     */
    ScanEventPublisher getEventPublisher();

    /**
     * Checks if the engine is ready to scan.
     *
     * @return true if ready
     */
    boolean isReady();

    /**
     * Initializes the engine (database updates, etc.).
     */
    void initialize();

    /**
     * Shuts down the engine and releases resources.
     */
    void shutdown();

    /**
     * Gets the engine name.
     *
     * @return The engine name
     */
    String getName();

    /**
     * Gets engine version.
     *
     * @return The version string
     */
    String getVersion();
}
