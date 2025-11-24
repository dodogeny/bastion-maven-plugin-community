package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Template Method Pattern: Defines the skeleton of the scanning algorithm.
 * Subclasses implement specific steps without changing the overall structure.
 */
public abstract class AbstractScannerTemplate {

    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * Template method that defines the scanning workflow.
     * This method is final to prevent subclasses from changing the workflow.
     */
    public final ScanResult executeScan(String projectPath, List<String> dependencies) {
        logger.info("Starting scan workflow for: {}", projectPath);
        long startTime = System.currentTimeMillis();

        try {
            // Step 1: Initialize
            logger.debug("Step 1: Initializing scanner...");
            initializeScanner();

            // Step 2: Prepare environment
            logger.debug("Step 2: Preparing environment...");
            prepareEnvironment();

            // Step 3: Update database if needed
            logger.debug("Step 3: Checking database updates...");
            if (shouldUpdateDatabase()) {
                updateDatabase();
            }

            // Step 4: Perform the scan
            logger.debug("Step 4: Performing scan...");
            List<Vulnerability> vulnerabilities = performScan(projectPath, dependencies);

            // Step 5: Process results
            logger.debug("Step 5: Processing results...");
            List<Vulnerability> processedVulnerabilities = processResults(vulnerabilities);

            // Step 6: Build scan result
            logger.debug("Step 6: Building scan result...");
            ScanResult result = buildScanResult(projectPath, processedVulnerabilities);

            // Step 7: Cleanup
            logger.debug("Step 7: Cleaning up...");
            cleanup();

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Scan completed in {}ms. Found {} vulnerabilities.",
                duration, processedVulnerabilities.size());

            return result;

        } catch (Exception e) {
            logger.error("Scan failed: {}", e.getMessage());
            handleScanError(e);
            throw new RuntimeException("Scan failed", e);
        }
    }

    // Abstract methods that subclasses must implement

    /**
     * Initialize the scanner (load configurations, etc.)
     */
    protected abstract void initializeScanner();

    /**
     * Prepare the scanning environment (create temp dirs, etc.)
     */
    protected abstract void prepareEnvironment();

    /**
     * Check if database needs updating.
     */
    protected abstract boolean shouldUpdateDatabase();

    /**
     * Update the vulnerability database.
     */
    protected abstract void updateDatabase();

    /**
     * Perform the actual scan.
     */
    protected abstract List<Vulnerability> performScan(String projectPath, List<String> dependencies);

    /**
     * Process the scan results (filter, enrich, etc.)
     */
    protected abstract List<Vulnerability> processResults(List<Vulnerability> vulnerabilities);

    /**
     * Build the final scan result.
     */
    protected abstract ScanResult buildScanResult(String projectPath, List<Vulnerability> vulnerabilities);

    // Hook methods that subclasses can optionally override

    /**
     * Cleanup after scan (optional).
     */
    protected void cleanup() {
        // Default: no cleanup
    }

    /**
     * Handle scan errors (optional).
     */
    protected void handleScanError(Exception e) {
        // Default: just log
        logger.error("Scan error: {}", e.getMessage(), e);
    }

    /**
     * Gets the scanner name.
     */
    public abstract String getScannerName();
}
