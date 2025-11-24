package io.github.dodogeny.security.scanner.engine;

import io.github.dodogeny.security.scanner.VulnerabilityScanner;
import io.github.dodogeny.security.scanner.patterns.ProcessorChain;
import io.github.dodogeny.security.scanner.patterns.ScanEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for creating ScanEngine instances.
 *
 * Provides convenient methods for creating pre-configured engines
 * for different use cases.
 */
public class ScanEngineFactory {

    private static final Logger logger = LoggerFactory.getLogger(ScanEngineFactory.class);

    private ScanEngineFactory() {
        // Utility class
    }

    /**
     * Creates a default scan engine.
     *
     * @return A configured default scan engine
     */
    public static ScanEngine createDefault() {
        logger.debug("Creating default scan engine");
        DefaultScanEngine engine = new DefaultScanEngine();
        engine.initialize();
        return engine;
    }

    /**
     * Creates a scan engine with custom configuration.
     *
     * @param configuration The scanner configuration
     * @return A configured scan engine
     */
    public static ScanEngine create(VulnerabilityScanner.ScannerConfiguration configuration) {
        logger.debug("Creating scan engine with custom configuration");
        DefaultScanEngine engine = DefaultScanEngine.builder()
            .withConfiguration(configuration)
            .build();
        engine.initialize();
        return engine;
    }

    /**
     * Creates a lightweight scan engine for quick scans.
     *
     * Configured with:
     * - Shorter timeout
     * - No caching
     * - Single thread
     *
     * @return A lightweight scan engine
     */
    public static ScanEngine createLightweight() {
        logger.debug("Creating lightweight scan engine");

        VulnerabilityScanner.ScannerConfiguration config =
            new VulnerabilityScanner.ScannerConfiguration();
        config.setTimeoutMs(60000); // 1 minute
        config.setEnableCache(false);
        config.setThreadCount(1);
        config.setAutoUpdate(false);

        return create(config);
    }

    /**
     * Creates a high-performance scan engine for CI/CD.
     *
     * Configured with:
     * - Caching enabled
     * - Multi-threading
     * - Smart caching
     *
     * @return A high-performance scan engine
     */
    public static ScanEngine createForCI() {
        logger.debug("Creating CI/CD optimized scan engine");

        VulnerabilityScanner.ScannerConfiguration config =
            new VulnerabilityScanner.ScannerConfiguration();
        config.setTimeoutMs(300000); // 5 minutes
        config.setEnableCache(true);
        config.setSmartCachingEnabled(true);
        config.setThreadCount(Runtime.getRuntime().availableProcessors());
        config.setAutoUpdate(false); // Database should be pre-updated in CI

        return create(config);
    }

    /**
     * Creates a scan engine for development/testing.
     *
     * Configured with:
     * - Verbose logging
     * - No network calls
     * - Fast timeouts
     *
     * @return A development scan engine
     */
    public static ScanEngine createForDevelopment() {
        logger.debug("Creating development scan engine");

        VulnerabilityScanner.ScannerConfiguration config =
            new VulnerabilityScanner.ScannerConfiguration();
        config.setTimeoutMs(30000); // 30 seconds
        config.setEnableCache(false);
        config.setAutoUpdate(false);
        config.setEnableRemoteValidation(false);
        config.setThreadCount(1);

        return create(config);
    }

    /**
     * Creates a scan engine with full features enabled.
     *
     * Configured with:
     * - All features enabled
     * - Auto-update
     * - Full caching
     *
     * @param nvdApiKey Optional NVD API key for faster updates
     * @return A fully-featured scan engine
     */
    public static ScanEngine createFull(String nvdApiKey) {
        logger.debug("Creating full-featured scan engine");

        VulnerabilityScanner.ScannerConfiguration config =
            new VulnerabilityScanner.ScannerConfiguration();
        config.setTimeoutMs(600000); // 10 minutes
        config.setEnableCache(true);
        config.setSmartCachingEnabled(true);
        config.setAutoUpdate(true);
        config.setEnableRemoteValidation(true);
        config.setThreadCount(Runtime.getRuntime().availableProcessors());

        // Note: NVD API key should be passed via system property or environment variable
        // -DnvdApiKey=your-key or NVD_API_KEY environment variable

        return create(config);
    }
}
