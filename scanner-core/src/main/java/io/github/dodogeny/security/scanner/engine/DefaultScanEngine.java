package io.github.dodogeny.security.scanner.engine;

import io.github.dodogeny.security.model.ScanResult;
import io.github.dodogeny.security.model.Vulnerability;
import io.github.dodogeny.security.scanner.OwaspDependencyCheckScanner;
import io.github.dodogeny.security.scanner.VulnerabilityScanner;
import io.github.dodogeny.security.scanner.patterns.ProcessorChain;
import io.github.dodogeny.security.scanner.patterns.ScanEventListener;
import io.github.dodogeny.security.scanner.patterns.ScanEventPublisher;
import io.github.dodogeny.security.scanner.patterns.VulnerabilityProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of ScanEngine.
 *
 * Orchestrates scanning using OWASP Dependency Check scanner,
 * processes results through the vulnerability pipeline,
 * and publishes events to listeners.
 */
public class DefaultScanEngine implements ScanEngine {

    private static final Logger logger = LoggerFactory.getLogger(DefaultScanEngine.class);
    private static final String ENGINE_NAME = "Bastion Scan Engine";
    private static final String ENGINE_VERSION = "1.0.0";

    private final VulnerabilityScanner scanner;
    private final ProcessorChain processorChain;
    private final ScanEventPublisher eventPublisher;
    private final ExecutorService executorService;

    private VulnerabilityScanner.ScannerConfiguration configuration;
    private boolean initialized = false;

    /**
     * Creates a new DefaultScanEngine with default components.
     */
    public DefaultScanEngine() {
        this(new OwaspDependencyCheckScanner(),
             ProcessorChain.createDefault(),
             ScanEventPublisher.getInstance());
    }

    /**
     * Creates a new DefaultScanEngine with custom components.
     *
     * @param scanner The vulnerability scanner to use
     * @param processorChain The processor chain for results
     * @param eventPublisher The event publisher
     */
    public DefaultScanEngine(VulnerabilityScanner scanner,
                            ProcessorChain processorChain,
                            ScanEventPublisher eventPublisher) {
        this.scanner = scanner;
        this.processorChain = processorChain;
        this.eventPublisher = eventPublisher;
        this.executorService = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "scan-engine-worker");
            t.setDaemon(true);
            return t;
        });
        this.configuration = new VulnerabilityScanner.ScannerConfiguration();
    }

    @Override
    public ScanResult scan(String projectPath) {
        logger.info("Starting synchronous scan for: {}", projectPath);

        try {
            return scanAsync(projectPath).get(
                configuration.getTimeoutMs(),
                TimeUnit.MILLISECONDS
            );
        } catch (Exception e) {
            logger.error("Scan failed: {}", e.getMessage(), e);
            eventPublisher.publishError("Scan failed: " + e.getMessage());
            throw new RuntimeException("Scan failed", e);
        }
    }

    @Override
    public CompletableFuture<ScanResult> scanAsync(String projectPath) {
        logger.info("Starting asynchronous scan for: {}", projectPath);

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Publish scan start event
                eventPublisher.publishScanStarted(projectPath, 0);

                // Perform the scan
                CompletableFuture<ScanResult> scanFuture = scanner.scanProject(projectPath);
                ScanResult result = scanFuture.get(configuration.getTimeoutMs(), TimeUnit.MILLISECONDS);

                // Process vulnerabilities through the pipeline
                if (result != null && result.getVulnerabilities() != null) {
                    List<Vulnerability> processed = processorChain.processAll(result.getVulnerabilities());
                    result = rebuildResultWithProcessedVulnerabilities(result, processed);
                }

                // Publish scan complete event
                eventPublisher.publishScanCompleted(result);

                logger.info("Scan completed. Found {} vulnerabilities.",
                    result != null ? result.getTotalVulnerabilities() : 0);

                return result;

            } catch (Exception e) {
                logger.error("Async scan failed: {}", e.getMessage(), e);
                eventPublisher.publishScanFailed("Scan failed: " + e.getMessage(), e);
                throw new RuntimeException("Scan failed", e);
            }
        }, executorService);
    }

    @Override
    public ScanResult scanDependencies(String projectPath, List<String> dependencies) {
        logger.info("Scanning {} specific dependencies in: {}", dependencies.size(), projectPath);

        try {
            // Publish scan start
            eventPublisher.publishScanStarted(projectPath, dependencies.size());

            // Use scanner's dependency scan method
            CompletableFuture<List<Vulnerability>> future = scanner.scanDependencies(dependencies);
            List<Vulnerability> vulnerabilities = future.get(configuration.getTimeoutMs(), TimeUnit.MILLISECONDS);

            // Process through pipeline
            List<Vulnerability> processed = processorChain.processAll(
                vulnerabilities != null ? vulnerabilities : new ArrayList<>());

            // Build result from processed vulnerabilities
            ScanResult result = new ScanResult();
            result.setStartTime(LocalDateTime.now());
            result.setEndTime(LocalDateTime.now());
            result.setVulnerabilities(processed);
            result.setTotalDependencies(dependencies.size());

            // Calculate severity counts
            int critical = 0, high = 0, medium = 0, low = 0;
            for (Vulnerability v : processed) {
                String severity = v.getSeverity();
                if (severity != null) {
                    switch (severity.toUpperCase()) {
                        case "CRITICAL": critical++; break;
                        case "HIGH": high++; break;
                        case "MEDIUM": medium++; break;
                        case "LOW": low++; break;
                    }
                }
            }
            result.setCriticalVulnerabilities(critical);
            result.setHighVulnerabilities(high);
            result.setMediumVulnerabilities(medium);
            result.setLowVulnerabilities(low);

            // Publish complete
            eventPublisher.publishScanCompleted(result);

            return result;

        } catch (Exception e) {
            logger.error("Dependency scan failed: {}", e.getMessage(), e);
            eventPublisher.publishScanFailed("Dependency scan failed: " + e.getMessage(), e);
            throw new RuntimeException("Dependency scan failed", e);
        }
    }

    @Override
    public ScanEngine addProcessor(VulnerabilityProcessor processor) {
        processorChain.addProcessor(processor);
        logger.debug("Added processor: {}", processor.getName());
        return this;
    }

    @Override
    public ScanEngine removeProcessor(VulnerabilityProcessor processor) {
        processorChain.removeProcessor(processor);
        logger.debug("Removed processor: {}", processor.getName());
        return this;
    }

    @Override
    public ScanEngine addEventListener(ScanEventListener listener) {
        eventPublisher.addListener(listener);
        logger.debug("Added event listener: {}", listener.getClass().getSimpleName());
        return this;
    }

    @Override
    public ScanEngine removeEventListener(ScanEventListener listener) {
        eventPublisher.removeListener(listener);
        logger.debug("Removed event listener: {}", listener.getClass().getSimpleName());
        return this;
    }

    @Override
    public ScanEngine configure(VulnerabilityScanner.ScannerConfiguration configuration) {
        this.configuration = configuration;
        scanner.configure(configuration);
        logger.info("Engine configured with timeout={}ms, threshold={}",
            configuration.getTimeoutMs(), configuration.getSeverityThreshold());
        return this;
    }

    @Override
    public VulnerabilityScanner.ScannerConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public ProcessorChain getProcessorChain() {
        return processorChain;
    }

    @Override
    public ScanEventPublisher getEventPublisher() {
        return eventPublisher;
    }

    @Override
    public boolean isReady() {
        return initialized;
    }

    @Override
    public void initialize() {
        logger.info("Initializing {}...", ENGINE_NAME);

        try {
            // Initialize the underlying scanner
            scanner.configure(configuration);

            // Publish initialization event
            eventPublisher.publishInfo("Engine initialization started");

            initialized = true;
            logger.info("{} initialized successfully", ENGINE_NAME);

        } catch (Exception e) {
            logger.error("Engine initialization failed: {}", e.getMessage(), e);
            eventPublisher.publishError("Initialization failed: " + e.getMessage());
            throw new RuntimeException("Engine initialization failed", e);
        }
    }

    @Override
    public void shutdown() {
        logger.info("Shutting down {}...", ENGINE_NAME);

        try {
            executorService.shutdown();
            if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }

            initialized = false;
            logger.info("{} shut down successfully", ENGINE_NAME);

        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
            logger.warn("Shutdown interrupted");
        }
    }

    @Override
    public String getName() {
        return ENGINE_NAME;
    }

    @Override
    public String getVersion() {
        return ENGINE_VERSION;
    }

    /**
     * Rebuilds a ScanResult with processed vulnerabilities.
     */
    private ScanResult rebuildResultWithProcessedVulnerabilities(
            ScanResult original, List<Vulnerability> processedVulnerabilities) {

        // Create a new ScanResult with the processed vulnerabilities
        ScanResult result = new ScanResult();
        result.setStartTime(original.getStartTime());
        result.setEndTime(original.getEndTime());
        result.setVulnerabilities(processedVulnerabilities);
        result.setDependencies(original.getDependencies());
        result.setTotalDependencies(original.getTotalDependencies());

        // Recalculate severity counts
        int critical = 0, high = 0, medium = 0, low = 0;
        for (Vulnerability v : processedVulnerabilities) {
            String severity = v.getSeverity();
            if (severity != null) {
                switch (severity.toUpperCase()) {
                    case "CRITICAL": critical++; break;
                    case "HIGH": high++; break;
                    case "MEDIUM": medium++; break;
                    case "LOW": low++; break;
                }
            }
        }

        result.setCriticalVulnerabilities(critical);
        result.setHighVulnerabilities(high);
        result.setMediumVulnerabilities(medium);
        result.setLowVulnerabilities(low);

        return result;
    }

    /**
     * Builder for creating configured ScanEngine instances.
     */
    public static class Builder {
        private VulnerabilityScanner scanner;
        private ProcessorChain processorChain;
        private ScanEventPublisher eventPublisher;
        private VulnerabilityScanner.ScannerConfiguration configuration;

        public Builder withScanner(VulnerabilityScanner scanner) {
            this.scanner = scanner;
            return this;
        }

        public Builder withProcessorChain(ProcessorChain chain) {
            this.processorChain = chain;
            return this;
        }

        public Builder withEventPublisher(ScanEventPublisher publisher) {
            this.eventPublisher = publisher;
            return this;
        }

        public Builder withConfiguration(VulnerabilityScanner.ScannerConfiguration config) {
            this.configuration = config;
            return this;
        }

        public DefaultScanEngine build() {
            DefaultScanEngine engine = new DefaultScanEngine(
                scanner != null ? scanner : new OwaspDependencyCheckScanner(),
                processorChain != null ? processorChain : ProcessorChain.createDefault(),
                eventPublisher != null ? eventPublisher : ScanEventPublisher.getInstance()
            );

            if (configuration != null) {
                engine.configure(configuration);
            }

            return engine;
        }
    }

    /**
     * Creates a builder for constructing ScanEngine instances.
     */
    public static Builder builder() {
        return new Builder();
    }
}
