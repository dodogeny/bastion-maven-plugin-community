package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.scanner.OwaspDependencyCheckScanner;
import io.github.dodogeny.security.scanner.VulnerabilityScanner;

/**
 * Factory Pattern: Creates scanner instances based on type.
 * Allows easy extension with new scanner implementations.
 */
public class ScannerFactory {

    public enum ScannerType {
        OWASP_DEPENDENCY_CHECK,
        // Future scanner types can be added here
        // SNYK,
        // SONATYPE,
        // CUSTOM
    }

    private ScannerFactory() {
        // Private constructor for utility class
    }

    /**
     * Creates a scanner instance of the specified type.
     *
     * @param type The type of scanner to create
     * @param config Configuration for the scanner
     * @return A configured scanner instance
     */
    public static VulnerabilityScanner createScanner(ScannerType type, ScannerConfig config) {
        switch (type) {
            case OWASP_DEPENDENCY_CHECK:
                return createOwaspScanner(config);
            default:
                throw new IllegalArgumentException("Unknown scanner type: " + type);
        }
    }

    /**
     * Creates the default scanner (OWASP Dependency-Check).
     */
    public static VulnerabilityScanner createDefaultScanner(String nvdApiKey) {
        return new OwaspDependencyCheckScanner(nvdApiKey);
    }

    /**
     * Creates the default scanner without API key.
     */
    public static VulnerabilityScanner createDefaultScanner() {
        return new OwaspDependencyCheckScanner();
    }

    private static VulnerabilityScanner createOwaspScanner(ScannerConfig config) {
        if (config.getNvdApiKey() != null && !config.getNvdApiKey().isEmpty()) {
            return new OwaspDependencyCheckScanner(config.getNvdApiKey());
        }
        return new OwaspDependencyCheckScanner();
    }

    /**
     * Configuration class for scanner creation (Builder pattern).
     */
    public static class ScannerConfig {
        private String nvdApiKey;
        private int timeoutMs = 900000; // 15 minutes default
        private boolean autoUpdate = true;
        private String cacheDirectory;
        private long cacheValidityHours = 6;

        public ScannerConfig() {}

        public String getNvdApiKey() { return nvdApiKey; }
        public int getTimeoutMs() { return timeoutMs; }
        public boolean isAutoUpdate() { return autoUpdate; }
        public String getCacheDirectory() { return cacheDirectory; }
        public long getCacheValidityHours() { return cacheValidityHours; }

        /**
         * Builder for ScannerConfig.
         */
        public static class Builder {
            private final ScannerConfig config = new ScannerConfig();

            public Builder nvdApiKey(String apiKey) {
                config.nvdApiKey = apiKey;
                return this;
            }

            public Builder timeoutMs(int timeout) {
                config.timeoutMs = timeout;
                return this;
            }

            public Builder autoUpdate(boolean autoUpdate) {
                config.autoUpdate = autoUpdate;
                return this;
            }

            public Builder cacheDirectory(String directory) {
                config.cacheDirectory = directory;
                return this;
            }

            public Builder cacheValidityHours(long hours) {
                config.cacheValidityHours = hours;
                return this;
            }

            public ScannerConfig build() {
                return config;
            }
        }

        public static Builder builder() {
            return new Builder();
        }
    }
}
