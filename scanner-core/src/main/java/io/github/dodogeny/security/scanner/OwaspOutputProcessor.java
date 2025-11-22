package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Processes OWASP Dependency-Check output and converts multi-line progress
 * messages into single-line Linux-style progress counters.
 */
public class OwaspOutputProcessor {

    private static final Logger logger = LoggerFactory.getLogger(OwaspOutputProcessor.class);

    // Pattern to match OWASP download progress: "Downloaded 10,000/319,107 (3%)"
    private static final Pattern DOWNLOAD_PATTERN = Pattern.compile(
        "Downloaded\\s+([\\d,]+)/([\\d,]+)\\s+\\((\\d+)%\\)"
    );

    // Pattern to match NVD API fetch progress
    private static final Pattern NVD_FETCH_PATTERN = Pattern.compile(
        "(?:Fetching|Processing).*?(\\d+).*?of.*?(\\d+)"
    );

    // Pattern to match analysis progress
    private static final Pattern ANALYSIS_PATTERN = Pattern.compile(
        "Analyzed\\s+(\\d+)\\s+(?:of|/)\\s+(\\d+)"
    );

    private Instant startTime;
    private long lastCurrent = 0;
    private long lastTotal = 0;
    private String currentOperation = "Downloading NVD";
    private boolean progressActive = false;

    public OwaspOutputProcessor() {
        this.startTime = Instant.now();
    }

    /**
     * Processes a single line of OWASP output.
     * Returns true if the line was a progress message (should be suppressed from normal output).
     */
    public boolean processLine(String line) {
        if (line == null || line.isEmpty()) {
            return false;
        }

        // Check for download progress pattern
        Matcher downloadMatcher = DOWNLOAD_PATTERN.matcher(line);
        if (downloadMatcher.find()) {
            long current = parseNumber(downloadMatcher.group(1));
            long total = parseNumber(downloadMatcher.group(2));

            if (!progressActive) {
                progressActive = true;
                startTime = Instant.now();
                ConsoleLogger.startProgress();
            }

            lastCurrent = current;
            lastTotal = total;
            currentOperation = "Downloading NVD";

            ConsoleLogger.printRecordProgress(current, total, startTime, currentOperation);
            return true; // Suppress original line
        }

        // Check for NVD fetch pattern
        Matcher nvdMatcher = NVD_FETCH_PATTERN.matcher(line);
        if (nvdMatcher.find()) {
            long current = parseNumber(nvdMatcher.group(1));
            long total = parseNumber(nvdMatcher.group(2));

            if (!progressActive) {
                progressActive = true;
                startTime = Instant.now();
                ConsoleLogger.startProgress();
            }

            lastCurrent = current;
            lastTotal = total;
            currentOperation = "Fetching CVEs";

            ConsoleLogger.printRecordProgress(current, total, startTime, currentOperation);
            return true;
        }

        // Check for analysis pattern
        Matcher analysisMatcher = ANALYSIS_PATTERN.matcher(line);
        if (analysisMatcher.find()) {
            long current = parseNumber(analysisMatcher.group(1));
            long total = parseNumber(analysisMatcher.group(2));

            if (!progressActive || !currentOperation.equals("Analyzing")) {
                progressActive = true;
                startTime = Instant.now();
                ConsoleLogger.startProgress();
            }

            lastCurrent = current;
            lastTotal = total;
            currentOperation = "Analyzing";

            ConsoleLogger.printRecordProgress(current, total, startTime, currentOperation);
            return true;
        }

        // Check for completion messages
        if (line.contains("update complete") || line.contains("Download complete") ||
            line.contains("Analysis complete") || line.contains("finished in")) {
            if (progressActive) {
                // Ensure we show 100% completion
                if (lastTotal > 0) {
                    ConsoleLogger.printRecordProgress(lastTotal, lastTotal, startTime, currentOperation);
                }
                progressActive = false;
            }
            return false; // Let completion message through
        }

        // If progress was active but this line isn't a progress message, clear and reset
        if (progressActive && !line.trim().isEmpty() &&
            !line.contains("Downloaded") && !line.contains("Fetching")) {
            ConsoleLogger.clearProgressLine();
            progressActive = false;
        }

        return false; // Don't suppress this line
    }

    /**
     * Processes an input stream and filters/reformats progress messages.
     * Non-progress messages are passed to the provided logger.
     */
    public void processStream(InputStream inputStream, boolean isError) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                boolean suppressed = processLine(line);

                if (!suppressed) {
                    // Clean up the line (remove nested [INFO] prefixes)
                    String cleanLine = cleanLogLine(line);

                    if (isError) {
                        if (cleanLine.contains("ERROR") || cleanLine.contains("FATAL")) {
                            logger.error(cleanLine);
                        } else if (cleanLine.contains("WARN")) {
                            logger.warn(cleanLine);
                        } else {
                            logger.debug(cleanLine);
                        }
                    } else {
                        // Filter out noisy/redundant messages
                        if (shouldShowLine(cleanLine)) {
                            logger.info(cleanLine);
                        }
                    }
                }
            }
        } catch (IOException e) {
            logger.debug("Error reading stream: {}", e.getMessage());
        }
    }

    /**
     * Cleans up nested log prefixes from OWASP output.
     */
    private String cleanLogLine(String line) {
        // Remove nested [INFO], [WARN], etc. prefixes
        String cleaned = line.replaceAll("^\\s*\\[INFO\\]\\s*\\[INFO\\]", "[INFO]")
                             .replaceAll("^\\s*\\[INFO\\]\\s*", "")
                             .replaceAll("^\\s*\\[WARN\\]\\s*", "")
                             .replaceAll("^\\s*\\[ERROR\\]\\s*", "")
                             .trim();
        return cleaned;
    }

    /**
     * Determines if a line should be shown in normal output.
     */
    private boolean shouldShowLine(String line) {
        if (line.isEmpty()) {
            return false;
        }

        // Skip noisy/redundant messages
        String[] skipPatterns = {
            "Downloading from central:",
            "Downloaded from central:",
            "Progress:",
            "...",
            "----",
            "====",
        };

        for (String pattern : skipPatterns) {
            if (line.contains(pattern)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Parses a number string that may contain commas.
     */
    private long parseNumber(String numberStr) {
        try {
            return Long.parseLong(numberStr.replace(",", ""));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Resets the processor state for a new operation.
     */
    public void reset() {
        startTime = Instant.now();
        lastCurrent = 0;
        lastTotal = 0;
        progressActive = false;
    }

    /**
     * Gets whether progress is currently active.
     */
    public boolean isProgressActive() {
        return progressActive;
    }

    /**
     * Finalizes any active progress display.
     */
    public void finalize() {
        if (progressActive && lastTotal > 0) {
            ConsoleLogger.printRecordProgress(lastTotal, lastTotal, startTime, currentOperation);
        }
        progressActive = false;
    }
}
