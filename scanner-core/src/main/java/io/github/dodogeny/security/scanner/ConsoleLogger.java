package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DecimalFormat;
import java.time.Duration;
import java.time.Instant;

/**
 * Professional console logger with ANSI colors, statistics formatting,
 * and interactive progress display.
 */
public class ConsoleLogger {

    private static final Logger logger = LoggerFactory.getLogger(ConsoleLogger.class);

    // ANSI Color Codes
    public static final String RESET = "\u001B[0m";
    public static final String BOLD = "\u001B[1m";
    public static final String DIM = "\u001B[2m";
    public static final String UNDERLINE = "\u001B[4m";

    // Foreground Colors
    public static final String BLACK = "\u001B[30m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String PURPLE = "\u001B[35m";
    public static final String CYAN = "\u001B[36m";
    public static final String WHITE = "\u001B[37m";

    // Bright Colors
    public static final String BRIGHT_RED = "\u001B[91m";
    public static final String BRIGHT_GREEN = "\u001B[92m";
    public static final String BRIGHT_YELLOW = "\u001B[93m";
    public static final String BRIGHT_BLUE = "\u001B[94m";
    public static final String BRIGHT_PURPLE = "\u001B[95m";
    public static final String BRIGHT_CYAN = "\u001B[96m";
    public static final String BRIGHT_WHITE = "\u001B[97m";

    // Background Colors
    public static final String BG_RED = "\u001B[41m";
    public static final String BG_GREEN = "\u001B[42m";
    public static final String BG_YELLOW = "\u001B[43m";
    public static final String BG_BLUE = "\u001B[44m";

    private static boolean colorsEnabled = true;
    private static final DecimalFormat DECIMAL_FORMAT = new DecimalFormat("#,###");
    private static final DecimalFormat PERCENT_FORMAT = new DecimalFormat("##0.0");

    static {
        // Disable colors if not in a TTY or if explicitly disabled
        String noColor = System.getenv("NO_COLOR");
        String term = System.getenv("TERM");
        if (noColor != null || "dumb".equals(term)) {
            colorsEnabled = false;
        }
    }

    public static void setColorsEnabled(boolean enabled) {
        colorsEnabled = enabled;
    }

    // ===========================================
    // Header and Section Formatting
    // ===========================================

    public static void printHeader(String title) {
        String line = "═".repeat(60);
        logger.info("");
        logger.info(colorize(BRIGHT_CYAN + BOLD, "╔" + line + "╗"));
        logger.info(colorize(BRIGHT_CYAN + BOLD, "║" + centerText(title, 60) + "║"));
        logger.info(colorize(BRIGHT_CYAN + BOLD, "╚" + line + "╝"));
        logger.info("");
    }

    public static void printSubHeader(String title) {
        String line = "─".repeat(50);
        logger.info("");
        logger.info(colorize(CYAN, "┌" + line + "┐"));
        logger.info(colorize(CYAN + BOLD, "│" + centerText(title, 50) + "│"));
        logger.info(colorize(CYAN, "└" + line + "┘"));
    }

    public static void printSection(String title) {
        logger.info("");
        logger.info(colorize(BRIGHT_WHITE + BOLD, "▶ " + title));
        logger.info(colorize(DIM, "─".repeat(40)));
    }

    public static void printDivider() {
        logger.info(colorize(DIM, "─".repeat(60)));
    }

    // ===========================================
    // Status Messages
    // ===========================================

    public static void success(String message) {
        logger.info(colorize(BRIGHT_GREEN, "✓ ") + message);
    }

    public static void success(String message, Object... args) {
        logger.info(colorize(BRIGHT_GREEN, "✓ ") + message, args);
    }

    public static void error(String message) {
        logger.error(colorize(BRIGHT_RED, "✗ ") + message);
    }

    public static void error(String message, Object... args) {
        logger.error(colorize(BRIGHT_RED, "✗ ") + message, args);
    }

    public static void warning(String message) {
        logger.warn(colorize(BRIGHT_YELLOW, "⚠ ") + message);
    }

    public static void warning(String message, Object... args) {
        logger.warn(colorize(BRIGHT_YELLOW, "⚠ ") + message, args);
    }

    public static void info(String message) {
        logger.info(colorize(BRIGHT_BLUE, "ℹ ") + message);
    }

    public static void info(String message, Object... args) {
        logger.info(colorize(BRIGHT_BLUE, "ℹ ") + message, args);
    }

    public static void step(int current, int total, String message) {
        String stepIndicator = colorize(BRIGHT_PURPLE + BOLD,
            String.format("[%d/%d]", current, total));
        logger.info("{} {}", stepIndicator, message);
    }

    public static void bullet(String message) {
        logger.info(colorize(DIM, "  • ") + message);
    }

    public static void indent(String message) {
        logger.info("    " + message);
    }

    // ===========================================
    // Progress Display (Single-line Linux-style)
    // ===========================================

    private static Instant progressStartTime;
    private static long lastProgressUpdate = 0;
    private static final long PROGRESS_UPDATE_INTERVAL_MS = 100; // Update every 100ms

    /**
     * Prints a single-line progress bar that updates in place (Linux-style).
     */
    public static void printProgress(long current, long total, String label) {
        if (total <= 0) return;

        // Throttle updates to avoid flickering
        long now = System.currentTimeMillis();
        if (current < total && now - lastProgressUpdate < PROGRESS_UPDATE_INTERVAL_MS) {
            return;
        }
        lastProgressUpdate = now;

        int barWidth = 30;
        double percent = (double) current / total;
        int filled = (int) (barWidth * percent);
        int empty = barWidth - filled;

        String bar = colorize(BRIGHT_GREEN, "█".repeat(filled)) +
                     colorize(DIM, "░".repeat(empty));

        String percentStr = colorize(BRIGHT_WHITE + BOLD,
            String.format("%5.1f%%", percent * 100));

        String stats = colorize(DIM,
            String.format(" %s/%s", formatNumber(current), formatNumber(total)));

        // Use carriage return for same-line update
        System.out.print(String.format("\r  %s │%s│ %s %s",
            label, bar, percentStr, stats));
        System.out.flush();

        if (current >= total) {
            System.out.println(); // New line when complete
        }
    }

    /**
     * Prints a single-line progress with ETA calculation (Linux-style).
     */
    public static void printProgressWithETA(long current, long total, Instant startTime, String label) {
        if (total <= 0) return;

        // Throttle updates
        long now = System.currentTimeMillis();
        if (current < total && now - lastProgressUpdate < PROGRESS_UPDATE_INTERVAL_MS) {
            return;
        }
        lastProgressUpdate = now;

        int barWidth = 25;
        double percent = (double) current / total;
        int filled = (int) (barWidth * percent);
        int empty = barWidth - filled;

        String bar = colorize(BRIGHT_GREEN, "█".repeat(filled)) +
                     colorize(DIM, "░".repeat(empty));

        String percentStr = colorize(BRIGHT_WHITE + BOLD,
            String.format("%5.1f%%", percent * 100));

        // Calculate ETA
        String etaStr = "";
        if (current > 0 && startTime != null) {
            long elapsedMs = Duration.between(startTime, Instant.now()).toMillis();
            long estimatedTotalMs = (long) (elapsedMs / percent);
            long remainingMs = estimatedTotalMs - elapsedMs;
            etaStr = colorize(CYAN, " ETA: " + formatDuration(remainingMs));
        }

        System.out.print(String.format("\r  %s │%s│ %s%s    ",
            label, bar, percentStr, etaStr));
        System.out.flush();

        if (current >= total) {
            System.out.println();
        }
    }

    /**
     * Prints a spinning download counter (Linux wget/curl style).
     * Updates on a single line with speed and progress info.
     */
    public static void printDownloadProgress(long bytesDownloaded, long totalBytes,
                                              Instant startTime, String filename) {
        // Throttle updates
        long now = System.currentTimeMillis();
        if (bytesDownloaded < totalBytes && now - lastProgressUpdate < PROGRESS_UPDATE_INTERVAL_MS) {
            return;
        }
        lastProgressUpdate = now;

        // Calculate speed
        long elapsedMs = startTime != null ? Duration.between(startTime, Instant.now()).toMillis() : 0;
        double speedBytesPerSec = elapsedMs > 0 ? (bytesDownloaded * 1000.0 / elapsedMs) : 0;

        // Progress bar
        int barWidth = 20;
        double percent = totalBytes > 0 ? (double) bytesDownloaded / totalBytes : 0;
        int filled = (int) (barWidth * percent);
        int empty = barWidth - filled;

        String bar = colorize(BRIGHT_GREEN, "█".repeat(filled)) +
                     colorize(DIM, "░".repeat(empty));

        // Format components
        String percentStr = totalBytes > 0 ?
            String.format("%5.1f%%", percent * 100) : "    ?%";
        String sizeStr = formatBytes(bytesDownloaded);
        String totalStr = totalBytes > 0 ? formatBytes(totalBytes) : "?";
        String speedStr = formatBytes((long) speedBytesPerSec) + "/s";

        // ETA
        String etaStr = "";
        if (totalBytes > 0 && speedBytesPerSec > 0) {
            long remainingBytes = totalBytes - bytesDownloaded;
            long etaSeconds = (long) (remainingBytes / speedBytesPerSec);
            etaStr = formatDuration(etaSeconds * 1000);
        }

        // Build the line
        StringBuilder line = new StringBuilder();
        line.append("\r");
        line.append(colorize(BRIGHT_CYAN, filename.length() > 15 ?
            filename.substring(0, 12) + "..." : String.format("%-15s", filename)));
        line.append(" │").append(bar).append("│ ");
        line.append(colorize(BRIGHT_WHITE + BOLD, percentStr));
        line.append(colorize(DIM, " " + sizeStr + "/" + totalStr));
        line.append(colorize(BRIGHT_YELLOW, " " + speedStr));
        if (!etaStr.isEmpty()) {
            line.append(colorize(CYAN, " ETA:" + etaStr));
        }
        line.append("   "); // Clear any trailing characters

        System.out.print(line.toString());
        System.out.flush();

        if (bytesDownloaded >= totalBytes && totalBytes > 0) {
            System.out.println();
        }
    }

    /**
     * Prints a counter-style progress for records/items (not bytes).
     * Similar to apt-get or yum progress.
     */
    public static void printRecordProgress(long current, long total, Instant startTime, String operation) {
        // Throttle updates
        long now = System.currentTimeMillis();
        if (current < total && now - lastProgressUpdate < PROGRESS_UPDATE_INTERVAL_MS) {
            return;
        }
        lastProgressUpdate = now;

        // Calculate speed
        long elapsedMs = startTime != null ? Duration.between(startTime, Instant.now()).toMillis() : 0;
        double recordsPerSec = elapsedMs > 0 ? (current * 1000.0 / elapsedMs) : 0;

        // Progress
        double percent = total > 0 ? (double) current / total * 100 : 0;

        // ETA
        String etaStr = "";
        if (total > 0 && recordsPerSec > 0) {
            long remaining = total - current;
            long etaSeconds = (long) (remaining / recordsPerSec);
            etaStr = formatDuration(etaSeconds * 1000);
        }

        // Spinner characters for visual feedback
        char[] spinner = {'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'};
        char spin = spinner[(int) ((now / 100) % spinner.length)];

        // Build line
        StringBuilder line = new StringBuilder();
        line.append("\r");
        line.append(colorize(BRIGHT_CYAN, String.valueOf(spin)));
        line.append(" ");
        line.append(colorize(BRIGHT_WHITE, operation));
        line.append(": ");
        line.append(colorize(BRIGHT_GREEN + BOLD, formatNumber(current)));
        line.append(colorize(DIM, "/" + formatNumber(total)));
        line.append(colorize(BRIGHT_WHITE, String.format(" (%5.1f%%)", percent)));
        line.append(colorize(BRIGHT_YELLOW, String.format(" %.0f/s", recordsPerSec)));
        if (!etaStr.isEmpty()) {
            line.append(colorize(CYAN, " ETA:" + etaStr));
        }
        line.append("      "); // Clear trailing

        System.out.print(line.toString());
        System.out.flush();

        if (current >= total && total > 0) {
            // Final line with checkmark
            System.out.print("\r");
            System.out.print(colorize(BRIGHT_GREEN, "✓ "));
            System.out.print(colorize(BRIGHT_WHITE, operation));
            System.out.print(": ");
            System.out.print(colorize(BRIGHT_GREEN + BOLD, formatNumber(total)));
            System.out.print(colorize(DIM, " records"));
            System.out.print(colorize(BRIGHT_YELLOW, " (" + formatDuration(elapsedMs) + ")"));
            System.out.println("                    ");
        }
    }

    /**
     * Clears the current progress line.
     */
    public static void clearProgressLine() {
        System.out.print("\r" + " ".repeat(80) + "\r");
        System.out.flush();
    }

    /**
     * Starts tracking progress time.
     */
    public static void startProgress() {
        progressStartTime = Instant.now();
        lastProgressUpdate = 0;
    }

    /**
     * Gets the progress start time.
     */
    public static Instant getProgressStartTime() {
        return progressStartTime;
    }

    // ===========================================
    // Statistics Display
    // ===========================================

    public static void printStatBox(String title, String[][] stats) {
        int maxKeyLen = 0;
        int maxValLen = 0;

        for (String[] stat : stats) {
            maxKeyLen = Math.max(maxKeyLen, stat[0].length());
            maxValLen = Math.max(maxValLen, stat[1].length());
        }

        int boxWidth = maxKeyLen + maxValLen + 7;
        String topLine = "┌" + "─".repeat(boxWidth) + "┐";
        String bottomLine = "└" + "─".repeat(boxWidth) + "┘";

        logger.info("");
        logger.info(colorize(CYAN, topLine));
        logger.info(colorize(CYAN + BOLD, "│" + centerText(title, boxWidth) + "│"));
        logger.info(colorize(CYAN, "├" + "─".repeat(boxWidth) + "┤"));

        for (String[] stat : stats) {
            String key = stat[0];
            String value = stat[1];
            String color = stat.length > 2 ? stat[2] : BRIGHT_WHITE;

            String formattedLine = String.format("│ %-" + maxKeyLen + "s : %s%" + maxValLen + "s%s │",
                key, colorize(color + BOLD, ""), value, RESET);
            logger.info(colorize(CYAN, formattedLine));
        }

        logger.info(colorize(CYAN, bottomLine));
    }

    public static void printKeyValue(String key, String value) {
        logger.info("  {} : {}",
            colorize(DIM, String.format("%-20s", key)),
            colorize(BRIGHT_WHITE, value));
    }

    public static void printKeyValue(String key, long value) {
        printKeyValue(key, formatNumber(value));
    }

    public static void printKeyValue(String key, double value, String suffix) {
        printKeyValue(key, PERCENT_FORMAT.format(value) + suffix);
    }

    // ===========================================
    // Severity and Status Indicators
    // ===========================================

    public static String severityBadge(String severity) {
        switch (severity.toUpperCase()) {
            case "CRITICAL":
                return colorize(BG_RED + WHITE + BOLD, " CRITICAL ");
            case "HIGH":
                return colorize(BRIGHT_RED + BOLD, "HIGH");
            case "MEDIUM":
                return colorize(BRIGHT_YELLOW + BOLD, "MEDIUM");
            case "LOW":
                return colorize(BRIGHT_GREEN + BOLD, "LOW");
            default:
                return colorize(DIM, severity);
        }
    }

    public static String statusBadge(String status) {
        switch (status.toUpperCase()) {
            case "SUCCESS":
            case "PASSED":
            case "VALID":
                return colorize(BRIGHT_GREEN + BOLD, "✓ " + status);
            case "FAILED":
            case "ERROR":
            case "INVALID":
                return colorize(BRIGHT_RED + BOLD, "✗ " + status);
            case "WARNING":
            case "PARTIAL":
                return colorize(BRIGHT_YELLOW + BOLD, "⚠ " + status);
            case "PENDING":
            case "IN_PROGRESS":
                return colorize(BRIGHT_BLUE + BOLD, "◐ " + status);
            default:
                return status;
        }
    }

    // ===========================================
    // Formatting Utilities
    // ===========================================

    public static String formatNumber(long number) {
        return DECIMAL_FORMAT.format(number);
    }

    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    public static String formatDuration(long milliseconds) {
        if (milliseconds < 1000) return milliseconds + "ms";
        if (milliseconds < 60000) return String.format("%.1fs", milliseconds / 1000.0);

        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;

        if (minutes < 60) {
            return String.format("%dm %ds", minutes, seconds);
        }

        long hours = minutes / 60;
        minutes = minutes % 60;
        return String.format("%dh %dm", hours, minutes);
    }

    public static String formatPercent(double value) {
        return PERCENT_FORMAT.format(value) + "%";
    }

    // ===========================================
    // Welcome and Completion Messages
    // ===========================================

    public static void printWelcome(String toolName, String version) {
        logger.info("");
        logger.info(colorize(BRIGHT_CYAN + BOLD, "  ____            _   _             "));
        logger.info(colorize(BRIGHT_CYAN + BOLD, " | __ )  __ _ ___| |_(_) ___  _ __  "));
        logger.info(colorize(BRIGHT_CYAN + BOLD, " |  _ \\ / _` / __| __| |/ _ \\| '_ \\ "));
        logger.info(colorize(BRIGHT_CYAN + BOLD, " | |_) | (_| \\__ \\ |_| | (_) | | | |"));
        logger.info(colorize(BRIGHT_CYAN + BOLD, " |____/ \\__,_|___/\\__|_|\\___/|_| |_|"));
        logger.info("");
        logger.info(colorize(DIM, "  " + toolName + " v" + version));
        logger.info(colorize(DIM, "  Enterprise-grade vulnerability scanning"));
        logger.info("");
    }

    public static void printCompletionSummary(boolean success, Duration duration,
                                               int vulnerabilities, int dependencies) {
        logger.info("");
        if (success) {
            printHeader("SCAN COMPLETE");
        } else {
            logger.info(colorize(BRIGHT_RED + BOLD, "╔════════════════════════════════════════════════════════════╗"));
            logger.info(colorize(BRIGHT_RED + BOLD, "║" + centerText("SCAN FAILED", 60) + "║"));
            logger.info(colorize(BRIGHT_RED + BOLD, "╚════════════════════════════════════════════════════════════╝"));
        }

        String[][] stats = {
            {"Status", success ? "SUCCESS" : "FAILED", success ? BRIGHT_GREEN : BRIGHT_RED},
            {"Duration", formatDuration(duration.toMillis()), BRIGHT_WHITE},
            {"Dependencies", formatNumber(dependencies), BRIGHT_BLUE},
            {"Vulnerabilities", formatNumber(vulnerabilities),
                vulnerabilities > 0 ? BRIGHT_RED : BRIGHT_GREEN}
        };

        printStatBox("Results", stats);
    }

    // ===========================================
    // Private Helpers
    // ===========================================

    private static String colorize(String color, String text) {
        if (!colorsEnabled) {
            return text;
        }
        return color + text + RESET;
    }

    private static String centerText(String text, int width) {
        if (text.length() >= width) {
            return text.substring(0, width);
        }
        int padding = (width - text.length()) / 2;
        return " ".repeat(padding) + text + " ".repeat(width - text.length() - padding);
    }
}
