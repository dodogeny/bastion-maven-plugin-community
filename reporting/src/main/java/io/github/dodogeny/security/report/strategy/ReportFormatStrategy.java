package io.github.dodogeny.security.report.strategy;

import io.github.dodogeny.security.model.ScanResult;

import java.io.File;
import java.util.Map;

/**
 * Strategy Pattern: Defines how to generate reports in different formats.
 * Allows adding new report formats without modifying existing code.
 */
public interface ReportFormatStrategy {

    /**
     * Gets the format name (e.g., "HTML", "JSON", "PDF").
     */
    String getFormatName();

    /**
     * Gets the file extension for this format.
     */
    String getFileExtension();

    /**
     * Generates a report from the scan result.
     *
     * @param scanResult The scan result data
     * @param templateModel Additional template model data
     * @param outputFile The output file
     * @return true if generation was successful
     */
    boolean generate(ScanResult scanResult, Map<String, Object> templateModel, File outputFile);

    /**
     * Checks if this strategy supports the given format.
     */
    default boolean supports(String format) {
        return getFormatName().equalsIgnoreCase(format);
    }

    /**
     * Gets the content type for this format.
     */
    default String getContentType() {
        switch (getFormatName().toUpperCase()) {
            case "HTML": return "text/html";
            case "JSON": return "application/json";
            case "PDF": return "application/pdf";
            case "CSV": return "text/csv";
            case "XML": return "application/xml";
            default: return "application/octet-stream";
        }
    }
}
