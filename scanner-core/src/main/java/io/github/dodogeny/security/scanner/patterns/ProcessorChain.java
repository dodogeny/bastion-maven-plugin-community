package io.github.dodogeny.security.scanner.patterns;

import io.github.dodogeny.security.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Chain of Responsibility: Manages a pipeline of vulnerability processors.
 */
public class ProcessorChain {

    private static final Logger logger = LoggerFactory.getLogger(ProcessorChain.class);

    private final List<VulnerabilityProcessor> processors = new ArrayList<>();

    /**
     * Adds a processor to the chain.
     */
    public ProcessorChain addProcessor(VulnerabilityProcessor processor) {
        processors.add(processor);
        processors.sort(Comparator.comparingInt(VulnerabilityProcessor::getOrder));
        return this;
    }

    /**
     * Removes a processor from the chain.
     */
    public ProcessorChain removeProcessor(VulnerabilityProcessor processor) {
        processors.remove(processor);
        return this;
    }

    /**
     * Processes a vulnerability through all processors in the chain.
     */
    public Vulnerability process(Vulnerability vulnerability) {
        Vulnerability result = vulnerability;

        for (VulnerabilityProcessor processor : processors) {
            if (!processor.isEnabled()) {
                continue;
            }

            try {
                result = processor.process(result);
                if (result == null) {
                    logger.debug("Vulnerability filtered by processor: {}", processor.getName());
                    return null;
                }
            } catch (Exception e) {
                logger.warn("Processor {} failed: {}", processor.getName(), e.getMessage());
                // Continue with unprocessed vulnerability
            }
        }

        return result;
    }

    /**
     * Processes all vulnerabilities through the chain.
     */
    public List<Vulnerability> processAll(List<Vulnerability> vulnerabilities) {
        List<Vulnerability> results = new ArrayList<>();

        for (Vulnerability vulnerability : vulnerabilities) {
            Vulnerability processed = process(vulnerability);
            if (processed != null) {
                results.add(processed);
            }
        }

        logger.info("Processed {} vulnerabilities through {} processors, {} remained",
            vulnerabilities.size(), processors.size(), results.size());

        return results;
    }

    /**
     * Gets the number of processors in the chain.
     */
    public int size() {
        return processors.size();
    }

    /**
     * Clears all processors from the chain.
     */
    public void clear() {
        processors.clear();
    }

    /**
     * Creates a default processor chain with standard processors.
     */
    public static ProcessorChain createDefault() {
        return new ProcessorChain();
        // Default processors can be added here in the future
    }
}
