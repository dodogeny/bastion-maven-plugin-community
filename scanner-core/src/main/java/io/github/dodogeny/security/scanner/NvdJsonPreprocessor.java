package io.github.dodogeny.security.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Preprocesses NVD JSON responses to handle CVSS v4.0 enum compatibility issues.
 * This class modifies JSON responses before they reach OWASP Dependency-Check's 
 * Jackson deserializers, replacing problematic enum values with compatible alternatives.
 */
public class NvdJsonPreprocessor {
    
    private static final Logger logger = LoggerFactory.getLogger(NvdJsonPreprocessor.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    
    // Mappings for problematic CVSSv4 enum values
    private static final Map<String, String> CVSS_V4_ENUM_MAPPINGS;
    
    static {
        CVSS_V4_ENUM_MAPPINGS = new HashMap<>();
        CVSS_V4_ENUM_MAPPINGS.put("SAFETY", "HIGH");     // Map SAFETY to HIGH
        CVSS_V4_ENUM_MAPPINGS.put("UNKNOWN", "NONE");    // Map UNKNOWN to NONE
        // Add more mappings as needed for future compatibility issues
    }
    
    /**
     * Preprocesses NVD API JSON response to replace problematic enum values
     */
    public static String preprocessNvdResponse(String jsonResponse) {
        if (jsonResponse == null || jsonResponse.trim().isEmpty()) {
            return jsonResponse;
        }

        try {
            // First, try simple string replacement for common cases
            String preprocessed = preprocessStringLevel(jsonResponse);

            // Then apply JSON-level preprocessing for more complex cases
            JsonNode root = mapper.readTree(preprocessed);
            boolean modified = processNode(root, "");

            if (modified) {
                String result = mapper.writeValueAsString(root);
                logger.debug("NVD JSON response preprocessed successfully - replaced problematic CVSS v4.0 enum values");
                return result;
            }

            return preprocessed; // Return string-level preprocessed version

        } catch (IOException e) {
            logger.warn("Failed to preprocess NVD JSON response: {}", e.getMessage());
            // Try string-level preprocessing as fallback
            return preprocessStringLevel(jsonResponse);
        }
    }

    /**
     * Performs aggressive string-level preprocessing to replace problematic enum values
     * before JSON parsing. This is a fallback for cases where JSON parsing fails.
     */
    private static String preprocessStringLevel(String jsonResponse) {
        if (jsonResponse == null) {
            return jsonResponse;
        }

        String result = jsonResponse;
        int replacements = 0;

        // Replace all instances of "SAFETY" with "HIGH" in CVSS v4.0 contexts
        String pattern1 = "\"SAFETY\"";
        String replacement1 = "\"HIGH\"";

        if (result.contains(pattern1)) {
            String newResult = result.replace(pattern1, replacement1);
            replacements += countOccurrences(result, pattern1);
            result = newResult;
        }

        // Handle other problematic enum values
        String[] problematicValues = {"\"UNKNOWN\"", "\"UNDEFINED\"", "\"NOT_DEFINED\""};
        for (String problematic : problematicValues) {
            if (result.contains(problematic)) {
                result = result.replace(problematic, "\"NONE\"");
                replacements++;
            }
        }

        if (replacements > 0) {
            logger.info("String-level preprocessing: replaced {} problematic enum values in NVD JSON", replacements);
        }

        return result;
    }

    /**
     * Counts occurrences of a substring in a string
     */
    private static int countOccurrences(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }
    
    /**
     * Recursively processes JSON nodes to find and replace problematic enum values
     */
    private static boolean processNode(JsonNode node, String path) {
        if (node == null) {
            return false;
        }
        
        boolean modified = false;
        
        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String fieldName = field.getKey();
                JsonNode fieldValue = field.getValue();
                String currentPath = path.isEmpty() ? fieldName : path + "." + fieldName;
                
                if (fieldValue.isTextual()) {
                    String textValue = fieldValue.asText();
                    if (isCvssV4Field(fieldName) && CVSS_V4_ENUM_MAPPINGS.containsKey(textValue)) {
                        String replacement = CVSS_V4_ENUM_MAPPINGS.get(textValue);
                        logger.debug("Replacing problematic enum '{}' -> '{}' in field '{}'", 
                                   textValue, replacement, currentPath);
                        objectNode.set(fieldName, new TextNode(replacement));
                        modified = true;
                    }
                } else {
                    // Recursively process nested objects and arrays
                    if (processNode(fieldValue, currentPath)) {
                        modified = true;
                    }
                }
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                if (processNode(node.get(i), path + "[" + i + "]")) {
                    modified = true;
                }
            }
        }
        
        return modified;
    }
    
    /**
     * Checks if a field name is likely to contain CVSS v4.0 enum values
     */
    private static boolean isCvssV4Field(String fieldName) {
        if (fieldName == null) {
            return false;
        }
        
        String lowerFieldName = fieldName.toLowerCase();
        return lowerFieldName.contains("modified") ||
               lowerFieldName.contains("impact") ||
               lowerFieldName.contains("exploitability") ||
               lowerFieldName.contains("cia") ||
               lowerFieldName.contains("safety") ||
               (lowerFieldName.contains("cvss") && lowerFieldName.contains("v4"));
    }
}