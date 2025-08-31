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
            JsonNode root = mapper.readTree(jsonResponse);
            boolean modified = processNode(root, "");
            
            if (modified) {
                String result = mapper.writeValueAsString(root);
                logger.debug("NVD JSON response preprocessed successfully - replaced problematic CVSS v4.0 enum values");
                return result;
            }
            
            return jsonResponse; // No modifications needed
            
        } catch (IOException e) {
            logger.warn("Failed to preprocess NVD JSON response: {}", e.getMessage());
            return jsonResponse; // Return original on error
        }
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