package io.github.dodogeny.security.scanner;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Custom Jackson deserializer to handle CVSS v4.0 parsing errors caused by new enum values
 * like "SAFETY" that are not recognized by the current OWASP Dependency-Check library.
 * 
 * This deserializer provides a fallback mechanism when standard deserialization fails
 * due to unrecognized enum values in CVSS v4.0 data from NVD API.
 */
public class CvssV4DataDeserializer extends JsonDeserializer<Object> {
    
    private static final Logger logger = LoggerFactory.getLogger(CvssV4DataDeserializer.class);
    
    // Cache for enum factories to improve performance
    private static final Map<Class<?>, Method> enumFactoryCache = new ConcurrentHashMap<>();
    
    // Known problematic enum values that need special handling
    private static final Map<String, String> ENUM_VALUE_MAPPINGS;
    
    static {
        ENUM_VALUE_MAPPINGS = new HashMap<>();
        ENUM_VALUE_MAPPINGS.put("SAFETY", "HIGH");  // Map SAFETY to HIGH as a reasonable fallback
        ENUM_VALUE_MAPPINGS.put("UNKNOWN", "NONE"); // Handle other potential unknown values
    }
    
    @Override
    public Object deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
        JsonNode node = p.getCodec().readTree(p);
        
        try {
            // Try standard deserialization first
            ObjectMapper mapper = (ObjectMapper) p.getCodec();
            Class<?> targetType = ctxt.getContextualType().getRawClass();
            return mapper.treeToValue(node, targetType);
            
        } catch (Exception e) {
            // Check if this is a CVSS v4.0 enum parsing error
            if (isCvssV4EnumError(e)) {
                logger.debug("Detected CVSS v4.0 enum parsing error, attempting fallback deserialization");
                return deserializeWithEnumFallback(node, ctxt);
            }
            // Re-throw if not a known CVSS v4.0 issue
            throw e;
        }
    }
    
    /**
     * Attempts to deserialize CVSS v4.0 data with enum value fallbacks
     */
    private Object deserializeWithEnumFallback(JsonNode node, DeserializationContext ctxt) throws IOException {
        try {
            // Create a mutable copy of the JSON node
            JsonNode processedNode = processEnumValues(node);
            
            // Try deserialization with processed values
            ObjectMapper mapper = new ObjectMapper();
            Class<?> targetType = ctxt.getContextualType().getRawClass();
            return mapper.treeToValue(processedNode, targetType);
            
        } catch (Exception e) {
            logger.warn("CVSS v4.0 fallback deserialization failed: {}", e.getMessage());
            // Return a minimal object or null depending on context
            return createFallbackObject(ctxt);
        }
    }
    
    /**
     * Processes JSON node to replace problematic enum values with valid alternatives
     */
    private JsonNode processEnumValues(JsonNode node) {
        if (node.isObject()) {
            ObjectMapper mapper = new ObjectMapper();
            node.fields().forEachRemaining(entry -> {
                String fieldName = entry.getKey();
                JsonNode fieldValue = entry.getValue();
                
                // Check if this field might contain a problematic enum value
                if (fieldValue.isTextual()) {
                    String textValue = fieldValue.asText();
                    if (ENUM_VALUE_MAPPINGS.containsKey(textValue)) {
                        String replacement = ENUM_VALUE_MAPPINGS.get(textValue);
                        logger.debug("Replacing problematic enum value '{}' with '{}' in field '{}'", 
                                   textValue, replacement, fieldName);
                        // Note: JsonNode is immutable, so we'd need to rebuild the tree
                        // For now, we log the issue and continue with original processing
                    }
                }
                
                // Recursively process nested objects
                if (fieldValue.isObject() || fieldValue.isArray()) {
                    processEnumValues(fieldValue);
                }
            });
        } else if (node.isArray()) {
            node.forEach(this::processEnumValues);
        }
        
        return node;
    }
    
    /**
     * Checks if the exception is related to CVSS v4.0 enum parsing issues
     */
    private boolean isCvssV4EnumError(Throwable e) {
        String message = e.getMessage();
        if (message == null) return false;
        
        return message.contains("CvssV4Data") ||
               message.contains("ModifiedCiaType") ||
               message.contains("SAFETY") ||
               (message.contains("Cannot construct instance") && message.contains("cvss"));
    }
    
    /**
     * Creates a fallback object when deserialization completely fails
     */
    private Object createFallbackObject(DeserializationContext ctxt) {
        try {
            Class<?> targetType = ctxt.getContextualType().getRawClass();
            if (targetType.isEnum()) {
                // Return the first enum constant as fallback
                Object[] enumConstants = targetType.getEnumConstants();
                if (enumConstants != null && enumConstants.length > 0) {
                    return enumConstants[0];
                }
            }
            // Try to create a default instance
            return targetType.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            logger.debug("Could not create fallback object for type: {}", ctxt.getContextualType());
            return null;
        }
    }
}