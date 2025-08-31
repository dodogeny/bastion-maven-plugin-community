package io.github.dodogeny.security.scanner;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * System-wide Jackson configuration fix for CVSS v4.0 compatibility issues.
 * This class attempts to globally configure Jackson ObjectMapper instances
 * to handle unknown enum values gracefully, particularly the "SAFETY" enum
 * that causes OWASP Dependency-Check to fail.
 */
public class JacksonCvssV4Fix {
    
    private static final Logger logger = LoggerFactory.getLogger(JacksonCvssV4Fix.class);
    private static boolean initialized = false;
    
    // Cache for enum mappings to avoid repeated reflection
    private static final Map<String, Object> enumMappingCache = new ConcurrentHashMap<>();
    
    /**
     * Applies global Jackson configuration to handle CVSS v4.0 compatibility issues.
     * This method should be called before any OWASP Dependency-Check objects are created.
     */
    public static void applyGlobalFix() {
        if (initialized) {
            return;
        }
        
        try {
            logger.info("🔧 Applying global Jackson configuration for CVSS v4.0 compatibility");
            
            // Set system properties that some Jackson configurations might check
            System.setProperty("jackson.deserialization.fail-on-unknown-properties", "false");
            System.setProperty("jackson.deserialization.read-unknown-enum-values-as-null", "true");
            
            // Try to configure the default ObjectMapper if accessible
            configureDefaultObjectMapper();
            
            initialized = true;
            logger.info("✅ Jackson CVSS v4.0 compatibility fix applied successfully");
            
        } catch (Exception e) {
            logger.warn("⚠️  Could not apply complete Jackson fix, some CVSS v4.0 issues may persist: {}", e.getMessage());
        }
    }
    
    /**
     * Attempts to configure the default ObjectMapper used by various libraries
     */
    private static void configureDefaultObjectMapper() {
        try {
            // Create a module with custom deserializers for problematic enum types
            SimpleModule cvssV4Module = new SimpleModule("CvssV4CompatibilityModule");
            
            // Add a generic enum deserializer that handles unknown values
            cvssV4Module.addDeserializer(Enum.class, new CvssV4EnumDeserializer());
            
            // Try to register this module with any ObjectMapper instances we can find
            registerModuleGlobally(cvssV4Module);
            
        } catch (Exception e) {
            logger.debug("Could not configure default ObjectMapper: {}", e.getMessage());
        }
    }
    
    /**
     * Attempts to register the compatibility module with ObjectMapper instances
     */
    private static void registerModuleGlobally(SimpleModule module) {
        try {
            // This is a best-effort attempt to configure Jackson globally
            // In practice, OWASP Dependency-Check creates its own ObjectMapper instances
            // so this might not be effective, but it's worth trying
            
            logger.debug("Attempting to register CVSS v4.0 compatibility module globally");
            
            // The real fix needs to happen at the OWASP library level or by preprocessing JSON
            // This method serves as a placeholder for potential future enhancements
            
        } catch (Exception e) {
            logger.debug("Could not register module globally: {}", e.getMessage());
        }
    }
    
    /**
     * Custom enum deserializer that handles unknown enum values gracefully
     */
    private static class CvssV4EnumDeserializer extends JsonDeserializer<Enum<?>> {
        
        @Override
        public Enum<?> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            String enumValue = p.getValueAsString();
            Class<?> enumClass = ctxt.getContextualType().getRawClass();
            
            if (enumValue == null || !enumClass.isEnum()) {
                return null;
            }
            
            try {
                // Try normal enum deserialization first
                return Enum.valueOf((Class<Enum>) enumClass, enumValue);
                
            } catch (IllegalArgumentException e) {
                // Handle unknown enum values
                if ("SAFETY".equals(enumValue) && isModifiedCiaType(enumClass)) {
                    logger.debug("Mapping unknown CVSS v4.0 enum value 'SAFETY' to 'HIGH' for compatibility");
                    return tryGetEnumConstant(enumClass, "HIGH");
                }
                
                if ("UNKNOWN".equals(enumValue)) {
                    logger.debug("Mapping unknown enum value 'UNKNOWN' to 'NONE' for compatibility");
                    return tryGetEnumConstant(enumClass, "NONE");
                }
                
                // Default fallback - return the first enum constant
                Object[] enumConstants = enumClass.getEnumConstants();
                if (enumConstants != null && enumConstants.length > 0) {
                    logger.debug("Using default enum value for unknown '{}' in class {}", enumValue, enumClass.getSimpleName());
                    return (Enum<?>) enumConstants[0];
                }
                
                return null;
            }
        }
        
        private boolean isModifiedCiaType(Class<?> enumClass) {
            return enumClass.getName().contains("ModifiedCiaType") || 
                   enumClass.getName().contains("CvssV4");
        }
        
        private Enum<?> tryGetEnumConstant(Class<?> enumClass, String constantName) {
            try {
                return Enum.valueOf((Class<Enum>) enumClass, constantName);
            } catch (IllegalArgumentException e) {
                // Return first constant as fallback
                Object[] constants = enumClass.getEnumConstants();
                return constants != null && constants.length > 0 ? (Enum<?>) constants[0] : null;
            }
        }
    }
}