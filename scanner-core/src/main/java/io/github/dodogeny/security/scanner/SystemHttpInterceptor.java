package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.util.HashMap;
import java.util.Map;

/**
 * System-level HTTP interceptor that hooks into Java's URL connection mechanism
 * to preprocess NVD API responses at the HTTP transport layer.
 *
 * This interceptor works by:
 * 1. Installing a custom URLStreamHandlerFactory
 * 2. Intercepting HTTP/HTTPS connections to NVD endpoints
 * 3. Wrapping responses with JSON preprocessing
 */
public class SystemHttpInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(SystemHttpInterceptor.class);
    private static boolean installed = false;
    private static URLStreamHandlerFactory originalFactory;
    private static URLStreamHandler defaultHttpHandler;
    private static URLStreamHandler defaultHttpsHandler;

    /**
     * Installs the system-wide HTTP interceptor
     */
    public static synchronized void install() {
        if (installed) {
            logger.debug("HTTP interceptor already installed");
            return;
        }

        try {
            // Get the original factory if one exists
            originalFactory = getInstalledURLStreamHandlerFactory();

            // Get default handlers before installing custom factory to avoid infinite recursion
            defaultHttpHandler = getDefaultHandler("http");
            defaultHttpsHandler = getDefaultHandler("https");

            // Install our custom factory
            NvdInterceptingURLStreamHandlerFactory factory = new NvdInterceptingURLStreamHandlerFactory(originalFactory);
            URL.setURLStreamHandlerFactory(factory);

            installed = true;
            logger.info("🔧 System HTTP interceptor installed for NVD API preprocessing");

        } catch (Exception e) {
            logger.warn("Failed to install system HTTP interceptor: {}", e.getMessage());
            logger.debug("HTTP interceptor installation failed", e);
        }
    }

    /**
     * Attempts to retrieve the currently installed URLStreamHandlerFactory using reflection
     */
    private static URLStreamHandlerFactory getInstalledURLStreamHandlerFactory() {
        try {
            Field factoryField = URL.class.getDeclaredField("factory");
            factoryField.setAccessible(true);
            return (URLStreamHandlerFactory) factoryField.get(null);
        } catch (Exception e) {
            logger.debug("Could not retrieve existing URLStreamHandlerFactory: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the default system URLStreamHandler for a protocol before custom factory installation
     */
    private static URLStreamHandler getDefaultHandler(String protocol) {
        try {
            // Create a temporary URL to get the default handler
            URL tempUrl = new URL(protocol + "://example.com");

            // Use reflection to access the handler
            Field handlerField = URL.class.getDeclaredField("handler");
            handlerField.setAccessible(true);
            return (URLStreamHandler) handlerField.get(tempUrl);
        } catch (Exception e) {
            logger.debug("Could not retrieve default {} handler: {}", protocol, e.getMessage());
            return null;
        }
    }

    /**
     * Custom URLStreamHandlerFactory that intercepts HTTP connections
     */
    private static class NvdInterceptingURLStreamHandlerFactory implements URLStreamHandlerFactory {
        private final URLStreamHandlerFactory originalFactory;
        private final Map<String, URLStreamHandler> handlers = new HashMap<>();

        public NvdInterceptingURLStreamHandlerFactory(URLStreamHandlerFactory originalFactory) {
            this.originalFactory = originalFactory;
        }

        @Override
        public URLStreamHandler createURLStreamHandler(String protocol) {
            // Only intercept HTTP and HTTPS protocols
            if ("http".equals(protocol) || "https".equals(protocol)) {
                return handlers.computeIfAbsent(protocol, this::createInterceptingHandler);
            }

            // For other protocols, delegate to original factory
            if (originalFactory != null) {
                return originalFactory.createURLStreamHandler(protocol);
            }

            return null;
        }

        private URLStreamHandler createInterceptingHandler(String protocol) {
            return new URLStreamHandler() {
                @Override
                protected URLConnection openConnection(URL url) throws IOException {
                    return openConnection(url, null);
                }

                @Override
                protected URLConnection openConnection(URL url, java.net.Proxy proxy) throws IOException {
                    // Get the default connection using the saved default handlers to avoid infinite recursion
                    URLConnection connection;
                    try {
                        URLStreamHandler defaultHandler = "https".equals(protocol) ? defaultHttpsHandler : defaultHttpHandler;

                        if (defaultHandler != null) {
                            // Use reflection to call protected openConnection methods on default handlers
                            if (proxy != null) {
                                Method openConnectionMethod = URLStreamHandler.class.getDeclaredMethod("openConnection", URL.class, java.net.Proxy.class);
                                openConnectionMethod.setAccessible(true);
                                connection = (URLConnection) openConnectionMethod.invoke(defaultHandler, url, proxy);
                            } else {
                                Method openConnectionMethod = URLStreamHandler.class.getDeclaredMethod("openConnection", URL.class);
                                openConnectionMethod.setAccessible(true);
                                connection = (URLConnection) openConnectionMethod.invoke(defaultHandler, url);
                            }
                        } else {
                            // Fallback: try to create connection without going through factory
                            throw new IOException("No default handler available for protocol: " + protocol);
                        }
                    } catch (Exception e) {
                        throw new IOException("Failed to create URL connection", e);
                    }

                    // Wrap HTTP connections to NVD endpoints
                    if (connection instanceof HttpURLConnection && isNvdApiUrl(url.toString())) {
                        logger.debug("🔗 Intercepting NVD API connection: {}", url);
                        return ResilientNvdHttpClient.wrapConnection((HttpURLConnection) connection);
                    }

                    return connection;
                }
            };
        }
    }

    /**
     * Checks if a URL is an NVD API endpoint
     */
    private static boolean isNvdApiUrl(String url) {
        if (url == null) {
            return false;
        }

        String lowerUrl = url.toLowerCase();
        return lowerUrl.contains("services.nvd.nist.gov") ||
               lowerUrl.contains("nvd.nist.gov/api") ||
               (lowerUrl.contains("nvd") && lowerUrl.contains("cve"));
    }

    /**
     * Checks if the interceptor is installed
     */
    public static boolean isInstalled() {
        return installed;
    }

    /**
     * Gets interception statistics
     */
    public static String getStats() {
        return ResilientNvdHttpClient.getInterceptionStats();
    }
}