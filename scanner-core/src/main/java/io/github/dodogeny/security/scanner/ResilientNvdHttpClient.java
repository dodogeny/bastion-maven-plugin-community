package io.github.dodogeny.security.scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * HTTP client wrapper that intercepts NVD API responses and preprocesses JSON
 * to handle CVSS v4.0 compatibility issues before they reach Jackson deserializers.
 *
 * This client acts as a transparent proxy that:
 * 1. Intercepts HTTP responses from NVD API
 * 2. Preprocesses JSON to replace problematic enum values
 * 3. Returns the cleaned JSON to the calling library
 */
public class ResilientNvdHttpClient {

    private static final Logger logger = LoggerFactory.getLogger(ResilientNvdHttpClient.class);
    private static final AtomicInteger interceptedRequests = new AtomicInteger(0);
    private static final AtomicInteger preprocessedResponses = new AtomicInteger(0);

    /**
     * Creates a wrapped InputStream that preprocesses NVD JSON responses
     */
    public static InputStream wrapNvdResponse(InputStream originalResponse, String requestUrl) {
        if (originalResponse == null) {
            return originalResponse;
        }

        // Only preprocess NVD API responses
        if (!isNvdApiUrl(requestUrl)) {
            return originalResponse;
        }

        try {
            interceptedRequests.incrementAndGet();

            // Read the entire response (Java 8 compatible)
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[8192];
            while ((nRead = originalResponse.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            byte[] responseBytes = buffer.toByteArray();
            String originalJson = new String(responseBytes, StandardCharsets.UTF_8);

            // Preprocess the JSON
            String processedJson = NvdJsonPreprocessor.preprocessNvdResponse(originalJson);

            // Check if any modifications were made
            if (!originalJson.equals(processedJson)) {
                preprocessedResponses.incrementAndGet();
                logger.debug("🔧 Preprocessed NVD API response for URL: {}", requestUrl);
            }

            // Return a new InputStream with the processed JSON
            return new ByteArrayInputStream(processedJson.getBytes(StandardCharsets.UTF_8));

        } catch (IOException e) {
            logger.warn("Failed to preprocess NVD response from {}: {}", requestUrl, e.getMessage());
            // Return original response if preprocessing fails
            try {
                originalResponse.reset();
                return originalResponse;
            } catch (IOException resetException) {
                logger.warn("Failed to reset original response stream: {}", resetException.getMessage());
                return null;
            }
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
               lowerUrl.contains("nvd") && lowerUrl.contains("cve");
    }

    /**
     * Creates a wrapper for HttpURLConnection that preprocesses responses
     */
    public static HttpURLConnection wrapConnection(HttpURLConnection connection) {
        return new HttpURLConnectionWrapper(connection);
    }

    /**
     * Gets statistics about HTTP interception
     */
    public static String getInterceptionStats() {
        return String.format("Intercepted: %d requests, Preprocessed: %d responses",
                           interceptedRequests.get(), preprocessedResponses.get());
    }

    /**
     * Wrapper class for HttpURLConnection that preprocesses input streams
     */
    private static class HttpURLConnectionWrapper extends HttpURLConnection {
        private final HttpURLConnection wrapped;

        public HttpURLConnectionWrapper(HttpURLConnection wrapped) {
            super(wrapped.getURL());
            this.wrapped = wrapped;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            InputStream original = wrapped.getInputStream();
            return wrapNvdResponse(original, wrapped.getURL().toString());
        }

        @Override
        public InputStream getErrorStream() {
            InputStream original = wrapped.getErrorStream();
            if (original == null) {
                return null;
            }
            return wrapNvdResponse(original, wrapped.getURL().toString());
        }

        // Delegate all other methods to the wrapped connection
        @Override
        public void disconnect() { wrapped.disconnect(); }

        @Override
        public boolean usingProxy() { return wrapped.usingProxy(); }

        @Override
        public void connect() throws IOException { wrapped.connect(); }

        @Override
        public int getResponseCode() throws IOException { return wrapped.getResponseCode(); }

        @Override
        public String getResponseMessage() throws IOException { return wrapped.getResponseMessage(); }

        @Override
        public String getHeaderField(String name) { return wrapped.getHeaderField(name); }

        @Override
        public String getHeaderField(int n) { return wrapped.getHeaderField(n); }

        @Override
        public String getHeaderFieldKey(int n) { return wrapped.getHeaderFieldKey(n); }

        @Override
        public long getHeaderFieldDate(String name, long Default) { return wrapped.getHeaderFieldDate(name, Default); }

        @Override
        public int getHeaderFieldInt(String name, int Default) { return wrapped.getHeaderFieldInt(name, Default); }

        @Override
        public long getHeaderFieldLong(String name, long Default) { return wrapped.getHeaderFieldLong(name, Default); }

        @Override
        public void setRequestMethod(String method) throws java.net.ProtocolException { wrapped.setRequestMethod(method); }

        @Override
        public String getRequestMethod() { return wrapped.getRequestMethod(); }

        @Override
        public boolean getInstanceFollowRedirects() { return wrapped.getInstanceFollowRedirects(); }

        @Override
        public void setInstanceFollowRedirects(boolean followRedirects) { wrapped.setInstanceFollowRedirects(followRedirects); }
    }
}