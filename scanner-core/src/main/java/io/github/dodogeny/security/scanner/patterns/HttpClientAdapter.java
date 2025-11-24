package io.github.dodogeny.security.scanner.patterns;

import java.io.InputStream;
import java.util.Map;

/**
 * Adapter Pattern: Abstracts HTTP client implementation.
 * Allows swapping HTTP libraries (HttpURLConnection, OkHttp, Apache HttpClient, etc.)
 */
public interface HttpClientAdapter {

    /**
     * Performs a GET request.
     *
     * @param url The URL to fetch
     * @param headers Request headers
     * @return The response
     */
    HttpResponse get(String url, Map<String, String> headers);

    /**
     * Performs a HEAD request (for metadata only).
     *
     * @param url The URL to check
     * @param headers Request headers
     * @return The response
     */
    HttpResponse head(String url, Map<String, String> headers);

    /**
     * Downloads content to a stream.
     *
     * @param url The URL to download
     * @param headers Request headers
     * @param progressListener Optional progress listener
     * @return Input stream of the content
     */
    InputStream download(String url, Map<String, String> headers, ProgressListener progressListener);

    /**
     * Sets connection timeout.
     */
    void setConnectionTimeout(int timeoutMs);

    /**
     * Sets read timeout.
     */
    void setReadTimeout(int timeoutMs);

    /**
     * HTTP response wrapper.
     */
    class HttpResponse {
        private int statusCode;
        private String body;
        private Map<String, String> headers;
        private long contentLength;
        private long lastModified;

        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
        public String getBody() { return body; }
        public void setBody(String body) { this.body = body; }
        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }
        public long getContentLength() { return contentLength; }
        public void setContentLength(long contentLength) { this.contentLength = contentLength; }
        public long getLastModified() { return lastModified; }
        public void setLastModified(long lastModified) { this.lastModified = lastModified; }

        public boolean isSuccess() {
            return statusCode >= 200 && statusCode < 300;
        }
    }

    /**
     * Progress listener for downloads.
     */
    interface ProgressListener {
        void onProgress(long bytesRead, long totalBytes);
    }
}
