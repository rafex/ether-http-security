package dev.rafex.ether.http.security.headers;

import java.util.LinkedHashMap;
import java.util.Map;

public record SecurityHeadersPolicy(boolean contentTypeOptions, boolean frameOptions, boolean referrerPolicy,
        boolean permissionsPolicy, boolean hsts, boolean noStore, String contentSecurityPolicy,
        Map<String, String> customHeaders) {

    public SecurityHeadersPolicy {
        customHeaders = customHeaders == null ? Map.of() : Map.copyOf(customHeaders);
    }

    public static SecurityHeadersPolicy defaults() {
        return new SecurityHeadersPolicy(true, true, true, true, true, true,
                "default-src 'self'; frame-ancestors 'none'; base-uri 'self'", Map.of());
    }

    public Map<String, String> headers() {
        final var headers = new LinkedHashMap<String, String>();
        if (contentTypeOptions) {
            headers.put("X-Content-Type-Options", "nosniff");
        }
        if (frameOptions) {
            headers.put("X-Frame-Options", "DENY");
        }
        if (referrerPolicy) {
            headers.put("Referrer-Policy", "no-referrer");
        }
        if (permissionsPolicy) {
            headers.put("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        }
        if (hsts) {
            headers.put("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        if (noStore) {
            headers.put("Cache-Control", "no-store");
        }
        if (contentSecurityPolicy != null && !contentSecurityPolicy.isBlank()) {
            headers.put("Content-Security-Policy", contentSecurityPolicy);
        }
        headers.putAll(customHeaders);
        return headers;
    }
}
