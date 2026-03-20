package dev.rafex.ether.http.security.cors;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record CorsPolicy(boolean allowAnyOrigin, List<String> allowedOrigins, List<String> allowedMethods,
        List<String> allowedHeaders, List<String> exposedHeaders, boolean allowCredentials, int maxAgeSeconds,
        boolean varyOrigin) {

    public CorsPolicy {
        allowedOrigins = copyList(allowedOrigins);
        allowedMethods = copyList(allowedMethods);
        allowedHeaders = copyList(allowedHeaders);
        exposedHeaders = copyList(exposedHeaders);
    }

    public static CorsPolicy permissive() {
        return new CorsPolicy(true, List.of(), defaultMethods(), List.of("*"), List.of(), false, 3600, true);
    }

    public static CorsPolicy strict(final List<String> allowedOrigins) {
        return new CorsPolicy(false, allowedOrigins, defaultMethods(), List.of("content-type", "authorization"),
                List.of(), false, 3600, true);
    }

    public boolean isOriginAllowed(final String origin) {
        if (allowAnyOrigin) {
            return true;
        }
        if (origin == null || origin.isBlank()) {
            return false;
        }
        for (final var allowed : allowedOrigins) {
            if (matches(allowed, origin)) {
                return true;
            }
        }
        return false;
    }

    public Map<String, String> responseHeaders(final String origin) {
        final var headers = new LinkedHashMap<String, String>();
        if (allowAnyOrigin) {
            headers.put("Access-Control-Allow-Origin", "*");
        } else if (isOriginAllowed(origin)) {
            headers.put("Access-Control-Allow-Origin", origin);
        }
        headers.put("Access-Control-Allow-Methods", String.join(", ", allowedMethods));
        headers.put("Access-Control-Allow-Headers", String.join(", ", allowedHeaders));
        if (!exposedHeaders.isEmpty()) {
            headers.put("Access-Control-Expose-Headers", String.join(", ", exposedHeaders));
        }
        if (allowCredentials) {
            headers.put("Access-Control-Allow-Credentials", "true");
        }
        headers.put("Access-Control-Max-Age", Integer.toString(maxAgeSeconds));
        if (varyOrigin) {
            headers.put("Vary", "Origin");
        }
        return headers;
    }

    private static List<String> copyList(final List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static boolean matches(final String allowed, final String candidate) {
        if (allowed == null || candidate == null) {
            return false;
        }
        if ("*".equals(allowed)) {
            return true;
        }
        return Objects.equals(allowed, candidate);
    }

    private static List<String> defaultMethods() {
        return List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD");
    }
}
