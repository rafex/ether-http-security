package dev.rafex.ether.http.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import dev.rafex.ether.http.security.cors.CorsPolicy;

class CorsPolicyTest {

    @Test
    void strictPolicyShouldAllowConfiguredOrigin() {
        final var policy = CorsPolicy.strict(List.of("https://app.example.com"));

        assertTrue(policy.isOriginAllowed("https://app.example.com"));
        assertEquals("https://app.example.com",
                policy.responseHeaders("https://app.example.com").get("Access-Control-Allow-Origin"));
    }

    @Test
    void permissivePolicyShouldEmitWildcard() {
        final var policy = CorsPolicy.permissive();

        assertEquals("*", policy.responseHeaders("https://any.example").get("Access-Control-Allow-Origin"));
    }
}
