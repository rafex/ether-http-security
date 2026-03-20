package dev.rafex.ether.http.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import dev.rafex.ether.http.security.ip.IpPolicy;
import dev.rafex.ether.http.security.profile.HttpSecurityProfile;

class HttpSecurityProfileTest {

    @Test
    void ipPolicyShouldRespectAllowAndDenyRules() {
        final var policy = new IpPolicy(List.of("10.0.", "192.168.1.10"), List.of("10.0.0.5"));

        assertTrue(policy.isAllowed("10.0.0.7"));
        assertFalse(policy.isAllowed("10.0.0.5"));
    }

    @Test
    void rateLimitShouldBeDisabledByDefault() {
        final var profile = HttpSecurityProfile.defaults();

        assertFalse(profile.rateLimit().isEnabled());
    }
}
