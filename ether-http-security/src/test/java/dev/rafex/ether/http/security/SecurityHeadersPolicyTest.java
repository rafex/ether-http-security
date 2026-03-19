package dev.rafex.ether.http.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SecurityHeadersPolicyTest {

	@Test
	void defaultsShouldEmitCommonHeaders() {
		final var headers = SecurityHeadersPolicy.defaults().headers();

		assertEquals("nosniff", headers.get("X-Content-Type-Options"));
		assertEquals("DENY", headers.get("X-Frame-Options"));
		assertTrue(headers.containsKey("Strict-Transport-Security"));
	}
}
