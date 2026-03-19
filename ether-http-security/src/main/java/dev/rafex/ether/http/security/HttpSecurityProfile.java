package dev.rafex.ether.http.security;

public record HttpSecurityProfile(
		CorsPolicy cors,
		SecurityHeadersPolicy headers,
		TrustedProxyPolicy trustedProxies,
		IpPolicy ipPolicy,
		RateLimitPolicy rateLimit) {

	public static HttpSecurityProfile defaults() {
		return new HttpSecurityProfile(
				CorsPolicy.strict(java.util.List.of()),
				SecurityHeadersPolicy.defaults(),
				TrustedProxyPolicy.disabled(),
				IpPolicy.allowAll(),
				new RateLimitPolicy(RateLimitPolicy.Scope.GLOBAL, 0, 0, 0, 0));
	}
}
