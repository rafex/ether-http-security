package dev.rafex.ether.http.security.profile;

import dev.rafex.ether.http.security.cors.CorsPolicy;
import dev.rafex.ether.http.security.headers.SecurityHeadersPolicy;
import dev.rafex.ether.http.security.ip.IpPolicy;
import dev.rafex.ether.http.security.proxy.TrustedProxyPolicy;
import dev.rafex.ether.http.security.ratelimit.RateLimitPolicy;

/**
 * Perfil de seguridad HTTP que agrupa todas las políticas de seguridad.
 * <p>
 * Define la configuración completa de seguridad para un servidor HTTP,
 * incluyendo CORS, encabezados de seguridad, control de IPs y rate limiting.
 * </p>
 */
public record HttpSecurityProfile(CorsPolicy cors, SecurityHeadersPolicy headers, TrustedProxyPolicy trustedProxies,
        IpPolicy ipPolicy, RateLimitPolicy rateLimit) {

    public static HttpSecurityProfile defaults() {
        return new HttpSecurityProfile(CorsPolicy.strict(java.util.List.of()), SecurityHeadersPolicy.defaults(),
                TrustedProxyPolicy.disabled(), IpPolicy.allowAll(),
                new RateLimitPolicy(RateLimitPolicy.Scope.GLOBAL, 0, 0, 0, 0));
    }
}
