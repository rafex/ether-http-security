package dev.rafex.ether.http.security.proxy;

import java.util.List;

/**
 * Política para configurar proxy de confianza en servidores.
 * <p>
 * Define qué proxies son de confianza y cómo extraer la IP real del cliente
 * cuando hay proxies o balanceadores de carga en medio.
 * </p>
 */
public record TrustedProxyPolicy(List<String> trustedSources, boolean trustForwardedHeader, boolean forwardedOnly,
        boolean preferRightMostForwardedFor) {

    public TrustedProxyPolicy {
        trustedSources = trustedSources == null ? List.of() : List.copyOf(trustedSources);
    }

    public static TrustedProxyPolicy disabled() {
        return new TrustedProxyPolicy(List.of(), false, false, true);
    }

    public boolean isTrusted(final String remoteAddress) {
        if (remoteAddress == null || remoteAddress.isBlank()) {
            return false;
        }
        for (final var source : trustedSources) {
            if (remoteAddress.equals(source) || remoteAddress.startsWith(source)) {
                return true;
            }
        }
        return false;
    }
}
