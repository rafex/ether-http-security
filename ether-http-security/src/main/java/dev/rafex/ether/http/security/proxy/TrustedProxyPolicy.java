package dev.rafex.ether.http.security.proxy;

import java.util.List;

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
