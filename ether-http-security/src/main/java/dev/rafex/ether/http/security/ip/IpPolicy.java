package dev.rafex.ether.http.security.ip;

import java.util.List;

/**
 * Política de control de acceso basada en direcciones IP.
 * <p>
 * Permite definir listas de permitidos y denegados para controlar
 * qué direcciones IP pueden acceder a los recursos.
 * </p>
 */
public record IpPolicy(List<String> allowList, List<String> denyList) {

    public IpPolicy {
        allowList = allowList == null ? List.of() : List.copyOf(allowList);
        denyList = denyList == null ? List.of() : List.copyOf(denyList);
    }

    public static IpPolicy allowAll() {
        return new IpPolicy(List.of(), List.of());
    }

    public boolean isAllowed(final String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        for (final var deny : denyList) {
            if (matches(deny, ip)) {
                return false;
            }
        }
        if (allowList.isEmpty()) {
            return true;
        }
        for (final var allow : allowList) {
            if (matches(allow, ip)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matches(final String rule, final String ip) {
        if (rule == null || rule.isBlank()) {
            return false;
        }
        if ("*".equals(rule)) {
            return true;
        }
        return ip.equals(rule) || ip.startsWith(rule);
    }
}
