package dev.rafex.ether.http.security.ratelimit;

/**
 * Política de control de tasa (rate limiting) para prevenir abusos.
 * <p>
 * Limita la cantidad de solicitudes por ventana de tiempo para proteger
 * contra ataques de fuerza bruta o abuso de recursos.
 * </p>
 */
public record RateLimitPolicy(Scope scope, int maxRequests, int windowSeconds, int burst, int maxConcurrentRequests) {

    /**
     * Alcance de la política de rate limiting.
     * <ul>
     *   <li>GLOBAL: Un límite compartido por todos los clientes</li>
     *   <li>PER_IP: Un límite por cada dirección IP</li>
     * </ul>
     */
    public enum Scope {
        GLOBAL, PER_IP
    }

    /**
     * Verifica si el rate limiting está habilitado.
     * @return true si maxRequests > 0 y windowSeconds > 0
     */
    public boolean isEnabled() {
        return maxRequests > 0 && windowSeconds > 0;
    }
}
