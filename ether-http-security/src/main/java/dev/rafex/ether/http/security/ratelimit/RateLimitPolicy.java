package dev.rafex.ether.http.security.ratelimit;

public record RateLimitPolicy(Scope scope, int maxRequests, int windowSeconds, int burst, int maxConcurrentRequests) {

    public enum Scope {
        GLOBAL, PER_IP
    }

    public boolean isEnabled() {
        return maxRequests > 0 && windowSeconds > 0;
    }
}
