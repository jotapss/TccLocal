package br.edu.sentinela.filter;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Limita requisições por agente (identificado pelo X-Agent-Token) usando Bucket4j.
 * O limite padrão é 100 requisições por minuto por agente.
 */
@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Value("${rate.limit.requests-per-minute:100}")
    private int requestsPerMinute;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        if (!isRateLimitedEndpoint(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String agentToken = request.getHeader("X-Agent-Token");
        if (agentToken == null || agentToken.isBlank()) {
            // Let downstream filters handle missing token
            filterChain.doFilter(request, response);
            return;
        }

        // Use the token as bucket key (not the hash — it's only in memory, never stored)
        Bucket bucket = buckets.computeIfAbsent(agentToken, this::newBucket);

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for agent (token hash prefix: {})",
                Integer.toHexString(agentToken.hashCode() & 0xFFFF));
            long waitSeconds = TimeUnit.NANOSECONDS.toSeconds(
                bucket.estimateAbilityToConsume(1).getNanosToWaitForRefill()
            );
            response.setHeader("Retry-After", String.valueOf(waitSeconds));
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded: max " +
                requestsPerMinute + " requests per minute\"}");
        }
    }

    private boolean isRateLimitedEndpoint(HttpServletRequest request) {
        String path   = request.getRequestURI();
        String method = request.getMethod();
        return ("POST".equals(method) && path.contains("/api/v1/alerts"))
            || path.startsWith("/api/v1/agents/");
    }

    private Bucket newBucket(String key) {
        Bandwidth limit = Bandwidth.builder()
            .capacity(requestsPerMinute)
            .refillIntervally(requestsPerMinute, Duration.ofMinutes(1))
            .build();
        return Bucket.builder().addLimit(limit).build();
    }
}
