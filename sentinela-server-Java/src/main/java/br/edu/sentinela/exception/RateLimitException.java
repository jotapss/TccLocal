package br.edu.sentinela.exception;

public class RateLimitException extends RuntimeException {
    public RateLimitException(String agentId) {
        super("Rate limit exceeded for agent: " + agentId);
    }
}
