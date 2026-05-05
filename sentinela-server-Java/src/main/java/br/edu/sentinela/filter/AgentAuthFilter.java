package br.edu.sentinela.filter;

import br.edu.sentinela.repository.AgentRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Valida o header X-Agent-Token nos endpoints de ingestão de alertas.
 * O token é convertido em SHA-256 e comparado com o hash armazenado —
 * o token em texto claro nunca é gravado ou logado.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AgentAuthFilter extends OncePerRequestFilter {

    private final AgentRepository agentRepository;

    private static final String AGENT_TOKEN_HEADER = "X-Agent-Token";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        if (!requiresAgentAuth(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String agentToken = request.getHeader(AGENT_TOKEN_HEADER);
        if (agentToken == null || agentToken.isBlank()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "X-Agent-Token header is required");
            return;
        }

        try {
            String tokenHash = sha256Hex(agentToken);
            boolean valid = agentRepository.findByTokenHash(tokenHash)
                .map(agent -> Boolean.TRUE.equals(agent.getActive()))
                .orElse(false);

            if (!valid) {
                log.warn("Invalid or inactive agent token received");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid agent token");
                return;
            }

            request.setAttribute("agent_token_hash", tokenHash);
        } catch (Exception e) {
            log.error("Agent token validation error", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token validation error");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresAgentAuth(HttpServletRequest request) {
        String path   = request.getRequestURI();
        String method = request.getMethod();
        // só a ingestão de alertas exige X-Agent-Token.
        // /api/v1/agents/** (register, status) são protegidos por JWT de admin, não por token de agente.
        return "POST".equals(method) && path.contains("/api/v1/alerts");
    }

    private String sha256Hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
