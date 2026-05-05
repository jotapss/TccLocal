package br.edu.sentinela.controller;

import br.edu.sentinela.dto.request.AgentAuthRequest;
import br.edu.sentinela.dto.request.UserLoginRequest;
import br.edu.sentinela.dto.response.AuthTokenResponse;
import br.edu.sentinela.model.User;
import br.edu.sentinela.repository.AgentRepository;
import br.edu.sentinela.repository.UserRepository;
import br.edu.sentinela.security.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final JwtService            jwtService;
    private final AgentRepository       agentRepository;
    private final UserRepository        userRepository;
    private final AuthenticationManager authenticationManager;

    @Value("${auth.cookie.secure:false}")
    private boolean secureCookie;

    /**
     * POST /api/v1/auth/token
     * O agente troca o agent_token por um JWT de curta duração.
     */
    @PostMapping("/token")
    public ResponseEntity<AuthTokenResponse> agentToken(@Valid @RequestBody AgentAuthRequest request) {
        String tokenHash = sha256Hex(request.getAgentToken());

        var agent = agentRepository.findByTokenHash(tokenHash)
            .filter(a -> Boolean.TRUE.equals(a.getActive()))
            .orElseThrow(() -> new BadCredentialsException("Invalid or inactive agent token"));

        if (!agent.getAgentId().equals(request.getAgentId())) {
            throw new BadCredentialsException("agent_id does not match token");
        }

        String accessToken  = jwtService.generateAccessToken(
            agent.getAgentId(), "AGENT", Map.of("role", "AGENT"));
        String refreshToken = jwtService.generateRefreshToken(agent.getAgentId(), "AGENT");

        log.info("JWT issued for agent {}", agent.getAgentId());

        return ResponseEntity.ok(AuthTokenResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtService.getAccessExpirationMs() / 1000)
            .build());
    }

    /**
     * POST /api/v1/auth/refresh
     * Renova o access token a partir de um refresh token válido.
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthTokenResponse> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refresh_token");
        if (refreshToken == null || !jwtService.isTokenValid(refreshToken) || !jwtService.isRefreshToken(refreshToken)) {
            throw new BadCredentialsException("Invalid or expired refresh token");
        }

        String subject = jwtService.extractSubject(refreshToken);
        String type    = jwtService.extractType(refreshToken);
        String role    = "AGENT".equals(type) ? "AGENT" : "USER";

        String newAccessToken = jwtService.generateAccessToken(subject, type, Map.of("role", role));

        return ResponseEntity.ok(AuthTokenResponse.builder()
            .accessToken(newAccessToken)
            .refreshToken(refreshToken)
            .tokenType("Bearer")
            .expiresIn(jwtService.getAccessExpirationMs() / 1000)
            .build());
    }

    /**
     * POST /api/v1/auth/login
     * Login para usuários do dashboard. Retorna o JWT em cookie HttpOnly (proteção XSS).
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @Valid @RequestBody UserLoginRequest request,
            HttpServletResponse response) {

        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new BadCredentialsException("User not found"));

        user.setLastLogin(Instant.now());
        userRepository.save(user);

        String token = jwtService.generateAccessToken(
            user.getUsername(), "USER", Map.of("role", user.getRole().name()));

        Cookie cookie = new Cookie("auth_token", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtService.getAccessExpirationMs() / 1000));
        response.addCookie(cookie);

        log.info("User {} logged in", user.getUsername());
        return ResponseEntity.ok(Map.of("message", "Login successful", "username", user.getUsername()));
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
