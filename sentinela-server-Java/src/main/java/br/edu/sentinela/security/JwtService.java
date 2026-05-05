package br.edu.sentinela.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

@Service
@Slf4j
public class JwtService {

    private final SecretKey secretKey;
    private final long accessExpirationMs;
    private final long refreshExpirationMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms:900000}") long accessExpirationMs,
            @Value("${jwt.refresh-expiration-ms:604800000}") long refreshExpirationMs) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpirationMs = accessExpirationMs;
        this.refreshExpirationMs = refreshExpirationMs;
    }

    public String generateAccessToken(String subject, String type, Map<String, Object> extraClaims) {
        return buildToken(subject, type, extraClaims, accessExpirationMs);
    }

    public String generateRefreshToken(String subject, String type) {
        return buildToken(subject, type, Map.of("token_type", "REFRESH"), refreshExpirationMs);
    }

    private String buildToken(String subject, String type, Map<String, Object> claims, long expirationMs) {
        Date now = new Date();
        return Jwts.builder()
            .subject(subject)
            .claim("type", type)
            .claims(claims)
            .issuedAt(now)
            .expiration(new Date(now.getTime() + expirationMs))
            .signWith(secretKey)
            .compact();
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(secretKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    public String extractSubject(String token) {
        return extractAllClaims(token).getSubject();
    }

    public String extractType(String token) {
        return extractAllClaims(token).get("type", String.class);
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            log.debug("JWT validation failed: {}", e.getClass().getSimpleName());
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractAllClaims(token).get("token_type", String.class);
            return "REFRESH".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    public long getAccessExpirationMs() {
        return accessExpirationMs;
    }
}
