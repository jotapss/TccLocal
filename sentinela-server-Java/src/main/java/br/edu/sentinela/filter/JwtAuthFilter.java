package br.edu.sentinela.filter;

import br.edu.sentinela.security.JwtService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Valida o JWT do header Authorization (Bearer) ou do cookie HttpOnly auth_token.
 * Preenche o SecurityContext para os filtros e handlers seguintes.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                if (jwtService.isTokenValid(token) && !jwtService.isRefreshToken(token)) {
                    String subject = jwtService.extractSubject(token);
                    String type    = jwtService.extractType(token);
                    String role    = jwtService.extractAllClaims(token).get("role", String.class);

                    List<SimpleGrantedAuthority> authorities = role != null
                        ? List.of(new SimpleGrantedAuthority("ROLE_" + role))
                        : List.of(new SimpleGrantedAuthority("ROLE_AGENT"));

                    var authToken = new UsernamePasswordAuthenticationToken(
                        subject, null, authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    authToken.getDetails();
                    // Store type for downstream use
                    request.setAttribute("jwt_subject", subject);
                    request.setAttribute("jwt_type", type);
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } catch (JwtException e) {
                log.debug("Invalid JWT: {}", e.getClass().getSimpleName());
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        // Check HttpOnly cookie for dashboard users
        if (request.getCookies() != null) {
            Optional<Cookie> cookieOpt = Arrays.stream(request.getCookies())
                .filter(c -> "auth_token".equals(c.getName()))
                .findFirst();
            if (cookieOpt.isPresent()) {
                return cookieOpt.get().getValue();
            }
        }
        return null;
    }
}
