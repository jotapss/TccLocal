package br.edu.sentinela.config;

import jakarta.servlet.http.HttpServletResponse;
import br.edu.sentinela.filter.AgentAuthFilter;
import br.edu.sentinela.filter.JwtAuthFilter;
import br.edu.sentinela.filter.RateLimitingFilter;
import br.edu.sentinela.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter      jwtAuthFilter;
    private final AgentAuthFilter    agentAuthFilter;
    private final RateLimitingFilter rateLimitingFilter;
    private final UserRepository     userRepository;
    private final CorsConfig         corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfig.corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/v1/auth/token",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/login",
                    "/actuator/health"
                ).permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/agents/register")
                    .hasRole("ADMIN")
                .requestMatchers("/api/v1/dashboard/**")
                    .hasAnyRole("ADMIN", "ANALYST")
                .requestMatchers("/api/v1/agents/**")
                    .hasAnyRole("ADMIN", "ANALYST")
                .anyRequest().authenticated()
            )
            // Filter order: RateLimit → AgentAuth → JwtAuth → UsernamePassword
            .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(agentAuthFilter,    RateLimitingFilter.class)
            .addFilterBefore(jwtAuthFilter,      AgentAuthFilter.class);

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
