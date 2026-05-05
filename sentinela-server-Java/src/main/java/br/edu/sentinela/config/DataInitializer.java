package br.edu.sentinela.config;

import br.edu.sentinela.model.User;
import br.edu.sentinela.model.UserRole;
import br.edu.sentinela.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.username:admin}")
    private String adminUsername;

    @Value("${admin.password:Admin@changeme123}")
    private String adminPassword;

    @Value("${admin.reset-password:false}")
    private boolean resetAdminPassword;

    @Override
    public void run(ApplicationArguments args) {
        if (!userRepository.existsByUsername(adminUsername)) {
            User admin = User.builder()
                .username(adminUsername)
                .password(passwordEncoder.encode(adminPassword))
                .role(UserRole.ADMIN)
                .active(true)
                .build();
            userRepository.save(admin);
            log.info("Default admin user '{}' created. CHANGE THE PASSWORD IMMEDIATELY.", adminUsername);
        } else if (resetAdminPassword) {
            User admin = userRepository.findByUsername(adminUsername)
                .orElseThrow(() -> new IllegalStateException("Admin user not found: " + adminUsername));
            admin.setPassword(passwordEncoder.encode(adminPassword));
            userRepository.save(admin);
            log.warn("Admin user '{}' password reset by configuration. Disable admin.reset-password after login.", adminUsername);
        }
    }
}
