package br.edu.sentinela;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class SentinelaApplication {
    public static void main(String[] args) {
        SpringApplication.run(SentinelaApplication.class, args);
    }
}
