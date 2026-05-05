package br.edu.sentinela.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Gera um par de chaves RSA-4096 em memória para os testes.
 * Estático para que todos os testes em um mesmo run compartilhem o mesmo par.
 */
@TestConfiguration
public class TestCryptoConfig {

    private static final KeyPair KEY_PAIR;

    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096);
            KEY_PAIR = gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate test RSA key pair", e);
        }
    }

    @Bean
    @Primary
    public PrivateKey rsaPrivateKey() {
        return KEY_PAIR.getPrivate();
    }

    @Bean
    @Primary
    public PublicKey rsaPublicKey() {
        return KEY_PAIR.getPublic();
    }

    public static KeyPair getKeyPair() {
        return KEY_PAIR;
    }
}
