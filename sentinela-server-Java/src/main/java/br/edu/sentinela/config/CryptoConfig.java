package br.edu.sentinela.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Carrega as chaves RSA-4096 uma única vez na inicialização.
 * A chave privada fica em memória e nunca é gravada em log ou armazenamento persistente.
 */
@Configuration
@Slf4j
public class CryptoConfig {

    private final ResourceLoader resourceLoader;

    @Value("${crypto.private-key-path:classpath:keys/private_key.pem}")
    private String privateKeyPath;

    @Value("${crypto.public-key-path:classpath:keys/public_key.pem}")
    private String publicKeyPath;

    public CryptoConfig(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @Bean
    public PrivateKey rsaPrivateKey() throws Exception {
        log.info("Loading RSA private key from {}", privateKeyPath);
        String pem = readPem(privateKeyPath);
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    @Bean
    public PublicKey rsaPublicKey() throws Exception {
        log.info("Loading RSA public key from {}", publicKeyPath);
        String pem = readPem(publicKeyPath);
        String base64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private String readPem(String path) throws IOException {
        Resource resource = resourceLoader.getResource(path);
        try (var inputStream = resource.getInputStream()) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
