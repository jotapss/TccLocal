package br.edu.sentinela.security;

import br.edu.sentinela.config.TestCryptoConfig;
import br.edu.sentinela.exception.DecryptionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.OAEPParameterSpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

@DisplayName("RsaDecryptionService")
class RsaDecryptionServiceTest {

    private RsaDecryptionService service;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        testKeyPair = TestCryptoConfig.getKeyPair();
        service = new RsaDecryptionService(testKeyPair.getPrivate());
    }

    @Test
    @DisplayName("Decrypts a valid RSA-OAEP payload successfully")
    void decryptValidPayload() throws Exception {
        String plaintext = "{\"type\":\"SECRET_EXPOSED\",\"severity\":\"CRITICAL\",\"agent_id\":\"agent-01\"}";
        String ciphertext = encrypt(plaintext, testKeyPair);

        String result = service.decrypt(ciphertext);

        assertThat(result).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("Throws DecryptionException when payload is corrupted")
    void throwsOnCorruptedPayload() {
        String corrupted = Base64.getEncoder().encodeToString("this is not a valid ciphertext".getBytes());

        assertThatThrownBy(() -> service.decrypt(corrupted))
            .isInstanceOf(DecryptionException.class);
    }

    @Test
    @DisplayName("Throws DecryptionException when wrong private key is used")
    void throwsOnWrongKey() throws Exception {
        // cifra com o par de teste
        String plaintext  = "{\"secret\":\"test\"}";
        String ciphertext = encrypt(plaintext, testKeyPair);

        // tenta decriptar com um par diferente — deve falhar
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair wrongPair = gen.generateKeyPair();
        RsaDecryptionService wrongService = new RsaDecryptionService(wrongPair.getPrivate());

        assertThatThrownBy(() -> wrongService.decrypt(ciphertext))
            .isInstanceOf(DecryptionException.class);
    }

    @Test
    @DisplayName("Throws DecryptionException when input is invalid Base64")
    void throwsOnInvalidBase64() {
        assertThatThrownBy(() -> service.decrypt("!!!not_base64!!!"))
            .isInstanceOf(DecryptionException.class);
    }

    private String encrypt(String plaintext, KeyPair keyPair) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec params = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), params);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
