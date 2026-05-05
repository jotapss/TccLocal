package br.edu.sentinela.security;

import br.edu.sentinela.exception.DecryptionException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.OAEPParameterSpec;
import java.util.Base64;

/**
 * Decripta payloads RSA-4096 OAEP+SHA-256 recebidos do agente.
 * Os dados decriptados existem apenas em memória — nunca são persistidos ou logados.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RsaDecryptionService {

    private final PrivateKey rsaPrivateKey;

    /** Decripta um ciphertext Base64 com RSA-OAEP+SHA-256. Lança DecryptionException em qualquer falha. */
    public String decrypt(String base64Ciphertext) {
        try {
            byte[] cipherBytes = Base64.getDecoder().decode(base64Ciphertext);

            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            );
            cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey, oaepParams);

            byte[] plainBytes = cipher.doFinal(cipherBytes);
            return new String(plainBytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new DecryptionException("Invalid Base64 encoding in payload", e);
        } catch (Exception e) {
            throw new DecryptionException("RSA decryption failed: " + e.getClass().getSimpleName(), e);
        }
    }
}
