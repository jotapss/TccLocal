package br.edu.sentinela.security;

import br.edu.sentinela.exception.HmacValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Valida assinaturas HMAC-SHA256 do agente Node.js.
 * A comparação usa MessageDigest.isEqual() para ser em tempo constante
 * e evitar ataques de timing oracle.
 */
@Service
@Slf4j
public class HmacValidationService {

    private final byte[] hmacSecretBytes;

    public HmacValidationService(@Value("${hmac.secret}") String hmacSecret) {
        this.hmacSecretBytes = hmacSecret.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Valida o HMAC-SHA256 sobre o payload em texto claro.
     * O agente assina o JSON antes de cifrar: HMAC(plaintext, HMAC_SECRET) → hex.
     */
    public void validate(String plaintext, String expectedHexHmac) {
        try {
            byte[] computed = computeHmac(plaintext);
            String computedHex = HexFormat.of().formatHex(computed);

            boolean matches = MessageDigest.isEqual(
                computedHex.getBytes(StandardCharsets.UTF_8),
                expectedHexHmac.toLowerCase().getBytes(StandardCharsets.UTF_8)
            );

            if (!matches) {
                throw new HmacValidationException("HMAC signature mismatch");
            }
        } catch (HmacValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new HmacValidationException("HMAC computation failed: " + e.getMessage());
        }
    }

    public byte[] computeHmac(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacSecretBytes, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    public String computeHmacHex(String data) throws Exception {
        return HexFormat.of().formatHex(computeHmac(data));
    }
}
