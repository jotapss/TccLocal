package br.edu.sentinela.security;

import br.edu.sentinela.exception.HmacValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("HmacValidationService")
class HmacValidationServiceTest {

    private static final String HMAC_SECRET = "test_hmac_secret_for_unit_tests";
    private HmacValidationService service;

    @BeforeEach
    void setUp() {
        service = new HmacValidationService(HMAC_SECRET);
    }

    @Test
    @DisplayName("Passes validation with correct HMAC signature")
    void passesWithValidSignature() throws Exception {
        String payload = "{\"type\":\"SECRET_EXPOSED\",\"severity\":\"CRITICAL\"}";
        String signature = service.computeHmacHex(payload);

        assertThatCode(() -> service.validate(payload, signature))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Throws HmacValidationException when signature is altered")
    void throwsOnAlteredSignature() throws Exception {
        String payload = "{\"type\":\"SECRET_EXPOSED\"}";
        String signature = service.computeHmacHex(payload);
        // altera o último char para simular adulteração
        String tampered = signature.substring(0, signature.length() - 1) +
            (signature.endsWith("a") ? "b" : "a");

        assertThatThrownBy(() -> service.validate(payload, tampered))
            .isInstanceOf(HmacValidationException.class)
            .hasMessageContaining("mismatch");
    }

    @Test
    @DisplayName("Throws HmacValidationException when payload differs from signed payload")
    void throwsOnAlteredPayload() throws Exception {
        String original  = "{\"severity\":\"CRITICAL\"}";
        String tampered  = "{\"severity\":\"LOW\"}";
        String signature = service.computeHmacHex(original);

        assertThatThrownBy(() -> service.validate(tampered, signature))
            .isInstanceOf(HmacValidationException.class);
    }

    @Test
    @DisplayName("Throws HmacValidationException when wrong HMAC secret is used")
    void throwsOnWrongSecret() throws Exception {
        String payload    = "{\"type\":\"SECRET_EXPOSED\"}";
        HmacValidationService otherService = new HmacValidationService("completely_different_secret");
        String signature  = otherService.computeHmacHex(payload);

        assertThatThrownBy(() -> service.validate(payload, signature))
            .isInstanceOf(HmacValidationException.class);
    }

    @Test
    @DisplayName("Accepts hex signatures in any case (upper/lower)")
    void acceptsCaseInsensitiveHex() throws Exception {
        String payload    = "{\"test\":\"value\"}";
        String signature  = service.computeHmacHex(payload).toUpperCase();

        assertThatCode(() -> service.validate(payload, signature))
            .doesNotThrowAnyException();
    }
}
