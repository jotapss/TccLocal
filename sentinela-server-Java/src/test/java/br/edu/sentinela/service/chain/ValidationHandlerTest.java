package br.edu.sentinela.service.chain;

import br.edu.sentinela.dto.request.AlertEnvelopeRequest;
import br.edu.sentinela.exception.AlertValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

import static org.assertj.core.api.Assertions.*;

@DisplayName("ValidationHandler")
class ValidationHandlerTest {

    private ValidationHandler handler;

    @BeforeEach
    void setUp() {
        handler = new ValidationHandler();
    }

    private AlertEnvelopeRequest validEnvelope() {
        AlertEnvelopeRequest req = new AlertEnvelopeRequest();
        req.setData("encryptedBase64Data");
        req.setSignature("a".repeat(64));   // 64-char hex
        req.setChecksum("b".repeat(64));    // 64-char hex
        req.setAgentId("agent-01");
        req.setSeverity("CRITICAL");
        req.setEventTime(Instant.now().toString());
        req.setRuleId("AWS_ACCESS_KEY_001");
        req.setFilePath("/app/.env");
        return req;
    }

    @Test
    @DisplayName("Passes with a valid envelope")
    void passesValidEnvelope() {
        AlertContext context = new AlertContext(validEnvelope());
        assertThatCode(() -> handler.handle(context)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Throws for invalid severity enum value")
    void throwsOnInvalidSeverity() {
        AlertEnvelopeRequest req = validEnvelope();
        req.setSeverity("EXTREME");
        AlertContext context = new AlertContext(req);

        assertThatThrownBy(() -> handler.handle(context))
            .isInstanceOf(AlertValidationException.class)
            .hasMessageContaining("Invalid severity");
    }

    @Test
    @DisplayName("Throws for invalid checksum format")
    void throwsOnInvalidChecksum() {
        AlertEnvelopeRequest req = validEnvelope();
        req.setChecksum("not_a_valid_hex_checksum");
        AlertContext context = new AlertContext(req);

        assertThatThrownBy(() -> handler.handle(context))
            .isInstanceOf(AlertValidationException.class)
            .hasMessageContaining("checksum");
    }

    @Test
    @DisplayName("Throws for event_time beyond ±30 seconds")
    void throwsOnOldTimestamp() {
        AlertEnvelopeRequest req = validEnvelope();
        // 5 minutos no passado — além da tolerância de ±30s
        req.setEventTime(Instant.now().minusSeconds(300).toString());
        AlertContext context = new AlertContext(req);

        assertThatThrownBy(() -> handler.handle(context))
            .isInstanceOf(AlertValidationException.class)
            .hasMessageContaining("tolerance");
    }

    @Test
    @DisplayName("Throws for malformed ISO-8601 event_time")
    void throwsOnMalformedTimestamp() {
        AlertEnvelopeRequest req = validEnvelope();
        req.setEventTime("2025-13-99 invalid");
        AlertContext context = new AlertContext(req);

        assertThatThrownBy(() -> handler.handle(context))
            .isInstanceOf(AlertValidationException.class)
            .hasMessageContaining("event_time");
    }

    @Test
    @DisplayName("Calls next handler when configured")
    void callsNextHandler() {
        AlertContext[] received = {null};
        AlertHandler mockNext = new AlertHandler() {
            @Override public AlertHandler setNext(AlertHandler n) { return n; }
            @Override public AlertContext handle(AlertContext ctx) { received[0] = ctx; return ctx; }
        };
        handler.setNext(mockNext);

        AlertContext context = new AlertContext(validEnvelope());
        handler.handle(context);

        assertThat(received[0]).isSameAs(context);
    }
}
