package br.edu.sentinela.service.chain;

import br.edu.sentinela.exception.AlertValidationException;
import br.edu.sentinela.model.Severity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Valida o envelope antes de qualquer processamento — rejeita rápido se algo estiver errado.
 * Verifica: severity válida, checksum e signature em hex de 64 chars, event_time em ±30s do servidor.
 */
@Component
@Slf4j
public class ValidationHandler implements AlertHandler {

    private static final long TIMESTAMP_TOLERANCE_SECONDS = 30;

    private AlertHandler next;

    @Override
    public AlertHandler setNext(AlertHandler next) {
        this.next = next;
        return next;
    }

    @Override
    public AlertContext handle(AlertContext context) {
        var envelope = context.getEnvelope();

        // Validate severity enum
        try {
            Severity.valueOf(envelope.getSeverity().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new AlertValidationException("Invalid severity: " + envelope.getSeverity());
        }

        // Validate checksum format (64-char hex)
        if (!envelope.getChecksum().matches("[0-9a-fA-F]{64}")) {
            throw new AlertValidationException("Invalid checksum format — expected 64-char hex SHA-256");
        }

        // Validate signature format (64-char hex)
        if (!envelope.getSignature().matches("[0-9a-fA-F]{64}")) {
            throw new AlertValidationException("Invalid signature format — expected 64-char hex HMAC-SHA256");
        }

        // Validate event_time within ±30 seconds
        Instant eventTime;
        try {
            eventTime = Instant.parse(envelope.getEventTime());
        } catch (DateTimeParseException e) {
            throw new AlertValidationException("Invalid event_time format — expected ISO-8601");
        }

        long diffSeconds = Math.abs(Instant.now().getEpochSecond() - eventTime.getEpochSecond());
        if (diffSeconds > TIMESTAMP_TOLERANCE_SECONDS) {
            throw new AlertValidationException("event_time must be within ±30 seconds of server time");
        }

        log.debug("Validation passed for agent {} rule {}", envelope.getAgentId(), envelope.getRuleId());

        return next != null ? next.handle(context) : context;
    }
}
