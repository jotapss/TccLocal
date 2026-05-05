package br.edu.sentinela.service.chain;

import br.edu.sentinela.dto.request.AlertEnvelopeRequest;
import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("DeduplicationHandler")
class DeduplicationHandlerTest {

    @Mock
    private AlertRepository alertRepository;

    @InjectMocks
    private DeduplicationHandler handler;

    private static final String CHECKSUM = "a".repeat(64);

    private AlertEnvelopeRequest envelopeWith(String checksum) {
        AlertEnvelopeRequest req = new AlertEnvelopeRequest();
        req.setData("data");
        req.setSignature("b".repeat(64));
        req.setChecksum(checksum);
        req.setAgentId("agent-01");
        req.setSeverity("CRITICAL");
        req.setEventTime(Instant.now().toString());
        req.setRuleId("RULE_001");
        req.setFilePath("/path");
        return req;
    }

    @Test
    @DisplayName("Does NOT mark context as duplicate for a new checksum")
    void doesNotMarkDuplicateForNewChecksum() {
        when(alertRepository.findByChecksum(CHECKSUM)).thenReturn(Optional.empty());

        AlertContext context = new AlertContext(envelopeWith(CHECKSUM));
        handler.handle(context);

        assertThat(context.isDuplicate()).isFalse();
        assertThat(context.getExistingAlertId()).isNull();
    }

    @Test
    @DisplayName("Marks context as duplicate when checksum exists in DB")
    void marksDuplicateForExistingChecksum() {
        Alert existing = Alert.builder()
            .id("existing-id-123")
            .agentId("agent-01")
            .severity(Severity.CRITICAL)
            .checksum(CHECKSUM)
            .build();
        when(alertRepository.findByChecksum(CHECKSUM)).thenReturn(Optional.of(existing));

        AlertContext context = new AlertContext(envelopeWith(CHECKSUM));
        handler.handle(context);

        assertThat(context.isDuplicate()).isTrue();
        assertThat(context.getExistingAlertId()).isEqualTo("existing-id-123");
    }

    @Test
    @DisplayName("Short-circuits chain on duplicate — next handler is NOT called")
    void shortCircuitsChainOnDuplicate() {
        Alert existing = Alert.builder().id("dup-id").checksum(CHECKSUM).build();
        when(alertRepository.findByChecksum(CHECKSUM)).thenReturn(Optional.of(existing));

        boolean[] nextCalled = {false};
        AlertHandler mockNext = new AlertHandler() {
            @Override public AlertHandler setNext(AlertHandler n) { return n; }
            @Override public AlertContext handle(AlertContext ctx) { nextCalled[0] = true; return ctx; }
        };
        handler.setNext(mockNext);

        AlertContext context = new AlertContext(envelopeWith(CHECKSUM));
        handler.handle(context);

        assertThat(nextCalled[0]).isFalse();
    }
}
