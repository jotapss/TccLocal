package br.edu.sentinela.service.chain;

import br.edu.sentinela.dto.request.AlertEnvelopeRequest;
import lombok.Getter;
import lombok.Setter;

/**
 * Objeto de contexto mutável que percorre a cadeia de processamento.
 * Carrega o envelope original, campos sanitizados e estado de deduplicação.
 */
@Getter
@Setter
public class AlertContext {

    private final AlertEnvelopeRequest envelope;

    /** Marcado pelo DeduplicationHandler quando o checksum já existe no banco. */
    private boolean duplicate = false;

    private String existingAlertId;

    private String sanitizedFilePath;
    private String sanitizedRuleId;
    private String sanitizedAgentId;

    public AlertContext(AlertEnvelopeRequest envelope) {
        this.envelope       = envelope;
        this.sanitizedFilePath = envelope.getFilePath();
        this.sanitizedRuleId   = envelope.getRuleId();
        this.sanitizedAgentId  = envelope.getAgentId();
    }
}
