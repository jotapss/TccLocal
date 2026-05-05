package br.edu.sentinela.service.factory;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.service.chain.AlertContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Cria entidades Alert a partir do payload decriptado e do contexto validado.
 * Centraliza a construção para manter o service livre desses detalhes.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AlertFactory {

    private final ObjectMapper objectMapper;

    /** Monta o Alert com os campos sanitizados do contexto e o preview já mascarado. */
    public Alert create(String decryptedJson, AlertContext context, String maskedPreview) {
        try {
            JsonNode node = objectMapper.readTree(decryptedJson);

            String agentId    = context.getSanitizedAgentId();
            String severityStr = context.getEnvelope().getSeverity().toUpperCase();
            Severity severity  = Severity.valueOf(severityStr);
            String ruleId     = context.getSanitizedRuleId();
            String filePath   = context.getSanitizedFilePath();
            Integer line      = node.has("line") && !node.get("line").isNull()
                ? node.get("line").asInt() : null;
            Instant eventTime = Instant.parse(context.getEnvelope().getEventTime());
            String checksum   = context.getEnvelope().getChecksum();

            return Alert.builder()
                .agentId(agentId)
                .severity(severity)
                .status(AlertStatus.OPEN)
                .ruleId(ruleId)
                .filePath(filePath)
                .secretPreview(maskedPreview)
                .lineNumber(line)
                .checksum(checksum)
                .eventTime(eventTime)
                .build();

        } catch (Exception e) {
            log.error("AlertFactory failed to parse decrypted payload", e);
            throw new IllegalStateException("Failed to create Alert from payload", e);
        }
    }
}
