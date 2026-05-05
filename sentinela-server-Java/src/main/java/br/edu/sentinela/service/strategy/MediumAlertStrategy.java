package br.edu.sentinela.service.strategy;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/** Ação para alertas MEDIUM: registra a detecção no audit log para análise posterior. */
@Component
@RequiredArgsConstructor
@Slf4j
public class MediumAlertStrategy implements AlertStrategy {

    private final AuditLogService auditLogService;

    @Override
    public void execute(Alert alert) {
        log.warn("MEDIUM alert: rule={} agent={} file={}",
            alert.getRuleId(), alert.getAgentId(), alert.getFilePath());

        auditLogService.log(
            "MEDIUM_ALERT_TRIGGERED",
            "Alert",
            alert.getId(),
            alert.getAgentId(),
            null,
            String.format("Medium risk secret exposure. Rule: %s | File: %s",
                alert.getRuleId(), alert.getFilePath())
        );
    }
}
