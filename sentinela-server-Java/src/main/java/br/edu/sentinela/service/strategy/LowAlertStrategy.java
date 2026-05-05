package br.edu.sentinela.service.strategy;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/** Ação para alertas LOW: apenas registra a detecção no audit log. */
@Component
@RequiredArgsConstructor
@Slf4j
public class LowAlertStrategy implements AlertStrategy {

    private final AuditLogService auditLogService;

    @Override
    public void execute(Alert alert) {
        log.info("LOW alert: rule={} agent={}", alert.getRuleId(), alert.getAgentId());

        auditLogService.log(
            "LOW_ALERT_REGISTERED",
            "Alert",
            alert.getId(),
            alert.getAgentId(),
            null,
            "Low risk detection recorded. Rule: " + alert.getRuleId()
        );
    }
}
