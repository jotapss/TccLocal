package br.edu.sentinela.service.strategy;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Ação para alertas CRITICAL: registra o incidente no audit log e simula a revogação da credencial.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CriticalAlertStrategy implements AlertStrategy {

    private final AuditLogService auditLogService;

    @Override
    public void execute(Alert alert) {
        log.warn("CRITICAL alert triggered: rule={} agent={} file={}",
            alert.getRuleId(), alert.getAgentId(), alert.getFilePath());

        // simula revogação imediata da credencial
        simulateRevocation(alert);

        auditLogService.log(
            "CRITICAL_ALERT_TRIGGERED",
            "Alert",
            alert.getId(),
            alert.getAgentId(),
            null,
            String.format("CRITICAL secret exposure detected. Rule: %s | File: %s | Preview: %s",
                alert.getRuleId(), alert.getFilePath(), alert.getSecretPreview())
        );
    }

    private void simulateRevocation(Alert alert) {
        // num sistema real chamaria a API da AWS IAM, endpoint de revogação do GitHub, etc.
        log.warn("SIMULATED REVOCATION initiated for rule={} in agent={}",
            alert.getRuleId(), alert.getAgentId());
        auditLogService.log(
            "REVOCATION_SIMULATED",
            "Alert",
            alert.getId(),
            alert.getAgentId(),
            null,
            "Automated revocation simulation for rule: " + alert.getRuleId()
        );
    }
}
