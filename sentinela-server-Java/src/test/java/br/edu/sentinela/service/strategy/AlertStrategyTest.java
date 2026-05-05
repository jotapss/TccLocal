package br.edu.sentinela.service.strategy;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.service.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("AlertStrategy")
class AlertStrategyTest {

    @Mock
    private AuditLogService auditLogService;

    private CriticalAlertStrategy criticalStrategy;
    private MediumAlertStrategy   mediumStrategy;
    private LowAlertStrategy      lowStrategy;

    @BeforeEach
    void setUp() {
        criticalStrategy = new CriticalAlertStrategy(auditLogService);
        mediumStrategy   = new MediumAlertStrategy(auditLogService);
        lowStrategy      = new LowAlertStrategy(auditLogService);
    }

    private Alert alert(Severity severity) {
        return Alert.builder()
            .id("alert-001")
            .agentId("agent-prod-01")
            .severity(severity)
            .status(AlertStatus.OPEN)
            .ruleId("AWS_ACCESS_KEY_001")
            .filePath("/app/.env")
            .secretPreview("AKIA*****LE")
            .build();
    }

    @Test
    @DisplayName("CRITICAL strategy triggers immediate revocation simulation and logs twice")
    void criticalExecutesImmediateAction() {
        criticalStrategy.execute(alert(Severity.CRITICAL));

        // CRITICAL dispara dois logs: o alerta e a simulação de revogação
        verify(auditLogService, times(2)).log(
            anyString(), eq("Alert"), eq("alert-001"),
            eq("agent-prod-01"), isNull(), anyString()
        );
        verify(auditLogService).log(
            eq("CRITICAL_ALERT_TRIGGERED"), any(), any(), any(), any(), any()
        );
        verify(auditLogService).log(
            eq("REVOCATION_SIMULATED"), any(), any(), any(), any(), any()
        );
    }

    @Test
    @DisplayName("MEDIUM strategy generates alert notification log entry")
    void mediumGeneratesAlertNotification() {
        mediumStrategy.execute(alert(Severity.MEDIUM));

        verify(auditLogService, times(1)).log(
            eq("MEDIUM_ALERT_TRIGGERED"), eq("Alert"), eq("alert-001"),
            eq("agent-prod-01"), isNull(), anyString()
        );
    }

    @Test
    @DisplayName("LOW strategy only registers the detection in the audit log")
    void lowOnlyRegisters() {
        lowStrategy.execute(alert(Severity.LOW));

        verify(auditLogService, times(1)).log(
            eq("LOW_ALERT_REGISTERED"), eq("Alert"), eq("alert-001"),
            eq("agent-prod-01"), isNull(), anyString()
        );
    }

    @Test
    @DisplayName("Strategies implement AlertStrategy interface")
    void strategiesImplementInterface() {
        org.assertj.core.api.Assertions.assertThat(criticalStrategy).isInstanceOf(AlertStrategy.class);
        org.assertj.core.api.Assertions.assertThat(mediumStrategy).isInstanceOf(AlertStrategy.class);
        org.assertj.core.api.Assertions.assertThat(lowStrategy).isInstanceOf(AlertStrategy.class);
    }
}
