package br.edu.sentinela.dto.response;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertResponse {
    private String id;
    private String agentId;
    private Severity severity;
    private AlertStatus status;
    private String ruleId;
    private String filePath;
    private String secretPreview;
    private Integer lineNumber;
    private Instant eventTime;
    private Instant createdAt;
    private String resolutionNote;
    private Instant resolvedAt;
    private String resolvedBy;

    public static AlertResponse from(Alert alert) {
        return AlertResponse.builder()
            .id(alert.getId())
            .agentId(alert.getAgentId())
            .severity(alert.getSeverity())
            .status(alert.getStatus())
            .ruleId(alert.getRuleId())
            .filePath(alert.getFilePath())
            .secretPreview(alert.getSecretPreview())
            .lineNumber(alert.getLineNumber())
            .eventTime(alert.getEventTime())
            .createdAt(alert.getCreatedAt())
            .resolutionNote(alert.getResolutionNote())
            .resolvedAt(alert.getResolvedAt())
            .resolvedBy(alert.getResolvedBy())
            .build();
    }
}
