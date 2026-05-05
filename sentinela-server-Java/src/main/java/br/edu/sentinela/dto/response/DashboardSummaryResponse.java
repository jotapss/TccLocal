package br.edu.sentinela.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DashboardSummaryResponse {
    private long alertsTotal;
    private Map<String, Long> bySeverity;
    private long agentsOnline;
    private Double avgDetectionMs;
    private Double falsePositivePct;
    private long openAlerts;
    private long resolvedAlerts;
}
