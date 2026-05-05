package br.edu.sentinela.service;

import br.edu.sentinela.dto.response.DashboardSummaryResponse;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.repository.AgentRepository;
import br.edu.sentinela.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class DashboardService {

    private final AlertRepository alertRepository;
    private final AgentRepository agentRepository;

    public DashboardSummaryResponse getSummary() {
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);

        long total        = alertRepository.count();
        long critical     = alertRepository.countBySeverity(Severity.CRITICAL);
        long medium       = alertRepository.countBySeverity(Severity.MEDIUM);
        long low          = alertRepository.countBySeverity(Severity.LOW);
        long open         = alertRepository.countByStatus(AlertStatus.OPEN);
        long resolved     = alertRepository.countByStatus(AlertStatus.RESOLVED);
        long ignored      = alertRepository.countByStatus(AlertStatus.IGNORED);
        long agentsOnline = agentRepository.countByActive(true);

        Double avgMs = alertRepository.avgDetectionLatencyMs(since);

        // falso positivo % = (IGNORED / total) * 100
        double falsePositivePct = total > 0 ? ((double) ignored / total) * 100.0 : 0.0;

        return DashboardSummaryResponse.builder()
            .alertsTotal(total)
            .bySeverity(Map.of(
                "CRITICAL", critical,
                "MEDIUM",   medium,
                "LOW",      low
            ))
            .agentsOnline(agentsOnline)
            .avgDetectionMs(avgMs)
            .falsePositivePct(falsePositivePct)
            .openAlerts(open)
            .resolvedAlerts(resolved)
            .build();
    }
}
