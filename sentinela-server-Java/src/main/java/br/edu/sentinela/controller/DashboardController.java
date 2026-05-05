package br.edu.sentinela.controller;

import br.edu.sentinela.dto.response.DashboardSummaryResponse;
import br.edu.sentinela.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final DashboardService dashboardService;

    /**
     * GET /api/v1/dashboard/summary
     * Retorna métricas agregadas: total de alertas, por severidade, latência média e % de falsos positivos.
     */
    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<DashboardSummaryResponse> getSummary() {
        return ResponseEntity.ok(dashboardService.getSummary());
    }

    /**
     * GET /api/v1/dashboard/timeline
     * Retorna o total de alertas nas últimas 24 horas como resumo de timeline.
     */
    @GetMapping("/timeline")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<DashboardSummaryResponse> getTimeline() {
        // para este escopo, timeline retorna os mesmos dados do summary.
        // uma série temporal real precisaria de GROUP BY time-bucket em SQL nativo.
        return ResponseEntity.ok(dashboardService.getSummary());
    }
}
