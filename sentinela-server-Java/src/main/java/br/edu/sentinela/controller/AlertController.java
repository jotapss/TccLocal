package br.edu.sentinela.controller;

import br.edu.sentinela.dto.request.AlertEnvelopeRequest;
import br.edu.sentinela.dto.request.AlertUpdateRequest;
import br.edu.sentinela.dto.response.AlertResponse;
import br.edu.sentinela.dto.response.PagedResponse;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.service.impl.AlertServiceImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/api/v1/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertServiceImpl alertService;

    /**
     * POST /api/v1/alerts
     * Recebe o envelope criptografado do agente Node.js e executa o pipeline completo de processamento.
     */
    @PostMapping
    public ResponseEntity<AlertResponse> receiveAlert(@Valid @RequestBody AlertEnvelopeRequest envelope) {
        AlertResponse response = alertService.processAlert(envelope);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * GET /api/v1/alerts
     * Lista alertas com filtros opcionais por severidade, status, agente e intervalo de tempo.
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<PagedResponse<AlertResponse>> listAlerts(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) AlertStatus status,
            @RequestParam(required = false) String agentId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        return ResponseEntity.ok(alertService.listAlerts(severity, status, agentId, from, to, page, size));
    }

    /**
     * PUT /api/v1/alerts/{id}
     * Atualiza o status de um alerta para RESOLVED ou IGNORED.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<AlertResponse> updateAlert(
            @PathVariable String id,
            @Valid @RequestBody AlertUpdateRequest request) {
        return ResponseEntity.ok(alertService.updateAlert(id, request));
    }
}
