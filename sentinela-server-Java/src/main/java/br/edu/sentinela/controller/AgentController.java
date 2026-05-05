package br.edu.sentinela.controller;

import br.edu.sentinela.dto.request.AgentRegisterRequest;
import br.edu.sentinela.dto.response.AgentRegisterResponse;
import br.edu.sentinela.dto.response.AgentStatusResponse;
import br.edu.sentinela.service.AgentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/agents")
@RequiredArgsConstructor
public class AgentController {

    private final AgentService agentService;

    /**
     * POST /api/v1/agents/register
     * Registra um novo agente. O agent_token é retornado uma única vez e não pode ser recuperado depois.
     */
    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AgentRegisterResponse> register(@Valid @RequestBody AgentRegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(agentService.register(request));
    }

    /**
     * GET /api/v1/agents/{id}/status
     * Retorna métricas de saúde de um agente específico.
     */
    @GetMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<AgentStatusResponse> getStatus(@PathVariable String id) {
        return ResponseEntity.ok(agentService.getStatus(id));
    }
}
