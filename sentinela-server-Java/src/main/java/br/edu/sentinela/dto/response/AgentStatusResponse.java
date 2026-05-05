package br.edu.sentinela.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AgentStatusResponse {
    private String agentId;
    private String name;
    private Boolean active;
    private Instant lastSeen;
    private Double cpuUsagePct;
    private Integer bufferPending;
    private String environment;
}
