package br.edu.sentinela.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AgentAuthRequest {

    @NotBlank(message = "agent_token is required")
    @JsonProperty("agent_token")
    private String agentToken;

    @NotBlank(message = "agent_id is required")
    @JsonProperty("agent_id")
    private String agentId;

    @NotBlank(message = "timestamp is required")
    private String timestamp;
}
