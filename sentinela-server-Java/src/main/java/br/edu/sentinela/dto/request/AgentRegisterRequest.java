package br.edu.sentinela.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class AgentRegisterRequest {

    @NotBlank(message = "name is required")
    private String name;

    @NotBlank(message = "environment is required")
    private String environment;
}
