package br.edu.sentinela.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class AlertUpdateRequest {

    @NotBlank(message = "status is required")
    @Pattern(regexp = "RESOLVED|IGNORED", message = "status must be RESOLVED or IGNORED")
    private String status;

    private String resolutionNote;
}
