package br.edu.sentinela.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * Envelope criptografado enviado pelo agente Node.js para POST /alerts.
 * data = payload RSA-OAEP cifrado em Base64; signature = HMAC-SHA256 em hex;
 * checksum = SHA-256 em hex, usado na deduplicação antes de decriptar.
 */
@Data
public class AlertEnvelopeRequest {

    @NotBlank(message = "data is required")
    private String data;

    @NotBlank(message = "signature is required")
    private String signature;

    @NotBlank(message = "checksum is required")
    private String checksum;

    @JsonProperty("agent_id")
    @NotBlank(message = "agent_id is required")
    private String agentId;

    @NotBlank(message = "severity is required")
    private String severity;

    @JsonProperty("event_time")
    @NotBlank(message = "event_time is required")
    private String eventTime;

    @JsonProperty("rule_id")
    @NotBlank(message = "rule_id is required")
    private String ruleId;

    @JsonProperty("file_path")
    @NotBlank(message = "file_path is required")
    private String filePath;
}
