package br.edu.sentinela.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AgentRegisterResponse {
    private String agentId;
    /** The plaintext agent token — shown ONCE at registration and never stored in plaintext. */
    private String agentToken;
    private String publicKey;
}
