package br.edu.sentinela.service;

import br.edu.sentinela.dto.request.AgentRegisterRequest;
import br.edu.sentinela.dto.response.AgentRegisterResponse;
import br.edu.sentinela.dto.response.AgentStatusResponse;
import br.edu.sentinela.model.Agent;
import br.edu.sentinela.model.Environment;
import br.edu.sentinela.repository.AgentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AgentService {

    private final AgentRepository agentRepository;
    private final PublicKey       rsaPublicKey;

    @Transactional
    public AgentRegisterResponse register(AgentRegisterRequest request) {
        String agentId    = "agent-" + UUID.randomUUID().toString().substring(0, 8);
        String agentToken = UUID.randomUUID().toString();
        String tokenHash  = sha256Hex(agentToken);

        Environment env;
        try {
            env = Environment.valueOf(request.getEnvironment().toUpperCase());
        } catch (IllegalArgumentException e) {
            env = Environment.PRODUCTION;
        }

        Agent agent = Agent.builder()
            .agentId(agentId)
            .name(request.getName())
            .tokenHash(tokenHash)
            .environment(env)
            .active(true)
            .build();

        agentRepository.save(agent);
        log.info("Registered new agent: {}", agentId);

        // chave pública do servidor para que o agente cifre os payloads
        String publicKeyPem = exportPublicKeyPem(rsaPublicKey);

        return AgentRegisterResponse.builder()
            .agentId(agentId)
            .agentToken(agentToken)   // exibido uma única vez — nunca armazenado em texto claro
            .publicKey(publicKeyPem)
            .build();
    }

    public AgentStatusResponse getStatus(String agentId) {
        Agent agent = agentRepository.findByAgentId(agentId)
            .orElseThrow(() -> new jakarta.persistence.EntityNotFoundException("Agent not found: " + agentId));
        return AgentStatusResponse.builder()
            .agentId(agent.getAgentId())
            .name(agent.getName())
            .active(agent.getActive())
            .lastSeen(agent.getLastSeen())
            .cpuUsagePct(agent.getCpuUsagePct())
            .bufferPending(agent.getBufferPending())
            .environment(agent.getEnvironment().name())
            .build();
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String exportPublicKeyPem(PublicKey key) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
    }
}
