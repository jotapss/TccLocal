package br.edu.sentinela.controller;

import br.edu.sentinela.config.TestCryptoConfig;
import br.edu.sentinela.model.Agent;
import br.edu.sentinela.model.Environment;
import br.edu.sentinela.repository.AgentRepository;
import br.edu.sentinela.security.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.PSource;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestCryptoConfig.class)
@DisplayName("AlertController Integration Tests")
class AlertControllerIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private AgentRepository agentRepository;
    @Autowired private JwtService jwtService;

    private static final String HMAC_SECRET = "test-hmac-secret-64-bytes-minimo-para-testes-unitarios-1234567890abcdef";
    private static final String AGENT_ID    = "agent-test-integ";
    private static final String AGENT_TOKEN = "integration-test-token-" + System.currentTimeMillis();

    private String agentJwt;
    private String tokenHash;

    @BeforeEach
    void setUp() throws Exception {
        // o filter compara pelo hash, nunca pelo token em texto claro
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        tokenHash = HexFormat.of().formatHex(digest.digest(AGENT_TOKEN.getBytes(StandardCharsets.UTF_8)));

        // idempotente: não recria o agente se o teste já rodou antes
        if (agentRepository.findByAgentId(AGENT_ID).isEmpty()) {
            Agent agent = Agent.builder()
                .agentId(AGENT_ID)
                .name("Integration Test Agent")
                .tokenHash(tokenHash)
                .environment(Environment.DEVELOPMENT)
                .active(true)
                .build();
            agentRepository.save(agent);
        }

        agentJwt = jwtService.generateAccessToken(AGENT_ID, "AGENT", Map.of("role", "AGENT"));
    }

    @Test
    @DisplayName("POST /alerts returns 201 with valid encrypted envelope")
    void postAlertReturns201() throws Exception {
        String envelope = buildValidEnvelope();

        mockMvc.perform(post("/api/v1/alerts")
                .header("Authorization", "Bearer " + agentJwt)
                .header("X-Agent-Token", AGENT_TOKEN)
                .header("X-Request-ID", "req-" + System.currentTimeMillis())
                .contentType(MediaType.APPLICATION_JSON)
                .content(envelope))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").isNotEmpty())
            .andExpect(jsonPath("$.severity").value("CRITICAL"))
            .andExpect(jsonPath("$.status").value("OPEN"));
    }

    @Test
    @DisplayName("POST /alerts returns 200 on duplicate checksum (idempotent)")
    void postAlertReturnsDuplicateGracefully() throws Exception {
        String envelope = buildValidEnvelope(makeChecksum("fixed-payload-for-dup-test"));

        // primeira requisição — deve persistir
        mockMvc.perform(post("/api/v1/alerts")
                .header("Authorization", "Bearer " + agentJwt)
                .header("X-Agent-Token", AGENT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(envelope))
            .andExpect(status().isCreated());

        // mesma requisição — deve retornar 200 sem duplicar
        mockMvc.perform(post("/api/v1/alerts")
                .header("Authorization", "Bearer " + agentJwt)
                .header("X-Agent-Token", AGENT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(envelope))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /alerts returns 401 when Authorization header is missing")
    void postAlertReturns401WithoutJwt() throws Exception {
        mockMvc.perform(post("/api/v1/alerts")
                .header("X-Agent-Token", AGENT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /alerts returns 400 when required fields are missing")
    void postAlertReturns400WhenFieldsMissing() throws Exception {
        mockMvc.perform(post("/api/v1/alerts")
                .header("Authorization", "Bearer " + agentJwt)
                .header("X-Agent-Token", AGENT_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"severity\":\"CRITICAL\"}"))
            .andExpect(status().isBadRequest());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String buildValidEnvelope() throws Exception {
        String payload = buildPayload();
        return buildValidEnvelope(makeChecksum(payload), payload);
    }

    private String buildValidEnvelope(String checksum) throws Exception {
        String payload = "{\"type\":\"SECRET_EXPOSED\",\"severity\":\"CRITICAL\",\"agent_id\":\"" + AGENT_ID +
            "\",\"event_time\":\"" + Instant.now() + "\",\"file_path\":\"/app/.env\",\"secret_preview\":\"AKIA*****LE\"" +
            ",\"rule_id\":\"AWS_ACCESS_KEY_001\",\"line\":42}";
        return buildValidEnvelope(checksum, payload);
    }

    private String buildValidEnvelope(String checksum, String payload) throws Exception {
        String encrypted = encryptRsa(payload);
        String signature = hmacSha256Hex(payload);
        String eventTime = Instant.now().toString();

        Map<String, String> envelope = Map.of(
            "data",       encrypted,
            "signature",  signature,
            "checksum",   checksum,
            "agent_id",   AGENT_ID,
            "severity",   "CRITICAL",
            "event_time", eventTime,
            "rule_id",    "AWS_ACCESS_KEY_001",
            "file_path",  "/app/.env"
        );
        return objectMapper.writeValueAsString(envelope);
    }

    private String buildPayload() {
        return "{\"type\":\"SECRET_EXPOSED\",\"severity\":\"CRITICAL\",\"agent_id\":\"" + AGENT_ID +
            "\",\"event_time\":\"" + Instant.now() + "\",\"file_path\":\"/app/.env\"" +
            ",\"secret_preview\":\"AKIA*****LE\",\"rule_id\":\"AWS_ACCESS_KEY_001\",\"line\":42}";
    }

    private String encryptRsa(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec params = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, TestCryptoConfig.getKeyPair().getPublic(), params);
        return Base64.getEncoder().encodeToString(
            cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
    }

    private String hmacSha256Hex(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(HMAC_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private String makeChecksum(String data) throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8)));
    }
}
