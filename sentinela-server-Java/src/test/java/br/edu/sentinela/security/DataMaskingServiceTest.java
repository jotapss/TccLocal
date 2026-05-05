package br.edu.sentinela.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("DataMaskingService")
class DataMaskingServiceTest {

    private DataMaskingService service;

    @BeforeEach
    void setUp() {
        service = new DataMaskingService();
    }

    @Test
    @DisplayName("Masks an AWS access key")
    void masksAwsAccessKey() {
        String awsKey = "AKIAIOSFODNN7EXAMPLE";
        String result = service.ensureMasked(awsKey);
        assertThat(result).contains("***");
        assertThat(result).doesNotContain("AKIAIOSFODNN7EXAMPLE");
    }

    @Test
    @DisplayName("Masks a GitHub personal access token")
    void masksGitHubToken() {
        String token = "ghp_abcdefghijklmnopqrstuvwxyz012345678";
        String result = service.ensureMasked(token);
        assertThat(result).contains("***");
        assertThat(result).doesNotContain("ghp_abcdefghijklmnopqrstuvwxyz012345678");
    }

    @Test
    @DisplayName("Masks a generic password string")
    void masksGenericPassword() {
        String secret = "mySuperSecretPassword123!";
        String result = service.ensureMasked(secret);
        assertThat(result).contains("***");
    }

    @Test
    @DisplayName("Returns value unchanged if already masked (contains asterisks)")
    void returnsAlreadyMaskedValue() {
        String masked = "AKIA*****LE";
        String result = service.ensureMasked(masked);
        assertThat(result).isEqualTo(masked);
    }

    @Test
    @DisplayName("Returns [REDACTED] for null input")
    void handlesNullInput() {
        String result = service.ensureMasked(null);
        assertThat(result).isEqualTo("[REDACTED]");
    }

    @Test
    @DisplayName("Returns [REDACTED] for blank input")
    void handlesBlankInput() {
        String result = service.ensureMasked("   ");
        assertThat(result).isEqualTo("[REDACTED]");
    }

    @Test
    @DisplayName("isMasked returns true for asterisk-containing value")
    void isMaskedTrue() {
        assertThat(service.isMasked("AKIA*****LE")).isTrue();
    }

    @Test
    @DisplayName("isMasked returns false for plain value")
    void isMaskedFalse() {
        assertThat(service.isMasked("AKIAIOSFODNN7EXAMPLE")).isFalse();
    }
}
