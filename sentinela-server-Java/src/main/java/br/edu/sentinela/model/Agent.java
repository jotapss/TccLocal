package br.edu.sentinela.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Entity
@Table(name = "agents", indexes = {
    @Index(name = "idx_agent_agent_id", columnList = "agent_id", unique = true),
    @Index(name = "idx_agent_token_hash", columnList = "token_hash", unique = true)
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "agent_id", nullable = false, unique = true)
    private String agentId;

    @Column(nullable = false)
    private String name;

    /** Hash SHA-256 do token do agente. O token em texto claro jamais é armazenado. */
    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    /** Chave pública RSA-4096 em formato PEM. */
    @Column(name = "public_key", columnDefinition = "TEXT")
    private String publicKey;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private Environment environment = Environment.PRODUCTION;

    @Column(name = "last_seen")
    private Instant lastSeen;

    @Column(name = "cpu_usage_pct")
    private Double cpuUsagePct;

    @Column(name = "buffer_pending")
    @Builder.Default
    private Integer bufferPending = 0;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
