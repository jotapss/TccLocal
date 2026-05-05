package br.edu.sentinela.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;

@Entity
@Table(name = "alerts", indexes = {
    @Index(name = "idx_alert_checksum", columnList = "checksum", unique = true),
    @Index(name = "idx_alert_severity", columnList = "severity"),
    @Index(name = "idx_alert_agent_id", columnList = "agent_id"),
    @Index(name = "idx_alert_event_time", columnList = "event_time")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "agent_id", nullable = false)
    private String agentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private AlertStatus status = AlertStatus.OPEN;

    @Column(name = "rule_id", nullable = false)
    private String ruleId;

    @Column(name = "file_path", nullable = false)
    private String filePath;

    /** Sempre contém valor mascarado (ex: AKIA*****LE). O segredo real jamais é armazenado. */
    @Column(name = "secret_preview", nullable = false)
    private String secretPreview;

    @Column(name = "line_number")
    private Integer lineNumber;

    /** SHA-256 do payload original em texto claro — usado para deduplicação antes da decriptação. */
    @Column(nullable = false, unique = true)
    private String checksum;

    @Column(name = "event_time", nullable = false)
    private Instant eventTime;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "resolution_note")
    private String resolutionNote;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "resolved_by")
    private String resolvedBy;
}
