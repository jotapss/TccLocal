package br.edu.sentinela.repository;

import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface AlertRepository extends JpaRepository<Alert, String> {

    Optional<Alert> findByChecksum(String checksum);

    boolean existsByChecksum(String checksum);

    @Query("SELECT a FROM Alert a WHERE " +
        "(:severity IS NULL OR a.severity = :severity) AND " +
        "(:status IS NULL OR a.status = :status) AND " +
        "(:agentId IS NULL OR a.agentId = :agentId) AND " +
        "(:from IS NULL OR a.eventTime >= :from) AND " +
        "(:to IS NULL OR a.eventTime <= :to)")
    Page<Alert> findByFilters(
        @Param("severity") Severity severity,
        @Param("status") AlertStatus status,
        @Param("agentId") String agentId,
        @Param("from") Instant from,
        @Param("to") Instant to,
        Pageable pageable
    );

    long countBySeverity(Severity severity);

    long countByStatus(AlertStatus status);

    @Query("SELECT COUNT(a) FROM Alert a WHERE a.createdAt >= :since")
    long countSince(@Param("since") Instant since);

    @Query(value = "SELECT AVG(EXTRACT(EPOCH FROM (created_at - event_time)) * 1000) " +
        "FROM alerts WHERE created_at >= :since", nativeQuery = true)
    Double avgDetectionLatencyMs(@Param("since") Instant since);
}
