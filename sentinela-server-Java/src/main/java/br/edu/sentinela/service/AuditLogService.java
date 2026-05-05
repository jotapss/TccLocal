package br.edu.sentinela.service;

import br.edu.sentinela.model.AuditLog;
import br.edu.sentinela.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Serviço de inserção exclusiva no log de auditoria imutável.
 * Cada operação roda em transação própria (REQUIRES_NEW) para garantir
 * que o registro persista mesmo se a transação chamadora for revertida.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    // REQUIRES_NEW: se o chamador fizer rollback, o log de auditoria já foi persistido
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public AuditLog log(String action, String entityType, String entityId,
                        String agentId, String userId, String details) {
        AuditLog entry = AuditLog.builder()
            .action(action)
            .entityType(entityType)
            .entityId(entityId)
            .agentId(agentId)
            .userId(userId)
            .details(details)
            .build();
        return auditLogRepository.save(entry);
    }
}
