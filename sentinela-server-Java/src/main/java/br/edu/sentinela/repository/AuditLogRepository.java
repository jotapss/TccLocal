package br.edu.sentinela.repository;

import br.edu.sentinela.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;

import java.util.Optional;

/**
 * Repositório somente-leitura e inserção para AuditLog.
 * Estende Repository (não JpaRepository) para não expor deleteById, deleteAll e variantes.
 * O @Immutable na entidade reforça isso no nível do Hibernate.
 */
public interface AuditLogRepository extends Repository<AuditLog, String> {

    <S extends AuditLog> S save(S entity);

    Optional<AuditLog> findById(String id);

    Page<AuditLog> findAll(Pageable pageable);
}
