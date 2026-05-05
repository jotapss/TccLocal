package br.edu.sentinela.repository;

import br.edu.sentinela.model.Agent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AgentRepository extends JpaRepository<Agent, String> {

    Optional<Agent> findByAgentId(String agentId);

    Optional<Agent> findByTokenHash(String tokenHash);

    boolean existsByAgentId(String agentId);

    long countByActive(boolean active);
}
