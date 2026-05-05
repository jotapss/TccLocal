package br.edu.sentinela.service.chain;

import br.edu.sentinela.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Verifica o checksum SHA-256 no banco antes de prosseguir.
 * Se já existir, marca o contexto como duplicata e interrompe a cadeia.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class DeduplicationHandler implements AlertHandler {

    private final AlertRepository alertRepository;

    private AlertHandler next;

    @Override
    public AlertHandler setNext(AlertHandler next) {
        this.next = next;
        return next;
    }

    @Override
    public AlertContext handle(AlertContext context) {
        String checksum = context.getEnvelope().getChecksum();

        alertRepository.findByChecksum(checksum).ifPresent(existing -> {
            log.debug("Duplicate alert detected for checksum prefix {}...", checksum.substring(0, 8));
            context.setDuplicate(true);
            context.setExistingAlertId(existing.getId());
        });

        if (context.isDuplicate()) {
            // duplicata detectada — interrompe a cadeia aqui
            return context;
        }

        return next != null ? next.handle(context) : context;
    }
}
