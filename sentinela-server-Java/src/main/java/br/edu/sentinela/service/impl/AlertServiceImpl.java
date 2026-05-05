package br.edu.sentinela.service.impl;

import br.edu.sentinela.dto.request.AlertEnvelopeRequest;
import br.edu.sentinela.dto.request.AlertUpdateRequest;
import br.edu.sentinela.dto.response.AlertResponse;
import br.edu.sentinela.dto.response.PagedResponse;
import br.edu.sentinela.exception.AlertValidationException;
import br.edu.sentinela.exception.DuplicateAlertException;
import br.edu.sentinela.model.Alert;
import br.edu.sentinela.model.AlertStatus;
import br.edu.sentinela.model.Severity;
import br.edu.sentinela.repository.AlertRepository;
import br.edu.sentinela.security.DataMaskingService;
import br.edu.sentinela.security.HmacValidationService;
import br.edu.sentinela.security.RsaDecryptionService;
import br.edu.sentinela.service.AuditLogService;
import br.edu.sentinela.service.chain.AlertContext;
import br.edu.sentinela.service.chain.DeduplicationHandler;
import br.edu.sentinela.service.chain.SanitizationHandler;
import br.edu.sentinela.service.chain.ValidationHandler;
import br.edu.sentinela.service.factory.AlertFactory;
import br.edu.sentinela.service.strategy.AlertStrategy;
import br.edu.sentinela.service.strategy.CriticalAlertStrategy;
import br.edu.sentinela.service.strategy.LowAlertStrategy;
import br.edu.sentinela.service.strategy.MediumAlertStrategy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

/**
 * Orquestra o pipeline de processamento de alertas:
 * Chain → HMAC → Decrypt → Mask → Factory → Strategy → Persist → Audit
 */
@Service
@Slf4j
public class AlertServiceImpl {

    private final AlertRepository      alertRepository;
    private final RsaDecryptionService rsaDecryptionService;
    private final HmacValidationService hmacValidationService;
    private final DataMaskingService   dataMaskingService;
    private final AlertFactory         alertFactory;
    private final AuditLogService      auditLogService;
    private final ObjectMapper         objectMapper;

    private final ValidationHandler     validationHandler;
    private final SanitizationHandler   sanitizationHandler;
    private final DeduplicationHandler  deduplicationHandler;

    private final CriticalAlertStrategy criticalStrategy;
    private final MediumAlertStrategy   mediumStrategy;
    private final LowAlertStrategy      lowStrategy;

    public AlertServiceImpl(
            AlertRepository alertRepository,
            RsaDecryptionService rsaDecryptionService,
            HmacValidationService hmacValidationService,
            DataMaskingService dataMaskingService,
            AlertFactory alertFactory,
            AuditLogService auditLogService,
            ObjectMapper objectMapper,
            ValidationHandler validationHandler,
            SanitizationHandler sanitizationHandler,
            DeduplicationHandler deduplicationHandler,
            CriticalAlertStrategy criticalStrategy,
            MediumAlertStrategy mediumStrategy,
            LowAlertStrategy lowStrategy) {

        this.alertRepository      = alertRepository;
        this.rsaDecryptionService  = rsaDecryptionService;
        this.hmacValidationService = hmacValidationService;
        this.dataMaskingService    = dataMaskingService;
        this.alertFactory          = alertFactory;
        this.auditLogService       = auditLogService;
        this.objectMapper          = objectMapper;
        this.validationHandler     = validationHandler;
        this.sanitizationHandler   = sanitizationHandler;
        this.deduplicationHandler  = deduplicationHandler;
        this.criticalStrategy      = criticalStrategy;
        this.mediumStrategy        = mediumStrategy;
        this.lowStrategy           = lowStrategy;

        // monta a cadeia: Validação → Sanitização → Deduplicação
        this.validationHandler.setNext(sanitizationHandler).setNext(deduplicationHandler);
    }

    @Transactional
    public AlertResponse processAlert(AlertEnvelopeRequest envelope) {
        AlertContext context = new AlertContext(envelope);
        validationHandler.handle(context);

        if (context.isDuplicate()) {
            log.debug("Duplicate alert ignored, existing id={}", context.getExistingAlertId());
            throw new DuplicateAlertException(context.getExistingAlertId());
        }

        String decryptedJson = rsaDecryptionService.decrypt(envelope.getData());

        // HMAC é validado sobre o plaintext — por isso ocorre APÓS a decriptação RSA
        hmacValidationService.validate(decryptedJson, envelope.getSignature());

        String maskedPreview = extractAndMaskPreview(decryptedJson);
        Alert alert = alertFactory.create(decryptedJson, context, maskedPreview);

        AlertStrategy strategy = resolveStrategy(alert.getSeverity());
        strategy.execute(alert);

        Alert saved = alertRepository.save(alert);
        log.info("Alert persisted id={} severity={} agent={}", saved.getId(), saved.getSeverity(), saved.getAgentId());

        auditLogService.log(
            "ALERT_CREATED",
            "Alert",
            saved.getId(),
            saved.getAgentId(),
            null,
            "Alert created with severity " + saved.getSeverity() + " for rule " + saved.getRuleId()
        );

        return AlertResponse.from(saved);
    }

    public PagedResponse<AlertResponse> listAlerts(
            Severity severity, AlertStatus status, String agentId,
            Instant from, Instant to, int page, int size) {
        Page<Alert> alerts = alertRepository.findByFilters(
            severity, status, agentId, from, to,
            PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"))
        );
        return PagedResponse.from(alerts.map(AlertResponse::from));
    }

    @Transactional
    public AlertResponse updateAlert(String id, AlertUpdateRequest request) {
        Alert alert = alertRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException("Alert not found: " + id));

        AlertStatus newStatus = AlertStatus.valueOf(request.getStatus());
        if (newStatus == AlertStatus.OPEN) {
            throw new AlertValidationException("Cannot set status back to OPEN");
        }

        alert.setStatus(newStatus);
        alert.setResolutionNote(request.getResolutionNote());
        alert.setResolvedAt(Instant.now());

        String principal = SecurityContextHolder.getContext().getAuthentication().getName();
        alert.setResolvedBy(principal);

        Alert saved = alertRepository.save(alert);

        auditLogService.log(
            "ALERT_UPDATED",
            "Alert",
            saved.getId(),
            saved.getAgentId(),
            principal,
            "Status changed to " + newStatus + " by " + principal
        );

        return AlertResponse.from(saved);
    }

    private String extractAndMaskPreview(String decryptedJson) {
        try {
            JsonNode node = objectMapper.readTree(decryptedJson);
            String preview = node.has("secret_preview") ? node.get("secret_preview").asText() : "[REDACTED]";
            return dataMaskingService.ensureMasked(preview);
        } catch (Exception e) {
            log.warn("Could not parse secret_preview from payload, using default mask");
            return "[REDACTED]";
        }
    }

    private AlertStrategy resolveStrategy(Severity severity) {
        return switch (severity) {
            case CRITICAL -> criticalStrategy;
            case MEDIUM   -> mediumStrategy;
            case LOW      -> lowStrategy;
        };
    }
}
