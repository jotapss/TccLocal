package br.edu.sentinela.service.chain;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Remove padrões perigosos dos campos de texto do envelope para prevenir XSS e SQL injection.
 */
@Component
@Slf4j
public class SanitizationHandler implements AlertHandler {

    // casa <script...>...</script> e tags self-closing
    private static final Pattern SCRIPT_TAG     = Pattern.compile("<script[^>]*>.*?</script>",
        Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    // sequências de comentário SQL e injeção
    private static final Pattern SQL_COMMENT     = Pattern.compile("(-{2}|;\\s*-{2}|/\\*.*?\\*/)",
        Pattern.DOTALL);
    // bytes nulos e chars de controle (exceto tab, newline e CR)
    private static final Pattern CONTROL_CHARS   = Pattern.compile("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]");
    // Unicode perigoso: direction override, zero-width, BIDI
    private static final Pattern UNICODE_DANGER  = Pattern.compile(
        "[\\u200B-\\u200F\\u2028\\u2029\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]");
    // chars HTML usados em XSS armazenado
    private static final Pattern HTML_SPECIAL    = Pattern.compile("[<>\"']");

    private AlertHandler next;

    @Override
    public AlertHandler setNext(AlertHandler next) {
        this.next = next;
        return next;
    }

    @Override
    public AlertContext handle(AlertContext context) {
        context.setSanitizedFilePath(sanitize(context.getEnvelope().getFilePath()));
        context.setSanitizedRuleId(sanitize(context.getEnvelope().getRuleId()));
        context.setSanitizedAgentId(sanitize(context.getEnvelope().getAgentId()));

        log.debug("Sanitization applied to envelope fields");

        return next != null ? next.handle(context) : context;
    }

    private String sanitize(String input) {
        if (input == null) return null;
        String result = input;
        result = SCRIPT_TAG.matcher(result).replaceAll("");
        result = SQL_COMMENT.matcher(result).replaceAll("");
        result = CONTROL_CHARS.matcher(result).replaceAll("");
        result = UNICODE_DANGER.matcher(result).replaceAll("");
        result = HTML_SPECIAL.matcher(result).replaceAll("");
        return result.trim();
    }
}
