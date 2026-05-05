package br.edu.sentinela.logging;

import ch.qos.logback.classic.pattern.ClassicConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

import java.util.regex.Pattern;

/**
 * Conversor Logback que mascara dados sensíveis antes de gravar no log.
 * Bearer tokens, chaves AWS, tokens GitHub e conteúdo PEM nunca aparecem em texto claro.
 */
public class MaskingConverter extends ClassicConverter {

    private static final Pattern BEARER_TOKEN =
        Pattern.compile("(Bearer\\s+)[A-Za-z0-9\\-._~+/]+=*", Pattern.CASE_INSENSITIVE);

    private static final Pattern AWS_ACCESS_KEY =
        Pattern.compile("AKIA[0-9A-Z]{16}");

    private static final Pattern AWS_SECRET_KEY =
        Pattern.compile("(?i)(aws_secret|secret_key)[\\s:=]+[\"']?([0-9a-zA-Z/+]{40})[\"']?");

    private static final Pattern GITHUB_TOKEN =
        Pattern.compile("(ghp_|github_pat_)[0-9a-zA-Z_]{10,}");

    private static final Pattern PEM_CONTENT =
        Pattern.compile("-----BEGIN[\\w\\s]+-----[A-Za-z0-9+/=\\n\\r]+-----END[\\w\\s]+-----",
            Pattern.DOTALL);

    private static final Pattern GENERIC_PASSWORD =
        Pattern.compile("(?i)(password|passwd|pwd|secret|token|api_key)[\\s:=]+[\"']?([^\\s\"'&]{6,})[\"']?");

    @Override
    public String convert(ILoggingEvent event) {
        String message = event.getFormattedMessage();
        if (message == null) return "";

        message = BEARER_TOKEN.matcher(message).replaceAll("$1[REDACTED]");
        message = AWS_ACCESS_KEY.matcher(message).replaceAll("AKIA***[REDACTED]");
        message = AWS_SECRET_KEY.matcher(message).replaceAll("$1=[REDACTED]");
        message = GITHUB_TOKEN.matcher(message).replaceAll("[REDACTED]");
        message = PEM_CONTENT.matcher(message).replaceAll("[PEM-KEY-REDACTED]");
        message = GENERIC_PASSWORD.matcher(message).replaceAll("$1=[REDACTED]");

        return message;
    }
}
