package br.edu.sentinela.security;

import org.springframework.stereotype.Service;

import java.util.regex.Pattern;

/**
 * Garante que segredos saem sempre mascarados antes de serem persistidos ou logados.
 * Um valor mascarado precisa conter ao menos 3 asteriscos consecutivos.
 */
@Service
public class DataMaskingService {

    private static final Pattern MASKED_PATTERN = Pattern.compile(".*\\*{3,}.*");

    // padrões de credenciais conhecidos para detectar valores não mascarados
    private static final Pattern AWS_ACCESS_KEY = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern AWS_SECRET_KEY = Pattern.compile("[0-9a-zA-Z/+]{40}");
    private static final Pattern GITHUB_TOKEN   = Pattern.compile("ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}");
    private static final Pattern GENERIC_SECRET = Pattern.compile("(?i)(password|secret|token|key)\\s*[=:]\\s*\\S+");

    /** Retorna o valor mascarado. Se já estiver mascarado, devolve sem alteração. */
    public String ensureMasked(String secretPreview) {
        if (secretPreview == null || secretPreview.isBlank()) {
            return "[REDACTED]";
        }
        if (isMasked(secretPreview)) {
            return secretPreview;
        }
        if (AWS_ACCESS_KEY.matcher(secretPreview).matches()) {
            return maskValue(secretPreview);
        }
        if (GITHUB_TOKEN.matcher(secretPreview).find()) {
            return maskValue(secretPreview);
        }
        if (GENERIC_SECRET.matcher(secretPreview).find()) {
            return maskValue(secretPreview);
        }
        // não é um padrão reconhecido mas também não está mascarado — mascara por precaução
        if (secretPreview.length() > 8) {
            return maskValue(secretPreview);
        }
        return secretPreview;
    }

    public boolean isMasked(String value) {
        return value != null && MASKED_PATTERN.matcher(value).matches();
    }

    public String maskValue(String value) {
        if (value == null) return "[REDACTED]";
        int len = value.length();
        if (len <= 6) return "*".repeat(len);
        int keepStart = Math.min(4, len / 4);
        int keepEnd   = Math.min(2, len / 4);
        String stars  = "*".repeat(Math.max(3, len - keepStart - keepEnd));
        return value.substring(0, keepStart) + stars + value.substring(len - keepEnd);
    }
}
