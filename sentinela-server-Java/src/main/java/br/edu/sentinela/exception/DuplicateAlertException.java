package br.edu.sentinela.exception;

public class DuplicateAlertException extends RuntimeException {
    private final String existingAlertId;

    public DuplicateAlertException(String existingAlertId) {
        super("Duplicate alert detected for checksum. Existing alert: " + existingAlertId);
        this.existingAlertId = existingAlertId;
    }

    public String getExistingAlertId() {
        return existingAlertId;
    }
}
