package br.edu.sentinela.exception;

public class AlertValidationException extends RuntimeException {
    public AlertValidationException(String message) {
        super(message);
    }
}
