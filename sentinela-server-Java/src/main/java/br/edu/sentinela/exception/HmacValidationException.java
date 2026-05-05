package br.edu.sentinela.exception;

public class HmacValidationException extends RuntimeException {
    public HmacValidationException(String message) {
        super(message);
    }
}
