package br.edu.sentinela.exception;

import br.edu.sentinela.dto.response.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
            .map(FieldError::getDefaultMessage)
            .toList();
        return ResponseEntity.badRequest().body(ErrorResponse.builder()
            .status(400)
            .error("Validation Failed")
            .message("Request validation failed")
            .path(request.getRequestURI())
            .details(details)
            .build());
    }

    @ExceptionHandler(AlertValidationException.class)
    public ResponseEntity<ErrorResponse> handleAlertValidation(
            AlertValidationException ex, HttpServletRequest request) {
        return ResponseEntity.badRequest().body(error(400, "Bad Request", ex.getMessage(), request));
    }

    @ExceptionHandler(DuplicateAlertException.class)
    public ResponseEntity<ErrorResponse> handleDuplicate(
            DuplicateAlertException ex, HttpServletRequest request) {
        return ResponseEntity.ok(error(200, "Duplicate", ex.getMessage(), request));
    }

    @ExceptionHandler(HmacValidationException.class)
    public ResponseEntity<ErrorResponse> handleHmac(
            HmacValidationException ex, HttpServletRequest request) {
        log.warn("HMAC validation failed: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(error(401, "Unauthorized", "Invalid signature", request));
    }

    @ExceptionHandler(DecryptionException.class)
    public ResponseEntity<ErrorResponse> handleDecryption(
            DecryptionException ex, HttpServletRequest request) {
        log.warn("Decryption failed: {}", ex.getMessage());
        return ResponseEntity.badRequest().body(error(400, "Bad Request", "Payload decryption failed", request));
    }

    @ExceptionHandler(RateLimitException.class)
    public ResponseEntity<ErrorResponse> handleRateLimit(
            RateLimitException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body(error(429, "Too Many Requests", ex.getMessage(), request));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(error(401, "Unauthorized", "Invalid credentials", request));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(error(403, "Forbidden", "Access denied", request));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(error(500, "Internal Server Error", "An unexpected error occurred", request));
    }

    private ErrorResponse error(int status, String error, String message, HttpServletRequest request) {
        return ErrorResponse.builder()
            .status(status)
            .error(error)
            .message(message)
            .path(request.getRequestURI())
            .build();
    }
}
