package com.example.authenticationService.exception.security.exceptions;

public class CorsException extends RuntimeException {
    public CorsException(String message) {
        super(message);
    }

    public CorsException(String message, Throwable cause) {
        super(message, cause);
    }
}
