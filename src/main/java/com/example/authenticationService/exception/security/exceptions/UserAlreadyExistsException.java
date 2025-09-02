package com.example.authenticationService.exception.security.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(final String email) {
        super("User already registered with email: " + email);
    }

    public UserAlreadyExistsException(final String email, final Throwable cause) {
        super("User already registered with email: " + email, cause);
    }
}

