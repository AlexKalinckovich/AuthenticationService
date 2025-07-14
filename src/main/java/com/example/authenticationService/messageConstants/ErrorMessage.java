package com.example.authenticationService.messageConstants;

import lombok.Getter;

@Getter
public enum ErrorMessage {
    RESOURCE_NOT_FOUND("resource_not_found"),
    EMAIL_ALREADY_EXISTS("email_already_exists"),
    AUTHENTICATION_ERROR("authentication_error"),
    ACCESS_DENIED("access_denied"),
    JWT_ERROR("jwt_error"),
    VALIDATION_ERROR("validation_error"),
    ERROR_KEY("error_key"),;

    private final String key;

    ErrorMessage(String key) {
        this.key = key;
    }

}