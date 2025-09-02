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
    ERROR_KEY("error_key"),
    AUTH_INVALID_CREDENTIALS("auth_invalid_credentials"),
    USER_NOT_FOUND("user_not_found"),
    USER_ALREADY_EXISTS("user_already_exists"),
    DATABASE_CONSTRAINT("database_constraint"),
    AUTH_ERROR("auth_error"),
    GENERIC_ERROR("generic_error"),
    ACCOUNT_DISABLED("account_disabled"),
    ACCOUNT_LOCKED("account_locked"),
    TOKEN_EXPIRED("token_expired"),
    TOKEN_INVALID("token_invalid"),
    PASSWORD_POLICY_VIOLATION("password_policy_violation"),
    RATE_LIMIT_EXCEEDED("rate_limit_exceeded"),
    MFA_REQUIRED("mfa_required"),
    MFA_INVALID("mfa_invalid"),
    SESSION_EXPIRED("session_expired"),
    CORS_ERROR("cors_error"),;

    private final String key;

    ErrorMessage(String key) {
        this.key = key;
    }
}