package com.example.authenticationService.exception.security.response;

import java.util.Map;

public record ValidationErrorDetails(Map<String, String> fieldErrors) implements ErrorDetails {
}
