package com.example.authenticationService.exception.security.response;

sealed interface ErrorDetails permits ValidationErrorDetails, SimpleErrorDetails {
}
