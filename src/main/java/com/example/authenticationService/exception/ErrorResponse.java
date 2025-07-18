package com.example.authenticationService.exception;

import java.time.Instant;

public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String path,
        Object details
) {}
