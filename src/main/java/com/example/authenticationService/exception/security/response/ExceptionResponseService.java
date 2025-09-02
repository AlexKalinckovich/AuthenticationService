package com.example.authenticationService.exception.security.response;

import com.example.authenticationService.messageConstants.ErrorMessage;
import com.example.authenticationService.service.messages.MessageService;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class ExceptionResponseService {

    private final MessageService messageService;


    @NotNull
    public ResponseEntity<ErrorResponse> buildErrorResponse(
            final @NotNull Exception ex,
            final @NotNull WebRequest request,
            final @NotNull HttpStatus status,
            final @NotNull ErrorMessage errorCode
    ) {
        final ErrorDetails details = new SimpleErrorDetails(ex.getMessage());

        final ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                status.value(),
                errorCode.name(),
                messageService.getMessage(errorCode),
                request.getDescription(false),
                details
        );

        return new ResponseEntity<>(errorResponse, status);
    }
}
