package com.example.authenticationService.exception.security.response;

import com.example.authenticationService.exception.ErrorResponse;
import com.example.authenticationService.messageConstants.ErrorMessage;
import com.example.authenticationService.service.messages.MessageService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.WebRequest;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ExceptionResponseService {

    private final MessageService messageService;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule());

    public void handleException(
            final HttpServletResponse response,
            final Exception ex,
            final HttpStatus status,
            final ErrorMessage errorMessage,
            final String requestPath
    ) throws IOException {
        final String detailsKey = resolveDetailsKey(ex);
        final String detailsMessage = ex.getMessage() != null ?
                ex.getMessage() : "No additional information";

        final ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                status.value(),
                messageService.getMessage(errorMessage),
                requestPath,
                Map.of(detailsKey, detailsMessage)
        );

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }

    public ResponseEntity<ErrorResponse> buildWebRequestErrorResponse(final Exception ex,
                                                                      final WebRequest request,
                                                                      final HttpStatus status,
                                                                      final String message){
        final ErrorResponse errorResponse = new ErrorResponse(
                Instant.now(),
                status.value(),
                message,
                request.getDescription(false),
                Map.of(messageService.getMessage(ErrorMessage.ERROR_KEY), ex.getMessage())
        );

        return new ResponseEntity<>(errorResponse, status);
    }

    private String resolveDetailsKey(Exception ex) {
        if (ex instanceof JwtException) {
            return messageService.getMessage(ErrorMessage.JWT_ERROR);
        }
        return messageService.getMessage(ErrorMessage.ERROR_KEY);
    }
}