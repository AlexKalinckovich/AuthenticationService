package com.example.authenticationService.exception;

import com.example.authenticationService.exception.security.exceptions.CorsException;
import com.example.authenticationService.exception.security.exceptions.JwtAuthenticationException;
import com.example.authenticationService.exception.security.exceptions.UserAlreadyExistsException;
import com.example.authenticationService.exception.security.exceptions.UserNotFoundException;
import com.example.authenticationService.exception.security.response.ErrorResponse;
import com.example.authenticationService.exception.security.response.ValidationErrorDetails;
import com.example.authenticationService.exception.security.response.ExceptionResponseService;
import com.example.authenticationService.messageConstants.ErrorMessage;
import com.github.dockerjava.zerodep.shaded.org.apache.hc.client5.http.auth.InvalidCredentialsException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.ServletException;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.csrf.CsrfException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.nio.file.AccessDeniedException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ExceptionResponseService exceptionResponseService;
    /* =========================
       DOMAIN EXCEPTIONS
       ========================= */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExists(
            UserAlreadyExistsException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.CONFLICT, ErrorMessage.USER_ALREADY_EXISTS
        );
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(
            UserNotFoundException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.NOT_FOUND, ErrorMessage.USER_NOT_FOUND
        );
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(
            InvalidCredentialsException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, ErrorMessage.AUTH_INVALID_CREDENTIALS
        );
    }

    @ExceptionHandler(JwtAuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleJwtAuthentication(
            JwtAuthenticationException ex, WebRequest request) {
        final ErrorMessage errorMessage = determineJwtErrorType(ex);
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, errorMessage
        );
    }

    /* =========================
       SPRING SECURITY EXCEPTIONS
       ========================= */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.NOT_FOUND, ErrorMessage.USER_NOT_FOUND
        );
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, ErrorMessage.AUTH_INVALID_CREDENTIALS
        );
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponse> handleDisabledUser(
            DisabledException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, ErrorMessage.ACCOUNT_DISABLED
        );
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponse> handleLockedUser(
            LockedException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.FORBIDDEN, ErrorMessage.ACCOUNT_LOCKED
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.FORBIDDEN, ErrorMessage.ACCESS_DENIED
        );
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthentication(
            AuthenticationException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, ErrorMessage.AUTHENTICATION_ERROR
        );
    }

    private ErrorMessage determineJwtErrorType(final JwtAuthenticationException ex) {
        final String message = ex.getMessage().toLowerCase();
        ErrorMessage result = ErrorMessage.JWT_ERROR;
        if (message.contains("expired")) {
            result = ErrorMessage.TOKEN_EXPIRED;
        } else if (message.contains("invalid") || message.contains("malformed")) {
            result = ErrorMessage.TOKEN_INVALID;
        }
        return result;
    }

    /* =========================
       JWT EXCEPTIONS
       ========================= */
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwtException(
            JwtException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNAUTHORIZED, ErrorMessage.JWT_ERROR
        );
    }

    /* =========================
       VALIDATION EXCEPTIONS
       ========================= */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
            final MethodArgumentNotValidException ex, final WebRequest request) {

        final Map<String, String> fieldErrorsMap = new LinkedHashMap<>();
        for (final FieldError fe : ex.getBindingResult().getFieldErrors()) {
            final String defaultMessage = fe.getDefaultMessage();
            fieldErrorsMap.putIfAbsent(fe.getField(), defaultMessage == null ? "" : defaultMessage);
        }

        final ValidationErrorDetails details = new ValidationErrorDetails(fieldErrorsMap);

        final ErrorResponse response = new ErrorResponse(
                Instant.now(),
                HttpStatus.BAD_REQUEST.value(),
                ErrorMessage.VALIDATION_ERROR.name(),
                ex.getMessage(),
                request.getDescription(false),
                details
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolation(
            ConstraintViolationException ex, WebRequest request) {

        final Map<String, String> fieldErrorsMap = ex.getConstraintViolations()
                .stream()
                .collect(Collectors.toMap(
                        cv -> cv.getPropertyPath().toString(),
                        cv -> cv.getMessage() == null ? "" : cv.getMessage(),
                        (existing, replacement) -> existing,
                        LinkedHashMap::new
                ));

        final ValidationErrorDetails details = new ValidationErrorDetails(fieldErrorsMap);

        final ErrorResponse response = new ErrorResponse(
                Instant.now(),
                HttpStatus.BAD_REQUEST.value(),
                ErrorMessage.VALIDATION_ERROR.name(),
                ex.getMessage(),
                request.getDescription(false),
                details
        );

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    /* =========================
       WEB / INFRA EXCEPTIONS
       ========================= */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.METHOD_NOT_ALLOWED, ErrorMessage.GENERIC_ERROR
        );
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMediaTypeNotSupported(
            HttpMediaTypeNotSupportedException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.UNSUPPORTED_MEDIA_TYPE, ErrorMessage.GENERIC_ERROR
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadableMessage(
            HttpMessageNotReadableException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.BAD_REQUEST, ErrorMessage.GENERIC_ERROR
        );
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingParam(
            MissingServletRequestParameterException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.BAD_REQUEST, ErrorMessage.GENERIC_ERROR
        );
    }

    @ExceptionHandler(ServletException.class)
    public ResponseEntity<ErrorResponse> handleServlet(
            ServletException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex, request, HttpStatus.BAD_REQUEST, ErrorMessage.GENERIC_ERROR
        );
    }

    /* =========================
       CORS / CSRF EXCEPTIONS
       ========================= */
    @ExceptionHandler(CorsException.class)
    public ResponseEntity<ErrorResponse> handleCors(
            final CorsException ex, final WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex,
                request,
                HttpStatus.FORBIDDEN,
                ErrorMessage.ACCESS_DENIED
        );
    }

    @ExceptionHandler(CsrfException.class)
    public ResponseEntity<ErrorResponse> handleCsrf(
            CsrfException ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex,
                request,
                HttpStatus.FORBIDDEN,
                ErrorMessage.ACCESS_DENIED
        );
    }

    /* =========================
       FALLBACK
       ========================= */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneric(
            Exception ex, WebRequest request) {
        return exceptionResponseService.buildErrorResponse(
                ex,
                request,
                HttpStatus.INTERNAL_SERVER_ERROR,
                ErrorMessage.GENERIC_ERROR
        );
    }
}
