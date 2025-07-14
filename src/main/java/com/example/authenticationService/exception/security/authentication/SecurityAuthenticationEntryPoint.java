package com.example.authenticationService.exception.security.authentication;

import com.example.authenticationService.exception.security.response.ExceptionResponseService;
import com.example.authenticationService.messageConstants.ErrorMessage;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ExceptionResponseService exceptionResponseService;

    @Override
    public void commence(
            final HttpServletRequest request,
            final HttpServletResponse response,
            final AuthenticationException exception) throws IOException {

        final ErrorMessage errorType = determineErrorType(exception);

        exceptionResponseService.handleException(
                response,
                exception,
                HttpStatus.UNAUTHORIZED,
                errorType,
                request.getRequestURI()
        );
    }

    private ErrorMessage determineErrorType(AuthenticationException ex) {
        if (ex.getCause() instanceof JwtException) {
            return ErrorMessage.JWT_ERROR;
        }
        return ErrorMessage.AUTHENTICATION_ERROR;
    }
}