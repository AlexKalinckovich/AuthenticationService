package com.example.authenticationService.exception.security;

import com.example.authenticationService.exception.security.response.ExceptionResponseService;
import com.example.authenticationService.messageConstants.ErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class SecurityAccessDeniedHandler implements AccessDeniedHandler {

    private final ExceptionResponseService exceptionResponseService;

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException ex) throws IOException {

        exceptionResponseService.handleException(
                response,
                ex,
                HttpStatus.FORBIDDEN,
                ErrorMessage.ACCESS_DENIED,
                request.getRequestURI()
        );
    }
}