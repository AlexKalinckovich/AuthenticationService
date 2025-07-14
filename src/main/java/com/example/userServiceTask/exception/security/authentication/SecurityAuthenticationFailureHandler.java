package com.example.userServiceTask.exception.security.authentication;

import com.example.userServiceTask.exception.security.response.ExceptionResponseService;
import com.example.userServiceTask.messageConstants.ErrorMessage;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class SecurityAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ExceptionResponseService exceptionResponseService;

    @Override
    public void onAuthenticationFailure(final HttpServletRequest request,
                                        final HttpServletResponse response,
                                        final AuthenticationException exception) throws IOException {
        exceptionResponseService.handleException(
                response,
                exception,
                HttpStatus.UNAUTHORIZED,
                ErrorMessage.AUTHENTICATION_ERROR,
                request.getRequestURI()
        );
    }
}