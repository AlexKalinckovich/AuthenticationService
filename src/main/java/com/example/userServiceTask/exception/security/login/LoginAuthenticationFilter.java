package com.example.userServiceTask.exception.security.login;

import com.example.userServiceTask.dto.security.LoginRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.InputStream;

public class LoginAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public LoginAuthenticationFilter(final String filterProcessesUrl) {
        setFilterProcessesUrl(filterProcessesUrl);
    }


    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request,
                                                final HttpServletResponse response) throws AuthenticationException {
        if (!request.getContentType().equalsIgnoreCase(MediaType.APPLICATION_JSON_VALUE)) {
            return super.attemptAuthentication(request, response);
        }

        try (final InputStream is = request.getInputStream()) {
            final LoginRequest login = objectMapper.readValue(is, LoginRequest.class);

            final UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                    login.getEmail(), login.getPasswordHash());

            setDetails(request, authRequest);
            return this.getAuthenticationManager().authenticate(authRequest);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Invalid login request format");
        }
    }
}

