package com.example.authenticationService.security;

import com.example.authenticationService.exception.security.exceptions.JwtAuthenticationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String JWT_TOKEN_PARTS_SPLITTER = "\\.";

    private static final int JWT_TOKEN_PARTS_COUNT = 3;


    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Value("${controllers.auth.baseEndpoint}")
    private String authBaseEndpoint;

    @Autowired
    public JwtAuthFilter(final JwtUtil jwtUtil,
                         final UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final @NotNull HttpServletResponse response,
                                    final @NotNull FilterChain filterChain) throws ServletException, IOException {
        final String requestURI = request.getRequestURI();
        if (!requestURI.startsWith(authBaseEndpoint)) {

            final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
            if (authHeader != null && authHeader.startsWith(BEARER_PREFIX)) {
                final int bearerPrefixSize = BEARER_PREFIX.length();

                final String token = authHeader.substring(bearerPrefixSize);

                if (token.isBlank() || token.split(JWT_TOKEN_PARTS_SPLITTER).length != JWT_TOKEN_PARTS_COUNT) {
                    throw new JwtAuthenticationException("Invalid token format");
                }


                final String username = jwtUtil.extractUsername(token);

                final SecurityContext securityContext = SecurityContextHolder.getContext();
                if (username != null && securityContext.getAuthentication() == null) {
                    final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    if (jwtUtil.isTokenValid(token, userDetails)) {
                        final UsernamePasswordAuthenticationToken authToken =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        securityContext.setAuthentication(authToken);
                    }else{
                        throw new JwtAuthenticationException("Invalid or expired token");
                    }
                }
            }

        }

        filterChain.doFilter(request, response);
    }

}
