package com.example.authenticationService.config;

import com.example.authenticationService.exception.security.exceptions.CorsException;
import com.example.authenticationService.security.JwtAuthFilter;
import com.example.authenticationService.service.security.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String ALL_ENDPOINTS = "/**";
    private static final String ORIGIN_HEADER = "Origin";

    @Value("${controllers.auth.baseEndpoint}")
    private String authBaseEndpoint;

    @Value("${controllers.auth.endpoints.login}")
    private String loginRoute;

    @Value("${cors.pattern}")
    private String corsAllowedOriginPattern;

    @Value("${cors.pattern-splitter}")
    private String corsAllowedPatternSplitter;

    private final CustomUserDetailsService userDetailsService;

    private final JwtAuthFilter jwtAuthFilter;


    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(corsAllowedOriginPattern.split(corsAllowedPatternSplitter)));
        configuration.setAllowedMethods(List.of("GET", "POST", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        return (final HttpServletRequest request) -> {
            final String origin = request.getHeader(ORIGIN_HEADER);
            if (origin != null && !isOriginAllowed(origin)) {
                throw new CorsException("CORS request rejected: Origin " + origin + " not allowed");
            }
            return configuration;
        };
    }

    private boolean isOriginAllowed(final String origin) {
        final List<String> allowedOrigins = List.of(corsAllowedOriginPattern.split(corsAllowedPatternSplitter));
        return allowedOrigins.contains(origin) || allowedOrigins.contains("*");
    }



    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors ->
                        cors.configurationSource(corsConfigurationSource())
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(authBaseEndpoint + ALL_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(
                        session ->
                                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(final HttpSecurity http) throws Exception {
        final AuthenticationManagerBuilder builder = http
                .getSharedObject(AuthenticationManagerBuilder.class);

        builder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        return builder.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}