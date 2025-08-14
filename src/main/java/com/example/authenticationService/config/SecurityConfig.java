package com.example.authenticationService.config;

import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationFailureHandler;
import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationSuccessHandler;
import com.example.authenticationService.exception.security.login.LoginAuthenticationFilter;
import com.example.authenticationService.exception.security.SecurityAccessDeniedHandler;
import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationEntryPoint;
import com.example.authenticationService.security.JwtAuthFilter;
import com.example.authenticationService.service.security.CustomUserDetailsService;
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

    @Value("${controllers.auth.baseEndpoint}")
    private String authBaseEndpoint;

    @Value("${controllers.auth.endpoints.login}")
    private String loginRoute;

    @Value("${cors.pattern}")
    private String corsAllowedOriginPattern;

    @Value("${cors.pattern-splitter}")
    private String corsAllowedPatternSplitter;

    private final SecurityAuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityAuthenticationFailureHandler authenticationFailureHandler;
    private final SecurityAuthenticationSuccessHandler authenticationSuccessHandler;

    private final SecurityAccessDeniedHandler accessDeniedHandler;

    private final CustomUserDetailsService userDetailsService;

    private final JwtAuthFilter jwtAuthFilter;

    private LoginAuthenticationFilter loginFilter;

    private void customFiltersInit(final HttpSecurity http) throws Exception {
        loginFilter = new LoginAuthenticationFilter(authBaseEndpoint + loginRoute);
        loginFilter.setAuthenticationManager(authenticationManager(http));
        loginFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        loginFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of(corsAllowedOriginPattern.split(corsAllowedPatternSplitter)));
        configuration.setAllowedMethods(List.of("GET", "POST", "PATCH"));
        return request -> configuration;
    }



    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        customFiltersInit(http);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors ->
                        cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(authBaseEndpoint + ALL_ENDPOINTS).permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(
                        session ->
                                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);

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