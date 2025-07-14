package com.example.authenticationService.config;

import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationFailureHandler;
import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationSuccessHandler;
import com.example.authenticationService.exception.security.login.LoginAuthenticationFilter;
import com.example.authenticationService.exception.security.SecurityAccessDeniedHandler;
import com.example.authenticationService.exception.security.authentication.SecurityAuthenticationEntryPoint;
import com.example.authenticationService.security.JwtAuthFilter;
import com.example.authenticationService.service.security.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
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

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String FILTER_LOGIN_URL = "/auth/login";

    private final SecurityAuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityAuthenticationFailureHandler authenticationFailureHandler;
    private final SecurityAuthenticationSuccessHandler authenticationSuccessHandler;

    private final SecurityAccessDeniedHandler accessDeniedHandler;

    private final CustomUserDetailsService userDetailsService;


    private final JwtAuthFilter jwtAuthFilter;

    private LoginAuthenticationFilter loginFilter;

    public void customFiltersInit(final HttpSecurity http) throws Exception {
        loginFilter = new LoginAuthenticationFilter(FILTER_LOGIN_URL);
        loginFilter.setAuthenticationManager(authenticationManager(http));
        loginFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
        loginFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        customFiltersInit(http);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
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