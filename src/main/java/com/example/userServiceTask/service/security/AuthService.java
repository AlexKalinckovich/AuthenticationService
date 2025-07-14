package com.example.userServiceTask.service.security;

import com.example.userServiceTask.dto.security.AuthResponse;
import com.example.userServiceTask.dto.security.LoginRequest;
import com.example.userServiceTask.dto.security.RefreshTokenRequest;
import com.example.userServiceTask.dto.security.RegisterRequest;
import com.example.userServiceTask.model.auth.UserCredentials;
import com.example.userServiceTask.model.auth.UserRole;
import com.example.userServiceTask.repositories.auth.UserCredentialsRepository;
import com.example.userServiceTask.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authManager;
    private final UserCredentialsRepository credentialsRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public AuthResponse register(final RegisterRequest req) {

        final UserCredentials credentials =
                UserCredentials.builder()
                .passwordHash(passwordEncoder.encode(req.getPasswordHash()))
                .role(UserRole.USER)
                .userId(req.getUserId())
                .build();

        credentialsRepository.save(credentials);

        final LoginRequest loginToRegisteredUser = new LoginRequest(req.getEmail(), req.getPasswordHash());
        return login(loginToRegisteredUser);
    }

    @Transactional(readOnly = true)
    public AuthResponse login(final LoginRequest req) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPasswordHash())
        );
        final String userEmail = req.getEmail();
        final UserCredentials creeds = credentialsRepository
                .findByUserEmail(userEmail)
                .orElseThrow();
        return jwtUtil.generateTokens(creeds, userEmail);
    }

    public AuthResponse refreshToken(final RefreshTokenRequest req) {
        return jwtUtil.refreshAccessToken(req.getRefreshToken());
    }
}
