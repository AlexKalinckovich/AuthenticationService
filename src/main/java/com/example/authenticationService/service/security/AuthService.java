package com.example.authenticationService.service.security;

import com.example.authenticationService.dto.security.AuthResponse;
import com.example.authenticationService.dto.security.AuthRequest;
import com.example.authenticationService.dto.security.RefreshTokenRequest;
import com.example.authenticationService.exception.security.exceptions.UserAlreadyExistsException;
import com.example.authenticationService.model.auth.UserCredentials;
import com.example.authenticationService.model.auth.UserRole;
import com.example.authenticationService.repositories.auth.UserCredentialsRepository;
import com.example.authenticationService.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String BEARER = "Bearer ";
    private static final int BEARER_LENGTH = BEARER.length();

    private final UserCredentialsRepository credentialsRepository;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public void register(final AuthRequest req) {

        final String email = req.getEmail();
        if(credentialsRepository.findByUserEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        final UserCredentials credentials =
                UserCredentials.builder()
                        .email(req.getEmail())
                        .passwordHash(passwordEncoder.encode(req.getPasswordHash()))
                        .role(UserRole.USER)
                        .build();

        credentialsRepository.save(credentials);
    }

    @Transactional(readOnly = true)
    public AuthResponse login(final AuthRequest req) {
        final String userEmail = req.getEmail();
        final UserCredentials creeds = credentialsRepository
                .findByUserEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return jwtUtil.generateTokens(creeds, userEmail, creeds.getId());
    }

    public AuthResponse refreshToken(final RefreshTokenRequest req) {
        return jwtUtil.refreshAccessToken(req.getRefreshToken());
    }

    public boolean validateToken(final String authHeader) {
        if (authHeader == null || !authHeader.startsWith(BEARER)) {
            return false;
        }
        final String token = authHeader.substring(BEARER_LENGTH);
        final String username = jwtUtil.extractUsername(token);
        final UserDetails loadedDetails =  userDetailsService.loadUserByUsername(username);
        return jwtUtil.isTokenValid(token, loadedDetails);
    }

    public void deleteCreds(final Long id) {
        if(credentialsRepository.existsById(id)) {
            credentialsRepository.deleteById(id);
        }else{
            throw new UsernameNotFoundException("Creds not found");
        }
    }
}
