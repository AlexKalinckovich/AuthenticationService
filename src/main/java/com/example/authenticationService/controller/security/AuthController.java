package com.example.authenticationService.controller.security;


import com.example.authenticationService.dto.security.AuthResponse;
import com.example.authenticationService.dto.security.AuthRequest;
import com.example.authenticationService.dto.security.RefreshTokenRequest;
import com.example.authenticationService.service.security.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${controllers.auth.baseEndpoint}")
@Validated
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(final AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("${controllers.auth.endpoints.register}")
    public ResponseEntity<AuthResponse> register(final @RequestBody AuthRequest request) {
        authService.register(request);
        final AuthRequest loginToRegisteredUser = new AuthRequest(request.getEmail(),
                request.getPasswordHash());
        return ResponseEntity.ok(authService.login(loginToRegisteredUser));

    }

    @PostMapping("${controllers.auth.endpoints.login}")
    public ResponseEntity<AuthResponse> login(final @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("${controllers.auth.endpoints.refresh}")
    public ResponseEntity<AuthResponse> refresh(final @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @GetMapping("${controllers.auth.endpoints.validate}")
    public ResponseEntity<Boolean> validate(final @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader){
        boolean isTokenValid = authService.validateToken(authHeader);
        return ResponseEntity.ok(isTokenValid);
    }
}
