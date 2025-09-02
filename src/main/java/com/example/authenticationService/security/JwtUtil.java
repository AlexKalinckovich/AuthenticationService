package com.example.authenticationService.security;

import com.example.authenticationService.dto.security.AuthResponse;
import com.example.authenticationService.model.auth.UserCredentials;
import com.example.authenticationService.repositories.auth.UserCredentialsRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtProperties jwtProperties;
    private final UserCredentialsRepository userCredentialsRepository;

    private Key key;

    @PostConstruct
    public void initKey() {
        final String base64Secret = Encoders.BASE64.encode(jwtProperties.getSecret().getBytes());
        this.key = Keys.hmacShaKeyFor(base64Secret.getBytes());
    }

    public AuthResponse generateTokens(final UserCredentials user,
                                       final String userEmail, Long id) {
        final String userRole = user.getRole().name();

        final String access = Jwts.builder()
                .setSubject(userEmail)
                .claim("role", userRole)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpirationMs()))
                .signWith(key)
                .compact();

        final String refresh = Jwts.builder()
                .setSubject(userEmail)
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getRefreshTokenExpirationMs()))
                .signWith(key)
                .compact();

        return new AuthResponse(id, access, refresh);
    }

    public AuthResponse refreshAccessToken(final String refreshToken) {
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(refreshToken)
                .getBody();
        final String email = claims.getSubject();
        final Optional<UserCredentials> credentials = userCredentialsRepository.findByUserEmail(email);
        if (credentials.isEmpty()) {
            throw new JwtException("User not found");
        }
        final long id = credentials.get().getId();
        return new AuthResponse(id, generateAccess(email), refreshToken);
    }

    private String generateAccess(final String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtProperties.getAccessTokenExpirationMs()))
                .signWith(key)
                .compact();
    }

    public String extractUsername(final String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean isTokenValid(final String token,
                                final UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(final String token) {
        final Date expiration = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }
}