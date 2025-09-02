package com.example.authenticationService.security;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtProperties {
    private String secret = String.valueOf(Keys.secretKeyFor(SignatureAlgorithm.HS512));

    private long accessTokenExpirationMs;

    private long refreshTokenExpirationMs;
}
