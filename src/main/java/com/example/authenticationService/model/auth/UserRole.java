package com.example.authenticationService.model.auth;

import lombok.Getter;

@Getter
public enum UserRole {
    USER("ROLE_USER"),
    ADMIN("ROLE_ADMIN");

    private final String authority;

    UserRole(final String authority) {
        this.authority = authority;
    }

}
