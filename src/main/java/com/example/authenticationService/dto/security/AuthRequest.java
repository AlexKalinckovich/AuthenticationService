package com.example.authenticationService.dto.security;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {
    @Email(message = "Email must be in valid format")
    @NotBlank(message = "Email must be not null or blank")
    private String email;

    @NotBlank(message = "Password cannot be blank")
    @Length(min = 6, message = "Password is too short, at least {min} symbols")
    private String passwordHash;
}