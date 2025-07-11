package com.example.userServiceTask.dto.security;

import com.example.dto.user.CreateUserDto;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private CreateUserDto user;
    private String passwordHash;
}
