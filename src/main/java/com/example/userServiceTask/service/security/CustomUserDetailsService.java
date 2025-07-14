package com.example.userServiceTask.service.security;

import com.example.userServiceTask.model.auth.UserCredentials;
import com.example.userServiceTask.repositories.auth.UserCredentialsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserCredentialsRepository credentialsRepository;

    @Autowired
    public CustomUserDetailsService(final UserCredentialsRepository credentialsRepository) {
        this.credentialsRepository = credentialsRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        final UserCredentials creds = credentialsRepository.findByUserEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return User.withUsername(email)
                .password(creds.getPasswordHash())
                .roles(creds.getRole().name())
                .build();
    }
}