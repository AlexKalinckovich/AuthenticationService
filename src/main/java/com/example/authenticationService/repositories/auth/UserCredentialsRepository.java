package com.example.authenticationService.repositories.auth;

import com.example.authenticationService.model.auth.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long> {

    @Query("SELECT uc FROM UserCredentials uc WHERE uc.email = :email")
    Optional<UserCredentials> findByUserEmail(@Param("email") String email);
}

