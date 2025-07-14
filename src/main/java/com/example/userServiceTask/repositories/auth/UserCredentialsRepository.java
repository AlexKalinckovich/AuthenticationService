package com.example.userServiceTask.repositories.auth;

import com.example.userServiceTask.model.auth.UserCredentials;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentials, Long> {
    @Query(
            "Select uc from UserCredentials uc inner join User u on uc.userId = u.id where u.email = :email"
    )
    Optional<UserCredentials> findByUserEmail(@Param(value = "email") String email);
}
