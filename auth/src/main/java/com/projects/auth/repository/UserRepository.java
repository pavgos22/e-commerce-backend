package com.projects.auth.repository;

import com.projects.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    @Query(nativeQuery = true, value = "SELECT * FROM users where login=?1 and islock=false and isenable=true")
    Optional<User> findUserByLoginAndLockAndEnabled(String login);
    Optional<User> findUserByLogin(String login);
    Optional<User> findUserByEmail(String email);
    Optional<User> findUserByUuid(String uuid);
}
