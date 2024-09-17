package com.projects.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Setter
@Table(name="users")
@Entity
public class User implements UserDetails {

    @Id
    @GeneratedValue(generator = "users_id_seq", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "users_id_seq", sequenceName = "users_id_seq", allocationSize = 1)
    private long id;

    @Getter
    private String uuid;
    private String login;
    private String password;
    @Getter
    private String email;
    @Getter
    @Enumerated(EnumType.STRING)
    private Role role;
    @Column(name = "islock")
    private boolean isLock;
    @Column(name = "isenabled")
    private boolean isEnabled;

    public User(long id, String uuid, String login, String password, String email, Role role, boolean isLock, boolean isEnabled) {
        this.id = id;
        this.uuid = uuid;
        this.login = login;
        this.password = password;
        this.email = email;
        this.role = role;
        this.isLock = isLock;
        this.isEnabled = isEnabled;
        generateUuid();
    }

    public User() {
        generateUuid();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isLock;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return isEnabled;
    }


    private void generateUuid() {
        if(uuid == null || uuid.isEmpty()) {
            setUuid(UUID.randomUUID().toString());
        }
    }
}
