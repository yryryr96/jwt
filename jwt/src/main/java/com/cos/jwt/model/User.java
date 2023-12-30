package com.cos.jwt.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Data
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String roles; // USER, ADMIN

    public List<String> getRoleList() {

        if (roles.length() > 0) {
            return Arrays.asList(roles.split(","));
        }

        return new ArrayList<>();
    }
}
