package com.cos.jwt.controller;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
//@RequestMapping("api/v1/")
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/")
    public String home() {
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {

        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입 완료";
    }

    @GetMapping("/api/v1/user")
    public String user(Authentication authentication) {

        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        String username = principal.getUsername();
        System.out.println(username);

        return "user";
    }

    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
