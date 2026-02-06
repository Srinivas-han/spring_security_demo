package com.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import com.security.entity.AppUser;
import com.security.repository.UserRepository;
import com.security.security.JwtUtil;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public String register(@RequestBody AppUser user) {
        user.setPassword(encoder.encode(user.getPassword()));
        repo.save(user);
        return "User Registered";
    }

    @PostMapping("/login")
    public String login(@RequestBody AppUser user) {
        var dbUser = repo.findByUsername(user.getUsername()).orElseThrow();

        if (encoder.matches(user.getPassword(), dbUser.getPassword())) {
            return jwtUtil.generateToken(user.getUsername());
        }
        throw new RuntimeException("Invalid credentials");
    }
}
