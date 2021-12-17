package org.hankyu.jwt.controller;

import lombok.RequiredArgsConstructor;
import org.hankyu.jwt.model.User;
import org.hankyu.jwt.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder encoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home<h1/>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token<h1/>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "Success";
    }

    @GetMapping("/api/v1/user")
    public String user() {
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
