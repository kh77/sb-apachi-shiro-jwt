package com.sm.controller;

import com.sm.config.security.jwt.JwtUtils;
import com.sm.controller.request.LoginDto;
import com.sm.controller.response.JwtResponse;
import lombok.RequiredArgsConstructor;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final JwtUtils jwtUtils;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDto loginDto) {
        try {
            // create a UsernamePasswordToken with the user's credentials
            UsernamePasswordToken token = new UsernamePasswordToken(loginDto.getUsername(), loginDto.getPassword());

            // get the Subject instance for the current thread
            Subject currentUser = SecurityUtils.getSubject();

            // attempt to authenticate the user
            currentUser.login(token);

            // authentication succeeded, generate a JWT token
            String jwt = jwtUtils.generateJwtToken(loginDto.getUsername());

            // return the JWT token in the response
            return ResponseEntity.ok(new JwtResponse(jwt));

        } catch (AuthenticationException e) {
            // authentication failed
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }

    @GetMapping("/logout")
    public void logout() {
        Subject currentUser = SecurityUtils.getSubject();
        if (currentUser != null) currentUser.logout();
    }

    @GetMapping("/api/index")
    public Object getPrinciple() {
        Subject currentUser = SecurityUtils.getSubject();
        return currentUser.getPrincipal();
    }

    @GetMapping("/api/admin")
    @RequiresRoles("ADMIN")
    public String adminPage() {
        return "ADMIN";
    }

    @GetMapping("/api/user")
    @RequiresRoles("USER")
    public String userPage() {
        return "USER";
    }

    @GetMapping("/public")
    public String publicPage() {
        return "Public endpoint";
    }
}

