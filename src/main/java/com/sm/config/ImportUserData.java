package com.sm.config;

import com.sm.entity.Role;
import com.sm.entity.User;
import com.sm.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ImportUserData implements CommandLineRunner {

    private final UserService userService;

    @Override
    public void run(String... args) throws Exception {
        String plainPassword = "password";
        String hashedPassword = BCrypt.hashpw(plainPassword, BCrypt.gensalt());
        userService.create(new User(null, "Ali".toLowerCase(), hashedPassword, Role.ADMIN));
        userService.create(new User(null, "Hunain".toLowerCase(), hashedPassword, Role.USER));
        userService.create(new User(null, "Awais".toLowerCase(), hashedPassword, Role.USER));

    }
}
